/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Copyright (C) 2023 Thomas Weißschuh <thomas@t-8ch.de>
 */

#include <sys/prctl.h>
#include <sys/syscall.h>

#include "setpriv-landlock.h"

#include "strutils.h"
#include "xalloc.h"
#include "nls.h"
#include "c.h"

/*
 * <linux/landlock.h> is deliberately not included: its contents (which
 * macros, the rule-type enum members, and the ruleset/rule attr struct
 * fields exist) vary by kernel version, so patching around a possibly-old
 * copy with #ifndef would only cover whatever gaps the systems seen so far
 * happened to have. setpriv only ever reaches Landlock through the raw
 * syscalls below, so it vendors every definition it needs itself instead,
 * matching the stable kernel ABI.
 */

#define LANDLOCK_CREATE_RULESET_VERSION		(1U << 0)

enum landlock_rule_type {
	LANDLOCK_RULE_PATH_BENEATH = 1,
	LANDLOCK_RULE_NET_PORT = 2,
};

struct landlock_ruleset_attr {
	uint64_t handled_access_fs;
	uint64_t handled_access_net;
	uint64_t scoped;
	uint64_t quiet_access_fs;
	uint64_t quiet_access_net;
	uint64_t quiet_scoped;
};

struct landlock_path_beneath_attr {
	uint64_t allowed_access;
	int32_t parent_fd;
} __attribute__((packed));

struct landlock_net_port_attr {
	uint64_t allowed_access;
	uint64_t port;
};

#define LANDLOCK_ACCESS_FS_EXECUTE			(1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE			(1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE			(1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR			(1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR			(1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE			(1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR			(1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR			(1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG			(1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK			(1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO			(1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK			(1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM			(1ULL << 12)
#define LANDLOCK_ACCESS_FS_REFER			(1ULL << 13)
#define LANDLOCK_ACCESS_FS_TRUNCATE			(1ULL << 14)
#define LANDLOCK_ACCESS_FS_IOCTL_DEV			(1ULL << 15)
#define LANDLOCK_ACCESS_FS_RESOLVE_UNIX			(1ULL << 16)

#define LANDLOCK_ACCESS_NET_BIND_TCP			(1ULL << 0)
#define LANDLOCK_ACCESS_NET_CONNECT_TCP			(1ULL << 1)
#define LANDLOCK_ACCESS_NET_BIND_UDP			(1ULL << 2)
#define LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP		(1ULL << 3)

#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET		(1ULL << 0)
#define LANDLOCK_SCOPE_SIGNAL				(1ULL << 1)

#define LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF	(1U << 0)
#define LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON		(1U << 1)
#define LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF	(1U << 2)

#define LANDLOCK_ADD_RULE_QUIET			(1U << 0)

#ifndef HAVE_LANDLOCK_CREATE_RULESET
static inline int landlock_create_ruleset(
		const struct landlock_ruleset_attr *attr,
		size_t size, uint32_t flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef HAVE_LANDLOCK_ADD_RULE
static inline int landlock_add_rule(
		int ruleset_fd, enum landlock_rule_type rule_type,
		const void *rule_attr, uint32_t flags)
{
	return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type,
		       rule_attr, flags);
}
#endif

#ifndef HAVE_LANDLOCK_RESTRICT_SELF
static inline int landlock_restrict_self(int ruleset_fd, uint32_t flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

#define SETPRIV_EXIT_PRIVERR 127	/* how we exit when we fail to set privs */

struct landlock_rule_entry {
	struct list_head head;
	enum landlock_rule_type rule_type;
	union {
		struct landlock_path_beneath_attr path_beneath_attr;
		struct landlock_net_port_attr net_port_attr;
	};
};

struct landlock_access_entry {
	unsigned long long value;
	const char *type;
	const char *help;
};

static const struct landlock_access_entry landlock_access_fs[] = {
	{ LANDLOCK_ACCESS_FS_EXECUTE,     "execute",     N_("execute a file") },
	{ LANDLOCK_ACCESS_FS_WRITE_FILE,  "write-file",  N_("open a file with write access") },
	{ LANDLOCK_ACCESS_FS_READ_FILE,   "read-file",   N_("open a file with read access") },
	{ LANDLOCK_ACCESS_FS_READ_DIR,    "read-dir",    N_("open a directory or list its content") },
	{ LANDLOCK_ACCESS_FS_REMOVE_DIR,  "remove-dir",  N_("remove an empty directory or rename one")  },
	{ LANDLOCK_ACCESS_FS_REMOVE_FILE, "remove-file", N_("unlink (or rename) a file") },
	{ LANDLOCK_ACCESS_FS_MAKE_CHAR,   "make-char",   N_("create (or rename or link) a character device") },
	{ LANDLOCK_ACCESS_FS_MAKE_DIR,    "make-dir",    N_("create (or rename) a directory") },
	{ LANDLOCK_ACCESS_FS_MAKE_REG,    "make-reg",    N_("create (or rename or link) a regular file") },
	{ LANDLOCK_ACCESS_FS_MAKE_SOCK,   "make-sock",   N_("create (or rename or link) a UNIX domain socket") },
	{ LANDLOCK_ACCESS_FS_MAKE_FIFO,   "make-fifo",   N_("create (or rename or link) a named pipe") },
	{ LANDLOCK_ACCESS_FS_MAKE_BLOCK,  "make-block",  N_("create (or rename or link) a block device") },
	{ LANDLOCK_ACCESS_FS_MAKE_SYM,    "make-sym",    N_("create (or rename or link) a symbolic link") },
	{ LANDLOCK_ACCESS_FS_REFER,       "refer",       N_("link or rename a file from or to a different directory") },
	{ LANDLOCK_ACCESS_FS_TRUNCATE,    "truncate",    N_("truncate a file with truncate(2)") },
	{ LANDLOCK_ACCESS_FS_IOCTL_DEV,   "ioctl-dev",   N_("invoke ioctl(2) on an opened character or block device") },
	{ LANDLOCK_ACCESS_FS_RESOLVE_UNIX, "resolve-unix", N_("connect(2) or bind(2) a pathname UNIX domain socket") },
};

static const struct landlock_access_entry landlock_access_net[] = {
	{ LANDLOCK_ACCESS_NET_BIND_TCP,         "bind-tcp",         N_("bind a TCP socket to a local port") },
	{ LANDLOCK_ACCESS_NET_CONNECT_TCP,      "connect-tcp",      N_("connect a TCP socket to a remote port") },
	{ LANDLOCK_ACCESS_NET_BIND_UDP,         "bind-udp",         N_("bind a UDP socket to a local port") },
	{ LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP, "connect-send-udp", N_("set the remote port of a UDP socket, or send a datagram to an explicit remote port") },
};

static const struct landlock_access_entry landlock_scope[] = {
	{ LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET, "abstract-unix-socket", N_("restrict connections to abstract UNIX sockets outside the domain") },
	{ LANDLOCK_SCOPE_SIGNAL,               "signal",               N_("restrict sending signals to processes outside the domain") },
};

static const struct landlock_access_entry landlock_restrict_self_flags[] = {
	{ LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF,  "log-same-exec-off",  N_("do not log denied accesses until the next execve(2)") },
	{ LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON,    "log-new-exec-on",    N_("log denied accesses after the next execve(2)") },
	{ LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF, "log-subdomains-off", N_("do not log denied accesses from nested domains") },
};

static long landlock_access_entry_to_mask(const struct landlock_access_entry *table,
					   size_t n, const char *str, size_t len)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (strncmp(table[i].type, str, len) == 0)
			return table[i].value;
	return -1;
}

static long landlock_restrict_self_flag_to_mask(const char *str, size_t len)
{
	return landlock_access_entry_to_mask(landlock_restrict_self_flags, ARRAY_SIZE(landlock_restrict_self_flags), str, len);
}

/*
 * An empty list matches every entry in the table.
 *
 * The table is passed in explicitly rather than via a callback function
 * pointer because string_to_bitmask()'s callback signature has no room to
 * pass it through as context, which would otherwise force a throwaway
 * wrapper function per table just to close over it.
 */
static uint64_t parse_landlock_bits(const char *list,
				     const struct landlock_access_entry *table, size_t n)
{
	uint64_t r = 0;
	const char *begin = NULL, *p;
	size_t i;

	if (list[0] == '\0') {
		for (i = 0; i < n; i++)
			r |= table[i].value;
		return r;
	}

	for (p = list; *p; p++) {
		const char *end = NULL;
		long flag;

		if (!begin)
			begin = p;
		if (*p == ',')
			end = p;
		if (*(p + 1) == '\0')
			end = p + 1;
		if (!end)
			continue;
		if (end <= begin)
			errx(EXIT_FAILURE, _("could not parse landlock access: %s"), list);

		flag = landlock_access_entry_to_mask(table, n, begin, end - begin);
		if (flag < 0)
			errx(EXIT_FAILURE, _("could not parse landlock access: %s"), list);
		r |= (uint64_t) flag;
		begin = NULL;
		if (!*end)
			break;
	}

	return r;
}

static uint64_t parse_landlock_fs_access(const char *list)
{
	return parse_landlock_bits(list, landlock_access_fs, ARRAY_SIZE(landlock_access_fs));
}

static uint64_t parse_landlock_net_access(const char *list)
{
	return parse_landlock_bits(list, landlock_access_net, ARRAY_SIZE(landlock_access_net));
}

static uint64_t parse_landlock_scope(const char *list)
{
	return parse_landlock_bits(list, landlock_scope, ARRAY_SIZE(landlock_scope));
}

void parse_landlock_access(struct setpriv_landlock_opts *opts, const char *str)
{
	const char *type;

	if (strcmp(str, "fs") == 0) {
		opts->access_fs |= parse_landlock_fs_access("");
		return;
	}
	if ((type = ul_startswith(str, "fs:")) != NULL) {
		opts->access_fs |= parse_landlock_fs_access(type);
		return;
	}

	if (strcmp(str, "net") == 0) {
		opts->access_net |= parse_landlock_net_access("");
		return;
	}
	if ((type = ul_startswith(str, "net:")) != NULL) {
		opts->access_net |= parse_landlock_net_access(type);
		return;
	}

	if (strcmp(str, "scope") == 0) {
		opts->scoped |= parse_landlock_scope("");
		return;
	}
	if ((type = ul_startswith(str, "scope:")) != NULL) {
		opts->scoped |= parse_landlock_scope(type);
		return;
	}

	errx(EXIT_FAILURE, _("invalid landlock access: %s"), str);
}

void parse_landlock_rule(struct setpriv_landlock_opts *opts, const char *str)
{
	struct landlock_rule_entry *rule;
	enum landlock_rule_type rule_type;
	const char *accesses;
	const char *arg;
	char *accesses_part;

	if ((accesses = ul_startswith(str, "path-beneath:")) != NULL) {
		rule_type = LANDLOCK_RULE_PATH_BENEATH;
	} else if ((accesses = ul_startswith(str, "net-port:")) != NULL) {
		rule_type = LANDLOCK_RULE_NET_PORT;
	} else {
		errx(EXIT_FAILURE, _("invalid landlock rule: %s"), str);
	}

	arg = strchr(accesses, ':');
	if (!arg)
		errx(EXIT_FAILURE, _("invalid landlock rule: %s"), str);

	accesses_part = xstrndup(accesses, arg - accesses);
	arg++;

	rule = xmalloc(sizeof(*rule));
	rule->rule_type = rule_type;

	switch (rule_type) {
	case LANDLOCK_RULE_PATH_BENEATH:
	{
		int parent_fd;

		rule->path_beneath_attr.allowed_access = parse_landlock_fs_access(accesses_part);

		parent_fd = open(arg, O_RDONLY | O_PATH | O_CLOEXEC);
		if (parent_fd == -1) {
			free(accesses_part);
			free(rule);
			err(EXIT_FAILURE, _("could not open file for landlock: %s"), arg);
		}
		rule->path_beneath_attr.parent_fd = parent_fd;
		break;
	}
	case LANDLOCK_RULE_NET_PORT:
		rule->net_port_attr.allowed_access = parse_landlock_net_access(accesses_part);
		rule->net_port_attr.port = strtou16_or_err(arg, _("invalid landlock port argument"));
		break;
	default:
		abort();
	}

	free(accesses_part);
	list_add(&rule->head, &opts->rules);
}

void parse_landlock_restrict_self(struct setpriv_landlock_opts *opts, const char *str)
{
	unsigned long r = 0;

	if (string_to_bitmask(str, &r, landlock_restrict_self_flag_to_mask))
		errx(EXIT_FAILURE,
		     _("could not parse landlock restrict-self flags: %s"), str);

	opts->restrict_self_flags |= r;
}

void init_landlock_opts(struct setpriv_landlock_opts *opts)
{
	INIT_LIST_HEAD(&opts->rules);
}

void do_landlock(const struct setpriv_landlock_opts *opts)
{
	struct landlock_rule_entry *rule;
	struct list_head *entry;
	int fd, ret;

	if (!opts->access_fs && !opts->access_net && !opts->scoped)
		return;

	const struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = opts->access_fs,
		.handled_access_net = opts->access_net,
		.scoped = opts->scoped,
	};

	fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	if (fd == -1)
		err(SETPRIV_EXIT_PRIVERR, _("landlock_create_ruleset failed"));

	list_for_each(entry, &opts->rules) {
		rule = list_entry(entry, struct landlock_rule_entry, head);

		switch (rule->rule_type) {
		case LANDLOCK_RULE_PATH_BENEATH:
			ret = landlock_add_rule(fd, rule->rule_type,
						 &rule->path_beneath_attr, 0);
			break;
		case LANDLOCK_RULE_NET_PORT:
			ret = landlock_add_rule(fd, rule->rule_type,
						 &rule->net_port_attr, 0);
			break;
		default:
			abort();
		}
		if (ret == -1)
			err(SETPRIV_EXIT_PRIVERR, _("adding landlock rule failed"));
	}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		err(SETPRIV_EXIT_PRIVERR, _("disallow granting new privileges for landlock failed"));

	if (landlock_restrict_self(fd, opts->restrict_self_flags) == -1)
		err(SETPRIV_EXIT_PRIVERR, _("landlock_restrict_self failed"));
}

void usage_landlock(FILE *out)
{
	size_t i;

	fputs(USAGE_ARGUMENTS, out);
	fputs(_(" <access> is a landlock access; syntax is <category>[:<right>, ...>]\n"), out);
	fputs(_(" <rule> is a landlock rule; syntax is <type>:<right>:<argument>\n"), out);
	fputs(_(" <flags> is a comma separated list of landlock restrict-self flags\n"), out);

	fputs(USAGE_SEPARATOR, out);
	fputs(_(" available landlock access categories are:\n"), out);
	/* TRANSLATORS: Keep *{fs,net,scope}* untranslated, they're category names */
	fputs(_("  fs    - filesystem access rights\n"), out);
	fputs(_("  net   - network access rights\n"), out);
	fputs(_("  scope - IPC scoping restrictions (no exception rules possible)\n"), out);

	fputs(USAGE_SEPARATOR, out);
	fputs(_(" available landlock rule types are:\n"), out);
	/* TRANSLATORS: Keep *{path-beneath,net-port}* untranslated, they're type names */
	fputs(_("  path-beneath - filesystem based rule; <argument> is a path\n"), out);
	fputs(_("  net-port     - network port based rule; <argument> is a port number\n"), out);

	fputs(USAGE_SEPARATOR, out);
	fputs(_(" available landlock filesystem rights are:\n"), out);
	for (i = 0; i < ARRAY_SIZE(landlock_access_fs); i++) {
		fprintf(out, "  %20s - %s\n", landlock_access_fs[i].type,
					_(landlock_access_fs[i].help));
	}

	fputs(USAGE_SEPARATOR, out);
	fputs(_(" available landlock network rights are:\n"), out);
	for (i = 0; i < ARRAY_SIZE(landlock_access_net); i++) {
		fprintf(out, "  %20s - %s\n", landlock_access_net[i].type,
					_(landlock_access_net[i].help));
	}

	fputs(USAGE_SEPARATOR, out);
	fputs(_(" available landlock scopes are:\n"), out);
	for (i = 0; i < ARRAY_SIZE(landlock_scope); i++) {
		fprintf(out, "  %20s - %s\n", landlock_scope[i].type,
					_(landlock_scope[i].help));
	}

	fputs(USAGE_SEPARATOR, out);
	fputs(_(" available landlock restrict-self flags are:\n"), out);
	for (i = 0; i < ARRAY_SIZE(landlock_restrict_self_flags); i++) {
		fprintf(out, "  %20s - %s\n", landlock_restrict_self_flags[i].type,
					_(landlock_restrict_self_flags[i].help));
	}
}
