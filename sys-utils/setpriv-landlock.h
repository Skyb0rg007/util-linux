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

#ifndef UTIL_LINUX_SETPRIV_LANDLOCK
#define UTIL_LINUX_SETPRIV_LANDLOCK

#ifdef HAVE_LINUX_LANDLOCK_H

#include <stdbool.h>
#include <stdint.h>

#include "list.h"

struct setpriv_landlock_opts {
	uint64_t access_fs;
	uint64_t access_net;
	uint64_t scoped;

	/* Subsets of access_fs/access_net/scoped that were explicitly named
	 * by the user (e.g. "fs:resolve-unix"), as opposed to pulled in via
	 * the bare "fs"/"net"/"scope" wildcard. Explicitly named rights
	 * always fail if the running kernel doesn't support them; wildcard
	 * rights are dropped silently unless an ABI is pinned with
	 * --landlock-abi. */
	uint64_t explicit_fs;
	uint64_t explicit_net;
	uint64_t explicit_scoped;

	uint64_t quiet_access_fs;
	uint64_t quiet_access_net;
	uint64_t quiet_scoped;

	uint32_t restrict_self_flags;

	/* --landlock-abi: if abi_pinned, abi_min is the minimum Landlock ABI
	 * the running kernel must support, or setpriv fails outright. abi_max
	 * is not a second requirement but a ceiling: masking behaves as if
	 * the kernel were exactly ABI abi_max, even when it actually supports
	 * more, since a right added after abi_max is one the script's author
	 * had no way to know about. This masking applies uniformly to every
	 * access and rule, explicit or wildcard alike, unlike the default
	 * behavior described above for explicit_fs, where only wildcards
	 * degrade silently. */
	int32_t abi_min;
	int32_t abi_max;
	bool abi_pinned;

	struct list_head rules;
};

void do_landlock(const struct setpriv_landlock_opts *opts);
void parse_landlock_access(struct setpriv_landlock_opts *opts, const char *str);
void parse_landlock_rule(struct setpriv_landlock_opts *opts, const char *str);
void parse_landlock_restrict_self(struct setpriv_landlock_opts *opts, const char *str);
void parse_landlock_abi(struct setpriv_landlock_opts *opts, const char *str);
void init_landlock_opts(struct setpriv_landlock_opts *opts);
void usage_landlock(FILE *out);

#else

#include "c.h"
#include "nls.h"

struct setpriv_landlock_opts {};

static inline void do_landlock(const void *opts __attribute__((unused))) {}
static inline void parse_landlock_access(
		void *opts __attribute__((unused)),
		const char *str __attribute__((unused)))
{
	errx(EXIT_FAILURE, _("no support for landlock"));
}
#define parse_landlock_rule parse_landlock_access
#define parse_landlock_restrict_self parse_landlock_access
#define parse_landlock_abi parse_landlock_access
static inline void init_landlock_opts(void *opts __attribute__((unused))) {}
static inline void usage_landlock(FILE *out __attribute__((unused))) {}

#endif /* HAVE_LINUX_LANDLOCK_H */

#endif
