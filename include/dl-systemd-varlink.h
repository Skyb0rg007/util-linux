/*
 * No copyright is claimed.  This code is in the public domain; do with
 * it what you wish.
 */
#ifndef UTIL_LINUX_DL_SYSTEMD_VARLINK_H
#define UTIL_LINUX_DL_SYSTEMD_VARLINK_H

#ifdef HAVE_LIBSYSTEMD

#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>

#ifdef USE_DLOPEN_SYSTEMD

#include "dl-utils.h"

/* Pointers to libsystemd functions (initialized by dlsym()) */
struct ul_systemd_varlink_opers {
	/* sd-varlink */
	int (*sd_varlink_connect_address)(sd_varlink **, const char *);
	int (*sd_varlink_set_allow_fd_passing_output)(sd_varlink *, int);
	int (*sd_varlink_push_dup_fd)(sd_varlink *, int);
	int (*sd_varlink_callb)(sd_varlink *, const char *, sd_json_variant **, const char **, ...);
	sd_varlink *(*sd_varlink_close_unref)(sd_varlink *);
	/* sd-json */
	sd_json_variant *(*sd_json_variant_unref)(sd_json_variant *);
	int (*sd_json_variant_format)(sd_json_variant *, sd_json_format_flags_t, char **);
};

typedef struct ul_systemd_varlink_opers ul_systemd_varlink_opers;

extern struct ul_systemd_varlink_opers ul_systemd_varlink;

extern int ul_dlopen_libsystemd_varlink(void);

#define systemd_varlink_call(_func)	(ul_systemd_varlink._func)

#else /* !USE_DLOPEN_SYSTEMD */

static inline int ul_dlopen_libsystemd_varlink(void) { return 0; }

#define systemd_varlink_call(_func)	(_func)

#endif /* USE_DLOPEN_SYSTEMD */


#endif /* HAVE_LIBSYSTEMD */
#endif /* UTIL_LINUX_DL_SYSTEMD_VARLINK_H */
