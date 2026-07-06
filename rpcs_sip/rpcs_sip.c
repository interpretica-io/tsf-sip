/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief SIP RPC server library
 *
 * The sip_* RPCs (see sip_rpc.x.m4) on top of ta_sip.
 * TARPC_FUNC_STATIC() binds an RPC to the function of the same name,
 * so each RPC has a plain C function first and the wrapper after it.
 */

#define TE_LGR_USER     "RPC SIP"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "rpc_server.h"

#include "ta_sip.h"

/* Hand a te_string result over to an RPC string field (never NULL). */
static char *
take(te_string *str)
{
    return str->ptr != NULL ? str->ptr : TE_STRDUP("");
}

/* An empty RPC string ("") means "not given" to ta_sip (NULL). */
static const char *
opt(const char *s)
{
    return (s != NULL && s[0] != '\0') ? s : NULL;
}

static te_errno
sip_options(const char *target, const char *from, int transport,
            int timeout_ms, int *status, char **server, char **user_agent,
            char **allow)
{
    te_string s = TE_STRING_INIT;
    te_string ua = TE_STRING_INIT;
    te_string al = TE_STRING_INIT;
    te_errno rc = ta_sip_options(target, from, transport, timeout_ms, status,
                                 &s, &ua, &al);

    *server = take(&s);
    *user_agent = take(&ua);
    *allow = take(&al);
    return rc;
}

TARPC_FUNC_STATIC(sip_options, {},
{
    int status = 0;

    MAKE_CALL(out->retval = func(in->target, in->from, in->transport,
                                 in->timeout_ms, &status, &out->server,
                                 &out->user_agent, &out->allow));
    out->status = status;
    out->common.errno_changed = false;
})

static te_errno
sip_register(const char *registrar, const char *aor, const char *contact,
             const char *username, const char *password, int expires,
             int transport, int timeout_ms, int *status, te_bool *accepted,
             char **auth_scheme)
{
    te_string scheme = TE_STRING_INIT;
    te_errno rc = ta_sip_register(registrar, opt(aor) != NULL ? aor : "",
                                  opt(contact), opt(username), opt(password),
                                  expires, transport, timeout_ms, status,
                                  accepted, &scheme);

    *auth_scheme = take(&scheme);
    return rc;
}

TARPC_FUNC_STATIC(sip_register, {},
{
    int status = 0;
    te_bool accepted = false;

    MAKE_CALL(out->retval = func(in->registrar, in->aor, in->contact,
                                 in->username, in->password, in->expires,
                                 in->transport, in->timeout_ms, &status,
                                 &accepted, &out->auth_scheme));
    out->status = status;
    out->accepted = accepted;
    out->common.errno_changed = false;
})

static te_errno
sip_invite(const char *target, const char *from, int transport,
           int timeout_ms, int *status, char **server)
{
    te_string s = TE_STRING_INIT;
    te_errno rc = ta_sip_invite(target, from, transport, timeout_ms, status,
                                &s);

    *server = take(&s);
    return rc;
}

TARPC_FUNC_STATIC(sip_invite, {},
{
    int status = 0;

    MAKE_CALL(out->retval = func(in->target, in->from, in->transport,
                                 in->timeout_ms, &status, &out->server));
    out->status = status;
    out->common.errno_changed = false;
})
