/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief SIP TAPI: RPC client wrappers
 *
 * The rcf_rpc_call() boilerplate behind tapi_sip. The RPCs return
 * te_errno; an RPC transport failure is mapped to TE_ECORRUPTED.
 */

#define TE_LGR_USER     "TAPI SIP RPC"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "logger_api.h"
#include "tapi_rpc_internal.h"
#include "tarpc.h"

#include "tapi_sip_rpc.h"

#define CHECK_RPC_ERRNO_UNCHANGED(_func, _var) \
    CHECK_RETVAL_VAR_ERR_COND(_func, _var, false,                    \
                              TE_RC(TE_TAPI, TE_ECORRUPTED), false)

/* Append an RPC string result, when there is one. */
static void
take_string(te_string *dst, const char *src)
{
    if (dst != NULL && src != NULL)
        te_string_append(dst, "%s", src);
}

/* NULL -> "" so the XDR string is never a null pointer. */
static const char *
s(const char *v)
{
    return v != NULL ? v : "";
}

/* See description in tapi_sip_rpc.h */
te_errno
rpc_sip_options(rcf_rpc_server *rpcs, const char *target, const char *from,
                int transport, int timeout_ms, int *status,
                te_string *server, te_string *user_agent, te_string *allow)
{
    tarpc_sip_options_in in;
    tarpc_sip_options_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.target = (char *)s(target);
    in.from = (char *)s(from);
    in.transport = transport;
    in.timeout_ms = timeout_ms;

    rcf_rpc_call(rpcs, "sip_options", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(sip_options, out.retval);
    TAPI_RPC_LOG(rpcs, sip_options, "%s", "%r status=%d",
                 s(target), out.retval, out.status);

    if (out.retval == 0)
    {
        if (status != NULL)
            *status = out.status;
        take_string(server, out.server);
        take_string(user_agent, out.user_agent);
        take_string(allow, out.allow);
    }
    RETVAL_TE_ERRNO(sip_options, out.retval);
}

/* See description in tapi_sip_rpc.h */
te_errno
rpc_sip_register(rcf_rpc_server *rpcs, const char *registrar, const char *aor,
                 const char *contact, const char *username,
                 const char *password, int expires, int transport,
                 int timeout_ms, int *status, te_bool *accepted,
                 te_string *auth_scheme)
{
    tarpc_sip_register_in in;
    tarpc_sip_register_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.registrar = (char *)s(registrar);
    in.aor = (char *)s(aor);
    in.contact = (char *)s(contact);
    in.username = (char *)s(username);
    in.password = (char *)s(password);
    in.expires = expires;
    in.transport = transport;
    in.timeout_ms = timeout_ms;

    rcf_rpc_call(rpcs, "sip_register", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(sip_register, out.retval);
    TAPI_RPC_LOG(rpcs, sip_register, "%s", "%r status=%d accepted=%d",
                 s(aor), out.retval, out.status, out.accepted);

    if (out.retval == 0)
    {
        if (status != NULL)
            *status = out.status;
        if (accepted != NULL)
            *accepted = out.accepted;
        take_string(auth_scheme, out.auth_scheme);
    }
    RETVAL_TE_ERRNO(sip_register, out.retval);
}

/* See description in tapi_sip_rpc.h */
te_errno
rpc_sip_invite(rcf_rpc_server *rpcs, const char *target, const char *from,
               int transport, int timeout_ms, int *status, te_string *server)
{
    tarpc_sip_invite_in in;
    tarpc_sip_invite_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.target = (char *)s(target);
    in.from = (char *)s(from);
    in.transport = transport;
    in.timeout_ms = timeout_ms;

    rcf_rpc_call(rpcs, "sip_invite", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(sip_invite, out.retval);
    TAPI_RPC_LOG(rpcs, sip_invite, "%s", "%r status=%d",
                 s(target), out.retval, out.status);

    if (out.retval == 0)
    {
        if (status != NULL)
            *status = out.status;
        take_string(server, out.server);
    }
    RETVAL_TE_ERRNO(sip_invite, out.retval);
}
