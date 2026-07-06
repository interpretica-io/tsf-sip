/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief SIP TAPI: RPC client wrappers
 *
 * Client wrappers of the sip_* RPCs, see sip_rpc.x.m4. Tests use
 * tapi_sip.h; these are the calls behind it, one per RPC.
 */

#ifndef __TAPI_SIP_RPC_H__
#define __TAPI_SIP_RPC_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "rcf_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/** OPTIONS; @p status is the SIP code (0 = no answer). */
extern te_errno rpc_sip_options(rcf_rpc_server *rpcs, const char *target,
                                const char *from, int transport,
                                int timeout_ms, int *status,
                                te_string *server, te_string *user_agent,
                                te_string *allow);

/** REGISTER; @p accepted tells whether the binding was taken. */
extern te_errno rpc_sip_register(rcf_rpc_server *rpcs, const char *registrar,
                                 const char *aor, const char *contact,
                                 const char *username, const char *password,
                                 int expires, int transport, int timeout_ms,
                                 int *status, te_bool *accepted,
                                 te_string *auth_scheme);

/** INVITE, torn down once answered. */
extern te_errno rpc_sip_invite(rcf_rpc_server *rpcs, const char *target,
                               const char *from, int transport,
                               int timeout_ms, int *status,
                               te_string *server);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_SIP_RPC_H__ */
