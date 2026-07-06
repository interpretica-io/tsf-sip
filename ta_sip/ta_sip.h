/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Agent-side SIP (VoIP) probing
 *
 * Probing a SIP user agent / proxy from an agent over **libeXosip2**
 * (on top of libosip2): the library is linked into the agent and
 * driven in-process, nothing is spawned. This is signalling only -
 * OPTIONS, REGISTER and a bare INVITE/CANCEL - and carries no media
 * (RTP is out of scope). The agent and its RPC server both link this;
 * the RPCs (see sip_rpc.x.m4) are thin wrappers over these functions.
 *
 * Each call stands up its own eXosip context on an ephemeral port,
 * sends one request, collects the first final response within the
 * timeout, and tears the context down - so nothing survives between
 * calls.
 */

#ifndef __TA_SIP_H__
#define __TA_SIP_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Transport for a probe. The values are the RPC's wire values. */
enum {
    TA_SIP_UDP = 0,     /**< SIP over UDP. */
    TA_SIP_TCP = 1,     /**< SIP over TCP. */
};

/**
 * Send a SIP OPTIONS and read the response.
 *
 * OPTIONS is the "are you a SIP UA, and what are you" ping: the answer
 * carries the stack's @c Server / @c User-Agent and its @c Allow list.
 *
 * @param[in]  target       Request URI, e.g. @c "sip:pbx.example".
 * @param[in]  from         From URI, e.g. @c "sip:probe@example".
 * @param[in]  transport    @c TA_SIP_UDP or @c TA_SIP_TCP.
 * @param[in]  timeout_ms   How long to wait for a final response, ms.
 * @param[out] status       The SIP status code, or @c 0 if nothing
 *                          answered in time.
 * @param[out] server       The @c Server header, if any.
 * @param[out] user_agent   The @c User-Agent header, if any.
 * @param[out] allow         The @c Allow header (methods), if any.
 *
 * @return Status code.
 */
extern te_errno ta_sip_options(const char *target, const char *from,
                               int transport, int timeout_ms, int *status,
                               te_string *server, te_string *user_agent,
                               te_string *allow);

/**
 * Attempt a SIP REGISTER and read what came back.
 *
 * With @p username / @p password set, authentication is supplied and
 * retried automatically; with them @c NULL, the REGISTER is sent
 * unauthenticated and not retried - so @p accepted tells you whether
 * the registrar let an anonymous binding through (it should not).
 *
 * @param[in]  registrar    Registrar/proxy URI, e.g. @c "sip:example".
 * @param[in]  aor          Address of record, e.g. @c "sip:1001@example".
 * @param[in]  contact      Contact URI to bind, or @c NULL to derive it.
 * @param[in]  username     Auth username, or @c NULL for anonymous.
 * @param[in]  password     Auth password, or @c NULL for anonymous.
 * @param[in]  expires      Requested registration lifetime, seconds.
 * @param[in]  transport    @c TA_SIP_UDP or @c TA_SIP_TCP.
 * @param[in]  timeout_ms   How long to wait for a final response, ms.
 * @param[out] status       The SIP status code, or @c 0 if none in time.
 * @param[out] accepted     @c true if the registration succeeded.
 * @param[out] auth_scheme  The challenged scheme (e.g. @c "Digest") when
 *                          the registrar replied 401/407.
 *
 * @return Status code.
 */
extern te_errno ta_sip_register(const char *registrar, const char *aor,
                                const char *contact, const char *username,
                                const char *password, int expires,
                                int transport, int timeout_ms, int *status,
                                te_bool *accepted, te_string *auth_scheme);

/**
 * Send a bare INVITE and immediately tear the call down.
 *
 * Reaches the first response (100/180/200/4xx...) and then terminates
 * the dialog with CANCEL/BYE, so no call is actually established. It is
 * a reachability/behaviour probe, not a call.
 *
 * @param[in]  target       Callee URI.
 * @param[in]  from         From URI.
 * @param[in]  transport    @c TA_SIP_UDP or @c TA_SIP_TCP.
 * @param[in]  timeout_ms   How long to wait for a response, ms.
 * @param[out] status       The first SIP status code seen, or @c 0.
 * @param[out] server       The @c Server header, if any.
 *
 * @return Status code.
 */
extern te_errno ta_sip_invite(const char *target, const char *from,
                              int transport, int timeout_ms, int *status,
                              te_string *server);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TA_SIP_H__ */
