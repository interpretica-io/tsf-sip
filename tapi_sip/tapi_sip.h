/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Probing SIP (VoIP) from an agent in a test
 *
 * @defgroup tapi_sip SIP probing (tapi_sip)
 * @{
 *
 * Probing a SIP user agent or proxy from a Test Agent over libeXosip2:
 * OPTIONS (is it a SIP UA, and what stack), REGISTER (does it demand
 * authentication, or bind an anonymous contact), and a bare INVITE that
 * is cancelled as soon as it is answered. Signalling only - no media.
 *
 * - tapi_sip_options()/register()/invite() each fill a #tapi_sip_probe;
 * - @ref tapi_sip_audit (tapi_sip_audit.h) reads a target as a security
 *   posture through tsf-cybersec.
 *
 * @code
 * tapi_sip_probe probe;
 *
 * CHECK_RC(tapi_sip_options(rpcs, "sip:pbx.example", "sip:probe@example",
 *                           TAPI_SIP_UDP, 5000, &probe));
 * if (probe.status == 0)
 *     TEST_SKIP("No SIP UA answered");
 * RING("SIP %d, server=%s allow=%s", probe.status,
 *      probe.server != NULL ? probe.server : "?",
 *      probe.allow != NULL ? probe.allow : "?");
 * tapi_sip_probe_free(&probe);
 * @endcode
 */

#ifndef __TAPI_SIP_H__
#define __TAPI_SIP_H__

#include "te_defs.h"
#include "te_errno.h"
#include "rcf_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Transport. The values are the RPC's wire values. */
typedef enum tapi_sip_transport {
    TAPI_SIP_UDP = 0,   /**< SIP over UDP. */
    TAPI_SIP_TCP = 1,   /**< SIP over TCP. */
} tapi_sip_transport;

/** The result of one SIP probe. */
typedef struct tapi_sip_probe {
    /** SIP status code of the final response, or @c 0 if none in time. */
    int status;
    /** The @c Server header, or @c NULL. */
    char *server;
    /** The @c User-Agent header, or @c NULL. */
    char *user_agent;
    /** The @c Allow header (methods), or @c NULL. */
    char *allow;
    /** For REGISTER: @c true if the binding was accepted. */
    bool reg_accepted;
    /** For REGISTER: the challenged auth scheme (e.g. @c "Digest"), or
     * @c NULL. */
    char *auth_scheme;
} tapi_sip_probe;

/**
 * OPTIONS: is it a SIP UA, and what does it say about itself?
 *
 * @param[in]  rpcs         RPC server on the agent.
 * @param[in]  target       Request URI (e.g. @c "sip:pbx.example").
 * @param[in]  from         From URI (e.g. @c "sip:probe@example").
 * @param[in]  transport    Transport.
 * @param[in]  timeout_ms   How long to wait for a response, ms.
 * @param[out] probe        Result; release with tapi_sip_probe_free().
 *
 * @return Status code.
 */
extern te_errno tapi_sip_options(rcf_rpc_server *rpcs, const char *target,
                                 const char *from,
                                 tapi_sip_transport transport,
                                 int timeout_ms, tapi_sip_probe *probe);

/**
 * REGISTER: with @p username / @p password set, authenticate; with them
 * @c NULL, attempt an anonymous binding and report whether it was taken.
 *
 * @param[in]  rpcs         RPC server on the agent.
 * @param[in]  registrar    Registrar/proxy URI.
 * @param[in]  aor          Address of record to register.
 * @param[in]  contact      Contact URI, or @c NULL to derive it.
 * @param[in]  username     Auth username, or @c NULL for anonymous.
 * @param[in]  password     Auth password, or @c NULL for anonymous.
 * @param[in]  expires      Requested lifetime, seconds.
 * @param[in]  transport    Transport.
 * @param[in]  timeout_ms   How long to wait, ms.
 * @param[out] probe        Result; release with tapi_sip_probe_free().
 *
 * @return Status code.
 */
extern te_errno tapi_sip_register(rcf_rpc_server *rpcs, const char *registrar,
                                  const char *aor, const char *contact,
                                  const char *username, const char *password,
                                  int expires, tapi_sip_transport transport,
                                  int timeout_ms, tapi_sip_probe *probe);

/**
 * INVITE, torn down as soon as it is answered (a reachability probe).
 *
 * @param[in]  rpcs         RPC server on the agent.
 * @param[in]  target       Callee URI.
 * @param[in]  from         From URI.
 * @param[in]  transport    Transport.
 * @param[in]  timeout_ms   How long to wait, ms.
 * @param[out] probe        Result; release with tapi_sip_probe_free().
 *
 * @return Status code.
 */
extern te_errno tapi_sip_invite(rcf_rpc_server *rpcs, const char *target,
                                const char *from,
                                tapi_sip_transport transport, int timeout_ms,
                                tapi_sip_probe *probe);

/**
 * Does a SIP UA answer OPTIONS at @p target at all?
 *
 * @param rpcs          RPC server on the agent.
 * @param target        Request URI.
 * @param transport     Transport.
 * @param timeout_ms    How long to wait, ms.
 *
 * @return @c true when a final response came back.
 */
extern bool tapi_sip_responds(rcf_rpc_server *rpcs, const char *target,
                              tapi_sip_transport transport, int timeout_ms);

/**
 * Write a probe into the log.
 *
 * @param probe         Probe.
 */
extern void tapi_sip_probe_log(const tapi_sip_probe *probe);

/**
 * Release a probe.
 *
 * @param probe         Probe.
 */
extern void tapi_sip_probe_free(tapi_sip_probe *probe);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_SIP_H__ */

/**@} <!-- END tapi_sip --> */
