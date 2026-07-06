/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief What a SIP endpoint is worth as a security posture
 *
 * @defgroup tapi_sip_audit SIP security posture
 * @ingroup tapi_sip
 * @{
 *
 * A SIP UA/proxy read as a security posture and reported through
 * tsf-cybersec: does it answer at all, does OPTIONS leak the exact
 * stack and version, does it bind a contact for an unauthenticated
 * REGISTER, and does it answer differently for an existing versus a
 * made-up account (user enumeration).
 *
 * | Finding | Severity | Raised when |
 * |---|---|---|
 * | @c sip.responds | info | the endpoint answers OPTIONS |
 * | @c sip.options-leak | low | OPTIONS reveals a Server / User-Agent banner |
 * | @c sip.registration-unauthenticated | high | an anonymous REGISTER is accepted |
 * | @c sip.user-enumeration | medium | existing vs made-up AoRs answer differently |
 * | @c sip.not-assessed | info | nothing answered |
 *
 * The REGISTER probes send real requests to a real UA/proxy, so the
 * anonymous-REGISTER and enumeration checks run only when
 * @a attempt_register is set, and only against a target you are
 * authorized to assess.
 */

#ifndef __TAPI_SIP_AUDIT_H__
#define __TAPI_SIP_AUDIT_H__

#include "te_defs.h"
#include "te_errno.h"
#include "rcf_rpc.h"

#include "tapi_cybersec.h"
#include "tapi_sip.h"

#ifdef __cplusplus
extern "C" {
#endif

/** What the SIP endpoint is expected to be. */
typedef struct tapi_sip_audit_policy {
    /** Request URI to probe, e.g. @c "sip:pbx.example" (required). */
    const char *target;
    /** From URI for the probes, or @c NULL for a default throwaway AoR. */
    const char *from;
    /** Transport. */
    tapi_sip_transport transport;
    /** Per-request timeout, ms, or @c 0 for 5000. */
    int timeout_ms;
    /**
     * Send unauthenticated REGISTER probes (the anonymous-binding and
     * user-enumeration checks). Off by default: it writes to a real
     * registrar. Needs @a probe_aor.
     */
    bool attempt_register;
    /** Registrar/proxy URI for REGISTER, or @c NULL to use @a target. */
    const char *registrar;
    /**
     * A plausibly-existing AoR (e.g. @c "sip:1001@example") for the
     * REGISTER probes; the enumeration check compares it against a
     * made-up AoR in the same domain. @c NULL skips the REGISTER checks.
     */
    const char *probe_aor;
} tapi_sip_audit_policy;

/**
 * The default: UDP, 5 s timeout, OPTIONS only (no REGISTER probes).
 */
extern const tapi_sip_audit_policy tapi_sip_default_audit_policy;

/**
 * Read a SIP endpoint's posture into @p report.
 *
 * @param[in]  rpcs     RPC server on the agent.
 * @param[in]  policy   What is expected (its @a target is required),
 *                      or @c NULL for the default (which has no target
 *                      and so only reports @c sip.not-assessed).
 * @param[out] report   Report to append findings to.
 *
 * @return Status code of reading the posture, not its verdict.
 */
extern te_errno tapi_sip_audit(rcf_rpc_server *rpcs,
                               const tapi_sip_audit_policy *policy,
                               tapi_cybersec_report *report);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_SIP_AUDIT_H__ */

/**@} <!-- END tapi_sip_audit --> */
