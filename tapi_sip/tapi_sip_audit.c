/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief What a SIP endpoint is worth as a security posture
 *
 * Probes with tapi_sip and classifies the result into tsf-cybersec
 * findings. OPTIONS is always sent; the REGISTER-based checks run only
 * when the policy enables them.
 */

#define TE_LGR_USER     "TAPI SIP AUDIT"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "logger_api.h"

#include "tapi_sip.h"
#include "tapi_sip_audit.h"

/* See description in tapi_sip_audit.h */
const tapi_sip_audit_policy tapi_sip_default_audit_policy = {
    .target = NULL,
    .from = NULL,
    .transport = TAPI_SIP_UDP,
    .timeout_ms = 0,
    .attempt_register = false,
    .registrar = NULL,
    .probe_aor = NULL,
};

/** The domain part of an AoR/URI ("sip:user@host" or "sip:host"). */
static const char *
sip_domain(const char *uri)
{
    const char *at = (uri != NULL) ? strchr(uri, '@') : NULL;

    if (at != NULL)
        return at + 1;
    if (uri != NULL && strncmp(uri, "sip:", 4) == 0)
        return uri + 4;
    return uri != NULL ? uri : "invalid";
}

/* See description in tapi_sip_audit.h */
te_errno
tapi_sip_audit(rcf_rpc_server *rpcs, const tapi_sip_audit_policy *policy,
               tapi_cybersec_report *report)
{
    tapi_sip_probe probe;
    const char *target;
    const char *from;
    const char *registrar;
    int timeout;
    te_errno rc;

    if (policy == NULL)
        policy = &tapi_sip_default_audit_policy;

    if (policy->target == NULL)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
            "sip.not-assessed", "-", "no SIP target was given");
        return 0;
    }

    target = policy->target;
    from = policy->from != NULL ? policy->from : "sip:probe@tsf.invalid";
    registrar = policy->registrar != NULL ? policy->registrar : target;
    timeout = policy->timeout_ms != 0 ? policy->timeout_ms : 5000;

    /* OPTIONS, always. */
    rc = tapi_sip_options(rpcs, target, from, policy->transport, timeout,
                          &probe);
    if (rc != 0)
        return rc;

    if (probe.status == 0)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
            "sip.not-assessed", target,
            "no SIP response to OPTIONS within %d ms", timeout);
        tapi_sip_probe_free(&probe);
        return 0;
    }

    tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
        "sip.responds", target, "SIP OPTIONS answered %d", probe.status);

    if (probe.server != NULL || probe.user_agent != NULL)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_LOW,
            "sip.options-leak", target,
            "OPTIONS reveals the stack: Server='%s' User-Agent='%s'",
            probe.server != NULL ? probe.server : "",
            probe.user_agent != NULL ? probe.user_agent : "");
    }
    tapi_sip_probe_free(&probe);

    /* REGISTER-based checks, only when enabled and given an AoR. */
    if (policy->attempt_register && policy->probe_aor != NULL)
    {
        tapi_sip_probe anon;
        tapi_sip_probe bogus;
        te_string bogus_aor = TE_STRING_INIT;

        /* Anonymous binding: a REGISTER with no credentials. */
        rc = tapi_sip_register(rpcs, registrar, policy->probe_aor, NULL,
                               NULL, NULL, 60, policy->transport, timeout,
                               &anon);
        if (rc != 0)
            return rc;
        if (anon.reg_accepted)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                "sip.registration-unauthenticated", target,
                "an anonymous REGISTER for '%s' was accepted (status %d)",
                policy->probe_aor, anon.status);
        }

        /* User enumeration: the made-up AoR should be indistinguishable
         * from the real one. A different status code tells an attacker
         * which accounts exist. */
        te_string_append(&bogus_aor, "sip:tsf-nouser-x9q7@%s",
                         sip_domain(policy->probe_aor));
        rc = tapi_sip_register(rpcs, registrar, te_string_value(&bogus_aor),
                               NULL, NULL, NULL, 60, policy->transport,
                               timeout, &bogus);
        if (rc == 0 && anon.status != 0 && bogus.status != 0 &&
            anon.status != bogus.status)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                "sip.user-enumeration", target,
                "existing vs made-up AoR answer differently (%d vs %d) - "
                "accounts can be enumerated", anon.status, bogus.status);
        }

        te_string_free(&bogus_aor);
        tapi_sip_probe_free(&anon);
        if (rc == 0)
            tapi_sip_probe_free(&bogus);
    }

    return 0;
}
