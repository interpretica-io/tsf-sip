/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Probing SIP (VoIP) from an agent in a test
 *
 * The engine-side layer over the sip_* RPCs: it drives the probe on the
 * agent and collects the response into a #tapi_sip_probe.
 */

#define TE_LGR_USER     "TAPI SIP"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "logger_api.h"

#include "tapi_sip.h"
#include "tapi_sip_rpc.h"

/** A te_string's value as a heap string, or NULL when it is empty. */
static char *
take_or_null(te_string *str)
{
    char *v = (str->len != 0) ? TE_STRDUP(te_string_value(str)) : NULL;

    te_string_free(str);
    return v;
}

/* See description in tapi_sip.h */
te_errno
tapi_sip_options(rcf_rpc_server *rpcs, const char *target, const char *from,
                 tapi_sip_transport transport, int timeout_ms,
                 tapi_sip_probe *probe)
{
    te_string server = TE_STRING_INIT;
    te_string ua = TE_STRING_INIT;
    te_string allow = TE_STRING_INIT;
    te_errno rc;

    memset(probe, 0, sizeof(*probe));
    rc = rpc_sip_options(rpcs, target, from, (int)transport, timeout_ms,
                         &probe->status, &server, &ua, &allow);
    probe->server = take_or_null(&server);
    probe->user_agent = take_or_null(&ua);
    probe->allow = take_or_null(&allow);
    return rc;
}

/* See description in tapi_sip.h */
te_errno
tapi_sip_register(rcf_rpc_server *rpcs, const char *registrar,
                  const char *aor, const char *contact, const char *username,
                  const char *password, int expires,
                  tapi_sip_transport transport, int timeout_ms,
                  tapi_sip_probe *probe)
{
    te_string scheme = TE_STRING_INIT;
    te_bool accepted = false;
    te_errno rc;

    memset(probe, 0, sizeof(*probe));
    rc = rpc_sip_register(rpcs, registrar, aor, contact, username, password,
                          expires, (int)transport, timeout_ms,
                          &probe->status, &accepted, &scheme);
    probe->reg_accepted = accepted;
    probe->auth_scheme = take_or_null(&scheme);
    return rc;
}

/* See description in tapi_sip.h */
te_errno
tapi_sip_invite(rcf_rpc_server *rpcs, const char *target, const char *from,
                tapi_sip_transport transport, int timeout_ms,
                tapi_sip_probe *probe)
{
    te_string server = TE_STRING_INIT;
    te_errno rc;

    memset(probe, 0, sizeof(*probe));
    rc = rpc_sip_invite(rpcs, target, from, (int)transport, timeout_ms,
                        &probe->status, &server);
    probe->server = take_or_null(&server);
    return rc;
}

/* See description in tapi_sip.h */
bool
tapi_sip_responds(rcf_rpc_server *rpcs, const char *target,
                  tapi_sip_transport transport, int timeout_ms)
{
    tapi_sip_probe probe;
    bool up;

    if (tapi_sip_options(rpcs, target, "sip:probe@tsf.invalid", transport,
                         timeout_ms, &probe) != 0)
        return false;
    up = (probe.status != 0);
    tapi_sip_probe_free(&probe);
    return up;
}

/* See description in tapi_sip.h */
void
tapi_sip_probe_log(const tapi_sip_probe *probe)
{
    RING("SIP probe: status=%d server=%s user-agent=%s allow=[%s] "
         "registered=%s auth=%s",
         probe->status,
         probe->server != NULL ? probe->server : "?",
         probe->user_agent != NULL ? probe->user_agent : "?",
         probe->allow != NULL ? probe->allow : "",
         probe->reg_accepted ? "yes" : "no",
         probe->auth_scheme != NULL ? probe->auth_scheme : "-");
}

/* See description in tapi_sip.h */
void
tapi_sip_probe_free(tapi_sip_probe *probe)
{
    free(probe->server);
    free(probe->user_agent);
    free(probe->allow);
    free(probe->auth_scheme);
    memset(probe, 0, sizeof(*probe));
}
