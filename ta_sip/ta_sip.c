/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Agent-side SIP probing over libeXosip2
 *
 * Written against the eXosip2 5.x API. Each probe stands up its own
 * eXosip context on an ephemeral port, sends one request, pumps the
 * event loop until the first final response or the timeout, pulls what
 * it needs out of the response, and tears the context down. Signalling
 * only - no media is set up, and an INVITE is cancelled as soon as it
 * is answered.
 */

#define TE_LGR_USER     "TA SIP"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/in.h>

#include <eXosip2/eXosip.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "logger_api.h"

#include "ta_sip.h"

/** Monotonic-ish milliseconds for the deadline loop. */
static long
sip_now_ms(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return (long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/** Bring up an eXosip context listening on an ephemeral local port. */
static te_errno
sip_up(struct eXosip_t **out, int transport)
{
    struct eXosip_t *ctx = eXosip_malloc();
    int proto = (transport == TA_SIP_TCP) ? IPPROTO_TCP : IPPROTO_UDP;

    *out = NULL;
    if (ctx == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOMEM);
    if (eXosip_init(ctx) != 0)
    {
        osip_free(ctx);
        ERROR("eXosip_init() failed");
        return TE_RC(TE_TA_UNIX, TE_EFAIL);
    }
    if (eXosip_listen_addr(ctx, proto, NULL, 0, AF_INET, 0) != 0)
    {
        eXosip_quit(ctx);
        osip_free(ctx);
        ERROR("eXosip_listen_addr() failed");
        return TE_RC(TE_TA_UNIX, TE_EADDRNOTAVAIL);
    }
    *out = ctx;
    return 0;
}

/** Tear an eXosip context down. */
static void
sip_down(struct eXosip_t *ctx)
{
    eXosip_quit(ctx);
    osip_free(ctx);
}

/** Pull Server / User-Agent / Allow out of a response. */
static void
sip_read_headers(osip_message_t *msg, te_string *server, te_string *ua,
                 te_string *allow)
{
    osip_header_t *h = NULL;
    osip_allow_t *al = NULL;
    int pos;
    bool first = true;

    if (server != NULL && osip_message_get_server(msg, 0, &h) >= 0 &&
        h != NULL && h->hvalue != NULL)
        te_string_append(server, "%s", h->hvalue);

    h = NULL;
    if (ua != NULL && osip_message_get_user_agent(msg, 0, &h) >= 0 &&
        h != NULL && h->hvalue != NULL)
        te_string_append(ua, "%s", h->hvalue);

    if (allow != NULL)
    {
        for (pos = 0; osip_message_get_allow(msg, pos, &al) >= 0 &&
             al != NULL; pos++)
        {
            if (al->value != NULL)
            {
                te_string_append(allow, "%s%s", first ? "" : ",", al->value);
                first = false;
            }
        }
    }
}

/** The challenged auth scheme from a 401 (WWW-) or 407 (Proxy-). */
static void
sip_read_auth_scheme(osip_message_t *msg, te_string *dst)
{
    osip_www_authenticate_t *wa = NULL;
    osip_proxy_authenticate_t *pa = NULL;
    const char *scheme = NULL;

    if (osip_message_get_www_authenticate(msg, 0, &wa) >= 0 && wa != NULL)
        scheme = osip_www_authenticate_get_auth_type(wa);
    else if (osip_message_get_proxy_authenticate(msg, 0, &pa) >= 0 &&
             pa != NULL)
        scheme = osip_proxy_authenticate_get_auth_type(pa);

    if (dst != NULL && scheme != NULL)
        te_string_append(dst, "%s", scheme);
}

/* See description in ta_sip.h */
te_errno
ta_sip_options(const char *target, const char *from, int transport,
               int timeout_ms, int *status, te_string *server,
               te_string *user_agent, te_string *allow)
{
    struct eXosip_t *ctx = NULL;
    osip_message_t *req = NULL;
    long deadline = sip_now_ms() + timeout_ms;
    bool done = false;
    te_errno rc;

    *status = 0;

    rc = sip_up(&ctx, transport);
    if (rc != 0)
        return rc;

    if (eXosip_options_build_request(ctx, &req, target, from, NULL) != 0 ||
        req == NULL)
    {
        sip_down(ctx);
        return TE_RC(TE_TA_UNIX, TE_EINVAL);
    }
    eXosip_lock(ctx);
    eXosip_options_send_request(ctx, req);
    eXosip_unlock(ctx);

    while (!done)
    {
        long remain = deadline - sip_now_ms();
        eXosip_event_t *evt;

        if (remain <= 0)
            break;
        evt = eXosip_event_wait(ctx, (int)(remain / 1000),
                                (int)(remain % 1000));
        eXosip_lock(ctx);
        eXosip_automatic_action(ctx);
        eXosip_unlock(ctx);
        if (evt == NULL)
            continue;

        if ((evt->type == EXOSIP_MESSAGE_ANSWERED ||
             evt->type == EXOSIP_MESSAGE_REQUESTFAILURE ||
             evt->type == EXOSIP_MESSAGE_SERVERFAILURE ||
             evt->type == EXOSIP_MESSAGE_GLOBALFAILURE) &&
            evt->response != NULL)
        {
            *status = osip_message_get_status_code(evt->response);
            sip_read_headers(evt->response, server, user_agent, allow);
            done = true;
        }
        eXosip_event_free(evt);
    }

    sip_down(ctx);
    return 0;
}

/* See description in ta_sip.h */
te_errno
ta_sip_register(const char *registrar, const char *aor, const char *contact,
                const char *username, const char *password, int expires,
                int transport, int timeout_ms, int *status,
                te_bool *accepted, te_string *auth_scheme)
{
    struct eXosip_t *ctx = NULL;
    osip_message_t *req = NULL;
    long deadline = sip_now_ms() + timeout_ms;
    bool with_auth = (username != NULL && password != NULL);
    bool done = false;
    int rid;
    te_errno rc;

    *status = 0;
    *accepted = false;

    rc = sip_up(&ctx, transport);
    if (rc != 0)
        return rc;

    /* With credentials, let eXosip answer the 401/407 challenge itself
     * (eXosip_automatic_action below). Without, the REGISTER goes out
     * anonymous and is never retried - so a success is a real finding. */
    if (with_auth)
        eXosip_add_authentication_info(ctx, username, username, password,
                                       NULL, NULL);

    rid = eXosip_register_build_initial_register(ctx, aor, registrar,
                                                 contact, expires, &req);
    if (rid < 0 || req == NULL)
    {
        sip_down(ctx);
        return TE_RC(TE_TA_UNIX, TE_EINVAL);
    }
    eXosip_lock(ctx);
    eXosip_register_send_register(ctx, rid, req);
    eXosip_unlock(ctx);

    while (!done)
    {
        long remain = deadline - sip_now_ms();
        eXosip_event_t *evt;

        if (remain <= 0)
            break;
        evt = eXosip_event_wait(ctx, (int)(remain / 1000),
                                (int)(remain % 1000));
        if (with_auth)
        {
            eXosip_lock(ctx);
            eXosip_automatic_action(ctx);
            eXosip_unlock(ctx);
        }
        if (evt == NULL)
            continue;

        if (evt->type == EXOSIP_REGISTRATION_SUCCESS)
        {
            *status = evt->response != NULL ?
                      osip_message_get_status_code(evt->response) : 200;
            *accepted = true;
            done = true;
        }
        else if (evt->type == EXOSIP_REGISTRATION_FAILURE &&
                 evt->response != NULL)
        {
            int code = osip_message_get_status_code(evt->response);

            /* A 401/407 without credentials is the expected challenge,
             * not a final answer; with credentials eXosip is retrying,
             * so keep waiting. Any other failure is final. */
            if ((code == 401 || code == 407))
            {
                *status = code;
                sip_read_auth_scheme(evt->response, auth_scheme);
                if (!with_auth)
                    done = true;
            }
            else
            {
                *status = code;
                done = true;
            }
        }
        eXosip_event_free(evt);
    }

    sip_down(ctx);
    return 0;
}

/* See description in ta_sip.h */
te_errno
ta_sip_invite(const char *target, const char *from, int transport,
              int timeout_ms, int *status, te_string *server)
{
    struct eXosip_t *ctx = NULL;
    osip_message_t *req = NULL;
    long deadline = sip_now_ms() + timeout_ms;
    bool done = false;
    te_errno rc;

    *status = 0;

    rc = sip_up(&ctx, transport);
    if (rc != 0)
        return rc;

    if (eXosip_call_build_initial_invite(ctx, &req, target, from, NULL,
                                         "tsf-sip probe") != 0 || req == NULL)
    {
        sip_down(ctx);
        return TE_RC(TE_TA_UNIX, TE_EINVAL);
    }
    eXosip_lock(ctx);
    eXosip_call_send_initial_invite(ctx, req);
    eXosip_unlock(ctx);

    while (!done)
    {
        long remain = deadline - sip_now_ms();
        eXosip_event_t *evt;

        if (remain <= 0)
            break;
        evt = eXosip_event_wait(ctx, (int)(remain / 1000),
                                (int)(remain % 1000));
        eXosip_lock(ctx);
        eXosip_automatic_action(ctx);
        eXosip_unlock(ctx);
        if (evt == NULL)
            continue;

        if (evt->response != NULL &&
            (evt->type == EXOSIP_CALL_RINGING ||
             evt->type == EXOSIP_CALL_ANSWERED ||
             evt->type == EXOSIP_CALL_REQUESTFAILURE ||
             evt->type == EXOSIP_CALL_SERVERFAILURE ||
             evt->type == EXOSIP_CALL_GLOBALFAILURE))
        {
            *status = osip_message_get_status_code(evt->response);
            sip_read_headers(evt->response, server, NULL, NULL);
            done = true;
        }

        /* Never leave a call hanging: cancel/bye whatever we started. */
        if (evt->cid > 0)
        {
            eXosip_lock(ctx);
            eXosip_call_terminate(ctx, evt->cid, evt->did);
            eXosip_unlock(ctx);
        }
        eXosip_event_free(evt);
    }

    sip_down(ctx);
    return 0;
}
