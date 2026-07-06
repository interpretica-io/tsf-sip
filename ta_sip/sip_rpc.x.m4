/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief RPC for SIP probing
 *
 * The RPCs of rpcs_sip, a thin layer over ta_sip, which probes a SIP UA
 * or proxy in the RPC server process over libeXosip2. Add this file to
 * the rpcxdr definitions of the engine platform and of the agent
 * platform:
 *
 *   TE_LIB_PARMS([rpcxdr], [<platform>], [],
 *                [--with-rpcdefs=tarpc_job.x.m4,../ta_sip/sip_rpc.x.m4])
 *
 * No state survives between calls: each probe is one request and its
 * first final response. A status of 0 means nothing answered in time.
 */

/* sip_options(): OPTIONS ping; the response's stack headers come back. */
struct tarpc_sip_options_in {
    struct tarpc_in_arg common;

    string          target<>;
    string          from<>;
    tarpc_int       transport;      /* 0 = UDP, 1 = TCP */
    tarpc_int       timeout_ms;
};

struct tarpc_sip_options_out {
    struct tarpc_out_arg common;

    tarpc_int       retval;
    tarpc_int       status;         /* SIP status code, or 0 if no answer */
    string          server<>;
    string          user_agent<>;
    string          allow<>;
};

/*
 * sip_register(): REGISTER. With username+password the challenge is
 * answered automatically; with them empty the binding is attempted
 * anonymously and accepted tells whether it went through.
 */
struct tarpc_sip_register_in {
    struct tarpc_in_arg common;

    string          registrar<>;
    string          aor<>;
    string          contact<>;
    string          username<>;
    string          password<>;
    tarpc_int       expires;
    tarpc_int       transport;
    tarpc_int       timeout_ms;
};

struct tarpc_sip_register_out {
    struct tarpc_out_arg common;

    tarpc_int       retval;
    tarpc_int       status;
    tarpc_bool      accepted;
    string          auth_scheme<>;
};

/* sip_invite(): a bare INVITE, torn down as soon as it is answered. */
struct tarpc_sip_invite_in {
    struct tarpc_in_arg common;

    string          target<>;
    string          from<>;
    tarpc_int       transport;
    tarpc_int       timeout_ms;
};

struct tarpc_sip_invite_out {
    struct tarpc_out_arg common;

    tarpc_int       retval;
    tarpc_int       status;
    string          server<>;
};

program sip
{
    version ver0
    {
        RPC_DEF(sip_options)
        RPC_DEF(sip_register)
        RPC_DEF(sip_invite)
    } = 1;
} = 32;
