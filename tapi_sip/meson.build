# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved.
#
# External TE library (see TE_EXT_REPO): engine-side TAPI for SIP
# probing on agents, and a security posture over it. Built as a shared
# library on the engine platform. It needs the sip_* RPCs in rpcxdr, so
# add ../ta_sip/sip_rpc.x.m4 to the rpcxdr definitions of the engine
# platform. The posture (tapi_sip_audit) reports through tsf-cybersec,
# so that repository is required too.

if get_option('engine')
    build_lib_shared = true
endif
build_lib_static = not get_option('engine')
install_lib = install_dev

headers += files(
    'tapi_sip.h',
    'tapi_sip_rpc.h',
    'tapi_sip_audit.h',
)

sources += files(
    'tapi_sip.c',
    'tapi_sip_rpc.c',
    'tapi_sip_audit.c',
)

te_libs += [
    'tapi',
    'tapi_rpc',
    'rcfrpc',
    'confapi',
    'rcfapi',
    'rpcxdr',
    'tapi_cybersec',
    'logger_core',
    'tools',
]
