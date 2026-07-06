# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved.
#
# External TE library (see TE_EXT_REPO): agent-side SIP probing over
# libeXosip2 (on top of libosip2). Signalling only, no media. The agent
# and its RPC server both link it.

headers += files(
    'ta_sip.h',
)

sources += files(
    'ta_sip.c',
)

te_libs += [
    'logger_core',
    'tools',
]

# eXosip2 ships no pkg-config on many distributions, so find the three
# libraries (the eXosip stack plus the osip2 parser and base) directly.
cc = meson.get_compiler('c')

exosip_dep = dependency('libexosip2', required: false)
if exosip_dep.found()
    deps += [ exosip_dep ]
else
    deps += [
        cc.find_library('eXosip2', has_headers: 'eXosip2/eXosip.h'),
        cc.find_library('osip2'),
        cc.find_library('osipparser2'),
    ]
endif
