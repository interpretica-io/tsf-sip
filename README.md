# tsf-sip

SIP (VoIP) probing from a Test Agent, packaged as an external Test
Environment (TE) repository (consumed with the `TE_EXT_REPO` builder
directive). It drives SIP from the agent over a low-level C library —
**libeXosip2 on top of libosip2, no Python, nothing spawned** — for
both quality verification and security assessment.

Three libraries:

- `ta_sip` — agent side. A SIP client over **libeXosip2** (`-leXosip2
  -losip2 -losipparser2`): an OPTIONS ping, a REGISTER (authenticated,
  or anonymous to see whether the registrar binds it), and a bare
  INVITE that is cancelled the moment it is answered. **Signalling
  only — no RTP/media.** The agent and its RPC server both link it.
- `rpcs_sip` — the `sip_*` RPCs for the agent's RPC server, thin
  wrappers over `ta_sip`. The signalling originates on the agent, where
  the UA/PBX is reachable, not on the engine.
- `tapi_sip` — engine side. `tapi_sip.h` gives a test the three probes
  into a `tapi_sip_probe` (status, `Server`/`User-Agent`/`Allow`,
  whether a REGISTER was accepted, the challenged auth scheme);
  `tapi_sip_audit.h` reads an endpoint as a security posture through
  tsf-cybersec; `tapi_sip_rpc.h` is the one-per-RPC layer beneath.

TE has no SIP client of its own.

## What it does

```c
tapi_sip_probe probe;

CHECK_RC(tapi_sip_options(rpcs, "sip:pbx.example", "sip:probe@example",
                          TAPI_SIP_UDP, 5000, &probe));
if (probe.status == 0)
    TEST_SKIP("No SIP UA answered");
RING("SIP %d, server=%s allow=%s", probe.status,
     probe.server ? probe.server : "?", probe.allow ? probe.allow : "?");
tapi_sip_probe_free(&probe);
```

- **OPTIONS** — is it a SIP UA, and what does it admit about itself
  (`Server`, `User-Agent`, `Allow`).
- **REGISTER** — with a username/password the digest challenge is
  answered automatically; without, the binding is attempted anonymously
  and `reg_accepted` tells you whether the registrar took it (it should
  not). A 401/407 hands back the challenged scheme.
- **INVITE** — reaches the first response (100/180/200/4xx) and then
  terminates the dialog, so no call is established — a behaviour probe,
  not a call.

## The library is linked, not a program

`ta_sip` does not run a softphone or `sipsak`. It links libeXosip2 and
drives it in the agent's RPC server process: it builds each request with
`eXosip_*_build_*`, sends it under the eXosip lock, pumps
`eXosip_event_wait()` to the first final response, and reads the status
and headers out of the `osip_message_t` — libosip2's own parsed object.

## Security posture

`tapi_sip_audit()` reads an endpoint and reports through tsf-cybersec:

| Finding | Severity | Raised when |
|---|---|---|
| `sip.responds` | info | the endpoint answers OPTIONS |
| `sip.options-leak` | low | OPTIONS reveals a `Server`/`User-Agent` banner |
| `sip.registration-unauthenticated` | high | an anonymous REGISTER is accepted |
| `sip.user-enumeration` | medium | an existing vs a made-up AoR answer with different status codes |
| `sip.not-assessed` | info | nothing answered |

The subject of a finding is the target URI (stable between runs).

## Authorized use only

The REGISTER and INVITE probes send real requests to a real UA/PBX, and
the anonymous-REGISTER and user-enumeration checks only run when
`attempt_register` is set in the policy. Point tsf-sip only at a device
or PBX you own or are engaged to test — a pilot, a CTF, an authorized
assessment.

## Agent host requirements

- **libeXosip2** with its development headers (Debian: `apt install
  libexosip2-dev`, which pulls libosip2); built and checked against
  eXosip2 **5.3**. The eXosip2 5.x API is what is used here.

## Usage

Declare the repository in an external libraries catalog and pass it to
`dispatcher.sh --external=<catalog.yml>`:

```yaml
repositories:
  - name: tsf_sip
    url: https://github.com/interpretica-io/tsf-sip.git
    ref: <tag>
    libs:
      - ta_sip
      - rpcs_sip
      - tapi_sip
```

In `builder.conf`, bind `tapi_sip` to the engine, list `ta_sip` and
`rpcs_sip` among the RPC server's libraries, and add the RPC definitions
to both platforms:

```
TE_EXT_REPO_USE([tsf_sip], [ta_sip rpcs_sip], [tapi_sip])

TE_LIB_PARMS([rpcxdr], [${TE_HOST}], [],
             [--with-rpcdefs=tarpc_job.x.m4,../ta_sip/sip_rpc.x.m4])
TE_LIB_PARMS([rpcxdr], [${TE_TA_TYPE}], [],
             [--with-rpcdefs=tarpc_job.x.m4,../ta_sip/sip_rpc.x.m4])
```

`tapi_sip_audit` reports through tsf-cybersec, so that repository (and
its prerequisites tsf-kernel and tsf-devtool) must be built too. The
RPC program number is **32** (20–31 are taken by the other tsf agent
RPCs); change it in `sip_rpc.x.m4` if it ever collides.

## What was verified, and what was not

**The eXosip2/libosip2 usage was checked against the real library.**
Every eXosip2 and osip2 call, struct field and event enum `ta_sip.c`
uses — `eXosip_malloc`/`init`/`listen_addr`/`quit`, the OPTIONS /
REGISTER / INVITE build+send calls, `eXosip_event_wait`,
`eXosip_automatic_action`, `eXosip_add_authentication_info`,
`eXosip_call_terminate`, `osip_message_get_status_code`,
`osip_message_get_server`/`user_agent`/`allow` (the Allow header is an
`osip_allow_t` whose value is `->value`),
`osip_message_get_www_authenticate` / `osip_message_get_proxy_authenticate`
and their `get_auth_type`, and the `EXOSIP_*` event constants — was
compiled with `-fsyntax-only` against the installed libeXosip2 **5.3.0**
headers and type-checks.

**Not verified:** the TE engine-side C was not compiled (no TE
toolchain here), no live SIP request was made (no UA/PBX to answer), and
the RPC marshalling and the user-enumeration heuristic were not
exercised against a real registrar. The first suite to point tsf-sip at
a real endpoint should expect to adjust a timeout or a status-code
expectation.

## Scope

- **Signalling only.** tsf-sip sets up no media; it does not place a
  call, only reaches the first response and tears the dialog down.
- **Posture is about exposure, not a break-in.** The checks observe how
  an endpoint answers; the anonymous-REGISTER check tries a binding (and
  is gated), but nothing here brute-forces a credential or places a
  fraudulent call.
