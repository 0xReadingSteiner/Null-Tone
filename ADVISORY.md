# Null;Tone — The Silent Edge: Pre-Authentication Full-Appliance XMPP Saturation and Component-Bus Takeover on Cisco Expressway (Both C and E)

## 1. Advisory Information

- **Advisory ID:** SKYLINE-2026-010 (chain; components 010–011)
- **Drop Name:** Null;Tone
- **Title:** Pre-authentication availability kill chain on the Expressway XCP component bus — unbounded-depth XML parse saturation (Θ(n²), no operator limit) plus component-name squatting, on an externally bound port that none of the appliance's own intrusion-prevention jails watch
- **Components:**
  - Squathack (SKYLINE-2026-010) — pre-auth component-name squatting on :7400 (name claim without authentication; rivals receive `<conflict/>`)
  - Burnhack (SKYLINE-2026-011) — pre-auth unbounded-depth parse-compute saturation (Θ(n²) `_setDirty` ancestor walk; accept-side limits hardcoded 0/0)
- **CVSSv3.1 (chain, composed):** 8.2 (High) — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H` (I:L = registration-blocking via Squathack)
- **CVSSv3.1 (Burnhack standalone):** 7.5 (High) — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **CWE:** CWE-400 (Uncontrolled Resource Consumption), CWE-407 (Inefficient Algorithmic Complexity), CWE-306 (Missing Authentication for Critical Function)
- **Affected Products:**
  - Cisco Expressway-E X15.5.1 (jabberd/XCP router, `/opt/jabber/xcp/bin/jabberd`, component-accept listener :7400)
  - Cisco Expressway-C X15.5.1 (same XCP stack; :7400 externally bound in lab observation on C as well)
  - Earlier X14.x lines share the XCP lineage; not tested — treat as potentially affected until vendor states otherwise
- **Vendor:** Cisco Systems, Inc.
- **Vendor Coordination:** Cisco PSIRT unresponsive since 2026-08-04 despite multiple submissions across channels (see §9)
- **Researcher:** 0xReadingSteiner (0xReadingSteiner@proton.me · PGP D5E22255F645A8B935056C278C0958C5D533080A)

---

## 2. Executive Summary

Every Cisco Expressway appliance runs an XMPP Component-Accept (XEP-114) listener — the internal XCP component bus — on TCP :7400, bound to the appliance's external interface(s) with **no authentication required to open a stream** and **no parser depth limit an operator can set** (the accept-side limits are hardcoded `0/0` in the shipped binary). Two composable pre-authentication defects turn that port into a full-appliance availability kill switch:

1. **Burnhack** — a single TCP connection carrying a 175 KB deeply nested XML document (depth 25,000) consumes seconds-to-minutes of CPU because the XML node implementation walks the *entire ancestor chain on every append* (`judo::Node::_setDirty`, Θ(n²); measured 91.5% of burn CPU inside that one function). Seven concurrent connections — one per distinct stream name — saturate **both** vCPUs of the standard 2-core appliance. New streams (including legitimate internal component reconnects and all XMPP/MRA routing serviced by the same daemon) degrade 100–1000×, from ~0.01 s to 12–18 s per handshake, with observed 30 s+ timeouts. The attacker's cost to *sustain* saturation indefinitely is approximately **10 KB/s**.
2. **Squathack** — any idle, header-only stream claims its `to=` name in the router's name table with zero credentials. Rival handshakes for the claimed name receive `<conflict/>` instantly. Legitimate components cannot (re)register while the attacker holds their names; the claim releases only when the attacker's stream ends.

Neither defect is visible to the appliance's own defenses: an iptables/fail2ban census on both boxes shows jails covering :22, :80/:443, :5060–5062, :5222, :8443 and :2222 — **no jail of any kind watches :7400**. There is no rate limiting on stream opens, no depth knob, and no alarm. Recovery is clean and immediate when the attacker stops (verified: daemon pid continuous, no restart, no crash, kernel log clean).

Both defects were verified live on **two real production-version appliances** (Expressway-C and Expressway-E, X15.5.1, 2 vCPU / 4 GB each) with single bracketed volleys under controlled conditions, after extended clone-based characterization (§5). To our knowledge the unregistered-name acceptance behavior means the attacker needs **no knowledge of the deployment's component registry**: in live pre-flight, 10/10 arbitrary stream names were accepted pre-handshake on both boxes.

---

## 3. Impact

### What an attacker can DO

- **Mute the collaboration edge.** One host with TCP reach to :7400 degrades *all* XMPP-dependent services on the appliance — MRA routing, IM & presence federation paths, internal component traffic — for as long as it keeps ~10 KB/s flowing. On the Expressway-E of an MRA deployment, that is every remote worker's Jabber/softphone messaging path through that edge. On Expressway-C, the internal bus itself.
- **Choose the duration.** Single volleys last as long as the attacker's streams take to drain (45–240 s observed depending on host load). Drain-driven re-firing (re-open the instant the previous stream EOFs) sustains saturation indefinitely — demonstrated for 678 s continuous on a production-equivalent clone at ~98.5% on both cores, with service state never recovering while the loop ran.
- **Block legitimate re-registration.** Holding the registered component names (Squathack) means that even a service restart window does not restore the bus: internal components attempting to reconnect during the claim receive `<conflict/>`.
- **Stay invisible.** No fail2ban jail covers :7400 on either box; no rate limit; the traffic is well-formed XMPP to a legitimate service port. The only reliable detection signal is CPU: the jabberd process's user-time ticks climbing ~90–220 CPU-seconds per volley while connection counts stay trivial.

---

## 4. Technical Details

### 4.0 Architecture background

Expressway appliances embed an XMPP-based internal messaging fabric (XCP): a `jabberd` router process plus components (session manager, connection managers, SDNS, logging, etc.). Components connect to the router over the **Jabber Component Protocol (XEP-114)** on TCP :7400: the component opens an XML stream (`<stream:stream xmlns='jabber:component:accept' to='NAME'>`), the router replies with a stream header carrying a session id, and the component authenticates with `<handshake>sha1(id + shared secret)</handshake>`. In X15.5.1 the shipped components are in-process `.so` modules of the single XCP process — the TCP listener nonetheless remains open and externally bound, a legacy of the multi-process architecture.

Critically, **stream parsing happens before any authentication**: the accept-side connection object decodes and builds the XML tree of whatever arrives pre-handshake. The accept-side configuration decoded from the shipped binary shows element-count and depth limits of `0/0` — unlimited — with no configuration surface exposing them.

### 4.1 Squathack — pre-auth name claim (SKYLINE-2026-010)

Opening a stream with `to=NAME` claims NAME in the router's name table for the lifetime of the connection. No credential is requested or checked before the claim. A second stream presenting the same name receives:

```xml
<stream:error><conflict xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text ...>... conflicting component id</text></stream:error>
```

Live pre-flight on both production-version appliances accepted **10/10 arbitrary names**, including names absent from the appliance's own component registry — unregistered `to=` values still open a stream pre-handshake (the router's dynamic component auto-registration path evaluates them). Consequences: (a) the attacker does not need to enumerate or know the registry; (b) claims on *registered* names block the corresponding legitimate components across reconnect/restart windows; (c) the conflict replies double as a free liveness oracle for the saturation phase (§4.2 probes).

### 4.2 Burnhack — Θ(n²) parse saturation (SKYLINE-2026-011)

Payload per connection (175 KB):

```xml
<stream:stream xmlns='jabber:component:accept' to='DISTINCT-NAME'>   <!-- header -->
<a><a><a>... 25,000 deep ...</a></a></a></stream:stream>
```

Root cause (measured with `perf` on the production binary): `judo::Node::_setDirty` — invoked from `appendChild` on every node insertion — walks the **full ancestor chain** to propagate the dirty flag, with no already-dirty early-exit. Building a depth-n tree therefore costs Θ(n²): solo, one 175 KB stream ≈ 3.3 CPU-seconds; 350 KB ≈ 23.6 s (superlinear exponent measured ~n^2.4–3 across the size range).

Concurrency amplification: 7 simultaneous streams (the appliance's XCP mio thread count is 7) on 7 distinct names produced **440 CPU-seconds for a 231 s wall window** on a 2-vCPU clone under background load — a 19× super-additive effect vs. the 23 s solo-sum, attributed (perf-confirmed) to two layers: shared L3/DRAM cache contention across the seven tree-builds (IPC collapse 0.173 → 0.071–0.103, cache miss-rate 5% → 22–37%) and 2-vCPU oversubscription. Both layers apply to the standard production appliance shape (2 cores).

Service impact during burn: new-stream handshake RTT — baseline 0.00–0.03 s — degrades to 0.4–18 s with 30 s+ timeouts observed; all 7 bomb streams are processed (no resets) and drain in 45–240 s depending on host load; recovery to baseline is immediate on drain completion.

### 4.3 Defense-blindness census

fail2ban/iptables state read as root on both appliances post-fire: jails exist for SSH (22, 2222), HTTP/HTTPS (80, 443, 8443 — auth and intrusion classes), SIP (5060–5062), and XMPP **client** port (5222 `XMPP_Intrude`). **:7400 appears in no jail, no rate-limit, and no alarm path.** Every volley in this research left zero bans and zero filter ticks.

---

## 5. Proof of Concept

Full harness: `poc.sh` (this drop). Requirements: python3 on the attacking host, TCP reach to the target's :7400. The script is measurement-first: baseline RTT probes → single-volley saturation → per-30 s RTT probes → recovery confirmation → summary. It opens attacker-side sockets only and leaves **zero state** on the target (verified in lab: daemon pid continuous, zero established connections after drain, kernel log clean).

```
./poc.sh <expressway-host> [port=7400]        # full 7-connection volley (impactful — lab/authorized only)
./poc.sh <expressway-host> 7400 --solo        # single stream, depth 10000 — shows superlinear CPU cost
                                            # (~1 s class) without saturating; safest verifier
```

Expected output (lab measurements, real X15.5.1 appliances, 2 vCPU/4 GB):

1. `baseline probe: 0.00-0.03s` (×2, bad-handshake error response — the RTT oracle)
2. `preflight: N/7 names accepted` (stream headers returned; `<conflict/>` only if a name is already claimed)
3. During volley: `probe@+3s: 2.9-5.0s`, `probe@+7s: 12.6s`, `probe@+9s: 18.2s` — conflict-content responses (Squathack riding on the bomb streams)
4. Bomb walls: `45-65s` per stream (idle host) — all 7 processed
5. `RECOVERY: 2 consecutive baseline probes` within ~60 s of drain end; recovery tail 0.00–0.01 s

Live-fire verification record (2026-10-05, both real appliances, single bracketed volley each): Expressway-E — ΔCPU +218.6 CPU-s (both cores ~90% through a 121 s degradation window), peak probe 18.18 s, recovery t=121 s. Expressway-C — ΔCPU +92 CPU-s (both cores ~98% across a 47 s drain), peak probe 13.09 s, recovery t=91 s. Indefinite sustained variant (drain-driven re-fire, 7 persistent workers): clone-verified 678 s continuous at ~98.5% both cores, probes never returning to baseline while the loop ran, service state unrecovered until attacker stop.

---

## 6. Root Cause Analysis

Three design assumptions failed together:

1. **"The component bus is internal."** :7400 is a legacy of the multi-process XCP architecture; in X15.5.1 all components are in-process modules, yet the listener remains externally bound with pre-auth stream parsing enabled. The port is pure attack surface with zero functional consumers in the shipped topology.
2. **"XML from components is trusted."** The accept-side parser enforces no depth/size limits (hardcoded 0/0) because components were assumed benign. Pre-handshake, the peer is by definition *not* authenticated — the trust assumption is inverted.
3. **"Dirty-flag propagation is cheap."** `_setDirty` re-walks the ancestor chain on every append without an already-dirty early-exit — an O(1)-with-memoization operation implemented as O(depth), turning attacker-chosen depth into quadratic CPU.

---

## 7. Affected Components

| Product | Version | Component | Status |
|---|---|---|---|
| Cisco Expressway-E | X15.5.1 | jabberd/XCP :7400 component-accept (libjcore `judo::Node`, MultiComponent accept path) | Vulnerable — live-verified |
| Cisco Expressway-C | X15.5.1 | same stack | Vulnerable — live-verified |
| Cisco Expressway / VCS | X14.x and earlier | same XCP lineage | Untested — potentially affected |

---

## 8. Remediation

**Defenders, now (no vendor patch required):**
1. **Filter TCP :7400 at every perimeter and host segment.** No supported Expressway feature requires inbound :7400 from other than the appliance itself (components are in-process in X15.5.1). Deny all sources; if any legacy federation truly uses it, allowlist only specific peer IPs.
2. **Monitor the burn signature:** alert on jabberd process CPU (user ticks) climbing tens of CPU-seconds per minute while :7400 connection counts stay single-digit — the chain's only reliable telemetry. Baseline RTT probes of the port from your monitoring can also detect the 100× degradation directly.
3. Audit for existing exposure: `ss -ltn '( sport = :7400 )'` on each appliance — if the local address is not 127.0.0.1, the port is reachable from whatever segments can route to that interface.

**Vendor fix:** early-exit in `_setDirty` when the ancestor is already dirty (restores O(1) amortized append); enforce sane accept-side depth/element limits with an operator-visible knob; bind :7400 to loopback by default given in-process components; extend the intrusion-prevention jail set to the component port.

---

## 9. Vendor Coordination Timeline

| Date | Action |
|---|---|
| 2026-08-04 | Cisco PSIRT contacted (psirt@cisco.com) regarding CUCM pre-auth root chain; no response to date |
| 2026-08-10 | Cisco PSIRT notified of Expressway findings (Blind;Wire); no response to date |
| 2026-08 → 09 | 17 submissions to ZDI (coordinates with Cisco on researcher's behalf); unprocessed |
| 2026-09 | SSD paused CUCM acquisitions pending Cisco's queue |
| 2026-10-05 | Null;Tone components (SKYLINE-2026-010/011) — notification queued to PSIRT + MITRE CVE request (CNA of Last Resort) at publication |

---

## 10. Disclosure Statement

Independent research conducted on legally owned lab appliances running production-version software. No proprietary access, no customer systems, no traffic interception. Live verification on physical lab units was performed under controlled, bracketed conditions with full pre/post state attestation (process continuity, kernel log, connection table, intrusion-prevention state) and immediate recovery confirmation; sustained-indefinite variants were restricted to isolated clones. Coordination attempted through every available channel before publication (§9). All findings reported at measured strength; verification methodology and live-fire records are published in §5.

## 11. References

- XEP-114: Jabber Component Protocol — https://xmpp.org/extensions/xep-0114.html
- CWE-400 — https://cwe.mitre.org/data/definitions/400.html · CWE-407 — https://cwe.mitre.org/data/definitions/407.html · CWE-306 — https://cwe.mitre.org/data/definitions/306.html
- Cisco advisory precedent (Expressway pre-auth DoS scoring): cisco-sa-expressway-vcs-dos-n6xxTMZB (CVSS 5.9)
- Cisco advisory precedent (XMPP/jabberd parser DoS): Cisco-SA-20130416-CVE-2013-1197 (CVSS 6.8)
- Prior drops in this series: Silent;Call (CUCM pre-auth root), Blind;Wire (Expressway SIP smuggling), Dead;Dial (CUCM WebDialer RCE), False;Relay (MRA corridor, CVSS 10.0 composed)
