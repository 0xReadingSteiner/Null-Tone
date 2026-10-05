# Null;Tone — Mitigations for Defenders (SKYLINE-2026-010/011)

No vendor patch exists at publication. All measures below are deployable today.

## 1. Filter TCP :7400 (the single highest-value action)

The XCP component bus has **no legitimate external consumers** in X15.5.1 — shipped
components are in-process modules of the single XCP process. Deny :7400 from every
source except the appliance itself:

- **Perimeter/segment firewalls & ACLs:** drop TCP 7400 to all Expressway-C and
  Expressway-E management/LAN interfaces. This alone kills the remote chain entirely.
- **Audit current exposure** on each appliance (root shell):
  ```sh
  ss -ltn '( sport = :7400 )'
  ```
  A local address other than `127.0.0.1` means the port answers on that interface.
- **Product-side bind change:** not exposed as a supported knob in this release. A bind
  change in the XCP configuration is technically possible but unsupported territory —
  validate in a lab first; prefer upstream filtering for production.

## 2. Detection (the chain is invisible to the appliance's own IPS)

No fail2ban jail covers :7400 (jails watch 22, 80/443, 5060–5062, 5222, 8443, 2222).
Detect from outside:

- **CPU-burn signature:** jabberd process user-time climbing tens of CPU-seconds per
  minute while its :7400 connection count stays single-digit. SNMP/host monitoring on
  the appliance process table catches this directly.
- **Active RTT baseline:** probe :7400 handshake RTT from your monitoring (expected
  0.00–0.05 s healthy). Sustained >1 s = saturation in progress; `<conflict/>` content
  on names nobody legitimately runs = active squatting.
- **Network telemetry:** ~175 KB inbound bursts on :7400 from a single source, 7
  parallel streams, repeated on EOF = the drain-driven sustained variant.

## 3. Incident response

- The daemon does **not** crash and needs no restart — saturation ends ~60 s after the
  attacker's streams stop/drain. Blocking the source at the firewall restores service
  immediately.
- Post-incident: confirm jabberd pid continuity, zero ESTABLISHED on :7400, clean
  kernel log. If legitimate components were squatted during a restart window, they
  re-register normally once the attacker's claims release.

## 4. What to ask the vendor

- Early-exit memoization in the dirty-flag propagation (`_setDirty`) restoring O(1)
  amortized append.
- Accept-side depth/element limits with an operator-visible configuration knob
  (currently hardcoded 0/0 = unlimited).
- Loopback-default bind for :7400 given in-process components.
- Intrusion-prevention jail coverage for the component port.
