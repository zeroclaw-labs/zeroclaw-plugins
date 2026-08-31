#!/usr/bin/env bash
# Live judge demo for solana-tx-guard.
#   1. Pure decode + classification tests (offline, deterministic).
#   2. Build two REAL transactions, simulate each LIVE against mainnet, and show
#      the guard's verdict — a safe SOL transfer vs a dangerous SetAuthority.
#
# This is the capability the whole field lacks: judging a transaction BEFORE it
# is signed, with the real on-chain simulation of what it would do.
set -euo pipefail
trap '' PIPE
cd "$(dirname "$0")"

RPC="${1:-https://api.mainnet-beta.solana.com}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

echo "== 1. decode + classification tests (offline) =="
cargo test --quiet 2>&1 | grep -E "^test result" | head -1
cargo build --release --quiet --example guard_file

# Build two real legacy transactions (Python — byte-accurate wire format).
python3 - "$TMP" <<'PY'
import base64, struct, sys, json, urllib.request
RPC="https://api.mainnet-beta.solana.com"
A="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58(s):
    n=0
    for c in s: n=n*58+A.index(c)
    b=n.to_bytes((n.bit_length()+7)//8,"big"); pad=len(s)-len(s.lstrip("1"))
    return b"\x00"*pad+b
def sv(n):
    o=bytearray()
    while True:
        e=n&0x7f; n>>=7
        o.append(e|0x80 if n else e)
        if not n: break
    return bytes(o)
def rpc(m,p):
    r=urllib.request.Request(RPC,data=json.dumps({"jsonrpc":"2.0","id":1,"method":m,"params":p}).encode(),headers={"Content-Type":"application/json"})
    return json.load(urllib.request.urlopen(r,timeout=15))
WALLET=b58("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM")
DEST  =b58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
SYS   =b"\x00"*32
TOKEN =b58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
bh=b58(rpc("getLatestBlockhash",[{"commitment":"finalized"}])["result"]["value"]["blockhash"])
def tx(keys,ixs):
    m=bytes([1,0,1])+sv(len(keys))+b"".join(keys)+bh+sv(len(ixs))
    for prog,acc,data in ixs:
        m+=bytes([prog])+sv(len(acc))+bytes(acc)+sv(len(data))+data
    return base64.b64encode(sv(1)+b"\x00"*64+m).decode()
# safe: System transfer
safe=tx([WALLET,DEST,SYS],[(2,[0,1],struct.pack("<IQ",2,1000000))])
# dangerous: SPL Token SetAuthority (tag 6)
danger=tx([WALLET,DEST,TOKEN],[(2,[1,0],bytes([6,0]))])
for name,t in [("safe",safe),("danger",danger)]:
    open(f"{sys.argv[1]}/{name}.b64","w").write(t)
    sim=rpc("simulateTransaction",[t,{"sigVerify":False,"replaceRecentBlockhash":True,"encoding":"base64"}])
    open(f"{sys.argv[1]}/{name}.sim.json","w").write(json.dumps(sim))
print("built + simulated 2 real transactions")
PY

for name in safe danger; do
  echo
  echo "== 2. LIVE guard: $name transaction =="
  cargo run --release --quiet --example guard_file -- "$(cat "$TMP/$name.b64")" "$TMP/$name.sim.json" \
    | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('  verdict     :', d['verdict'], '(static score', str(d['static_risk_score'])+')')
print('  summary     :', d['summary'])
for f in d['findings']: print('   •', f['severity'].upper(), f['program_name'], f['instruction'], '—', f['detail'][:70])
sim=d.get('simulation') or {}
print('  live sim err:', json.dumps(sim.get('err')), '| units:', sim.get('units_consumed'))
"
done
echo
echo "Guarded two real transactions against live mainnet. Signs nothing, sends nothing."
