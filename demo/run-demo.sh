#!/usr/bin/env bash
# One command for the whole Solana payment suite: build the three components,
# run every test they have, run the end to end against a local fake, print the
# numbers.
#
#   demo/run-demo.sh                offline. No credentials, no network beyond 127.0.0.1.
#   MAINNET=1 demo/run-demo.sh      also run the read-only mainnet stage (needs internet).
#   OFFLINE=1 demo/run-demo.sh      pass --offline to cargo (warm registry cache only).
#   WRITE_GOLDEN=1 demo/run-demo.sh re-record demo/golden/local-fake.json.
#
# Every number printed below is a number a command in this run produced. Raw
# logs, the staged components, the RPC transcript and the results JSON stay in
# demo/out/ afterwards. Nothing in this rig can sign or send a transaction:
# there is no keypair, no wallet and no private key anywhere in it.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
OUT="$HERE/out"
PLUGINS=(spl-transfer-build payment-watch nonce-status)
START=$SECONDS
FAILURES=0

stage() { printf '\n== %s\n' "$*"; }
fail() {
  FAILURES=$((FAILURES + 1))
  printf '  FAILED: %s\n' "$*"
}
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- stage 0
stage "stage 0: environment"
missing=()
for tool in cargo rustc python3 curl openssl git; do
  have "$tool" || missing+=("$tool")
done
if ((${#missing[@]})); then
  echo "  missing required tools: ${missing[*]}"
  exit 2
fi
printf '  %s\n' "$(rustc --version)" "$(cargo --version)" "$(python3 --version 2>&1)" \
  "$(curl --version | head -1)" "$(openssl version)"

if have rustup; then
  installed=$(rustup target list --installed 2>/dev/null)
else
  installed=$(ls "$(rustc --print sysroot)/lib/rustlib" 2>/dev/null)
fi
if ! grep -qx wasm32-wasip2 <<<"$installed"; then
  echo "  wasm32-wasip2 is not installed. Add it with: rustup target add wasm32-wasip2"
  exit 2
fi
echo "  wasm32-wasip2 target present"
echo "  repo $(git -C "$ROOT" rev-parse --short HEAD) on branch $(git -C "$ROOT" rev-parse --abbrev-ref HEAD)"

# The repo's validator refuses to validate a plugin directory that is not clean,
# because it snapshots the committed tree and diffs it afterwards. Say so here
# rather than letting it fail deep inside a cargo log.
dirty=$(git -C "$ROOT" status --porcelain=v1 --untracked-files=all --ignored=matching \
  -- "${PLUGINS[@]/#/plugins/}" wit/v0)
if [[ -n $dirty ]]; then
  echo "  the plugin directories are not clean, so the CI validator will refuse them:"
  sed 's/^/    /' <<<"$dirty"
  echo "  commit or stash those paths and run again."
  exit 2
fi
echo "  plugin directories and wit/v0 are clean"

CARGO_OFFLINE=""
if [[ ${OFFLINE:-0} == 1 ]]; then
  CARGO_OFFLINE="--offline"
  # The validator builds through its own cargo invocations, which take no flags
  # from here, so the env var is what makes stage 1 offline too.
  export CARGO_NET_OFFLINE=true
  echo "  cargo runs with --offline, so every crate must already be in the local registry cache"
else
  echo "  cargo may fetch crates from crates.io on a cold cache. The demo itself talks to 127.0.0.1 only"
fi

rm -rf "$OUT"
mkdir -p "$OUT"

# ---------------------------------------------------------------- stage 1
stage "stage 1: the repo's own component gates, tools/ci/validate_components.sh"
echo "  per component: cargo test, clippy on the host, clippy on wasm32-wasip2, release wasm build"
# Invoked through bash because the file is committed non-executable, which is how
# .github/workflows/validate.yml runs it as well.
(
  cd "$ROOT" || exit 125
  REPORT_PATH="$OUT/matrix.tsv" \
    LOG_ROOT="$OUT/logs" \
    STAGED_DIR="$OUT/staged" \
    REPORT_STACK=demo \
    CARGO_TARGET_DIR="$ROOT/target-shared" \
    bash tools/ci/validate_components.sh "${PLUGINS[@]}"
) >"$OUT/validate.log" 2>&1 &
validate_pid=$!
# Follow the validator's own progress lines while it runs, so a four-minute
# stage does not look like a hang.
tail_pid=""
(
  sleep 1
  tail -n +1 -f "$OUT/validate.log" 2>/dev/null | grep --line-buffered -E '^(BEGIN|END|error)' | sed 's/^/  /'
) &
tail_pid=$!
wait "$validate_pid"
gate_rc=$?
sleep 1
kill "$tail_pid" 2>/dev/null
wait "$tail_pid" 2>/dev/null
echo "  validator exit code $gate_rc, full log demo/out/validate.log"
[[ $gate_rc -eq 0 ]] || fail "component gates returned $gate_rc"
python3 "$HERE/report.py" gates "$OUT/matrix.tsv" "$OUT/staged" "$OUT/gates.json" \
  || fail "a component did not come back clean"

stage "stage 1b: one shared core, three vendored copies"
python3 "$HERE/report.py" vendored "$ROOT" || fail "the vendored core copies drifted"

# ---------------------------------------------------------------- stage 2
stage "stage 2: build the demo drivers"
echo "  a driver runs one component's real core on the host and prints what it returned"
for d in build watch nonce; do
  if (cd "$HERE/drivers/$d" && cargo build $CARGO_OFFLINE) >"$OUT/driver-$d.log" 2>&1; then
    bin="$HERE/drivers/$d/target/debug/zc-drive-$d"
    printf '  %-6s %s bytes  %s\n' "$d" "$(wc -c <"$bin" | tr -d ' ')" "demo/drivers/$d/target/debug/zc-drive-$d"
  else
    fail "driver $d did not build, see demo/out/driver-$d.log"
  fi
done

# ---------------------------------------------------------------- stage 3
stage "stage 3: end to end against a local fake RPC on 127.0.0.1"
openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes \
  -keyout "$OUT/fake-key.pem" -out "$OUT/fake-cert.pem" \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" \
  >"$OUT/openssl.log" 2>&1 || fail "could not generate the loopback certificate"
echo "  self-signed loopback certificate generated, because the components refuse any rpc_url that is not https"

python3 "$HERE/fake-rpc.py" \
  --cert "$OUT/fake-cert.pem" --key "$OUT/fake-key.pem" \
  --port-file "$OUT/fake.port" --log "$OUT/fake-rpc.jsonl" \
  >"$OUT/fake-rpc.log" 2>&1 &
fake_pid=$!
trap 'kill "$fake_pid" 2>/dev/null' EXIT
for _ in $(seq 1 60); do
  [[ -s "$OUT/fake.port" ]] && break
  sleep 0.2
done
if [[ ! -s "$OUT/fake.port" ]]; then
  fail "the local fake RPC did not start, see demo/out/fake-rpc.log"
else
  port=$(cat "$OUT/fake.port")
  echo "  local fake RPC on https://127.0.0.1:$port (synthetic fixtures, not a cluster)"
  golden_flag=()
  [[ ${WRITE_GOLDEN:-0} == 1 ]] && golden_flag=(--write-golden)
  python3 "$HERE/run-cases.py" \
    --scenarios "$HERE/scenarios/local-fake.json" \
    --drivers-dir "$HERE/drivers" \
    --rpc-url "https://127.0.0.1:$port" \
    --cacert "$OUT/fake-cert.pem" \
    --transcript "$OUT/rpc-transcript.jsonl" \
    --out "$OUT/fake-run.json" \
    --golden "$HERE/golden/local-fake.json" \
    "${golden_flag[@]}" || fail "a scenario did not match what the component should have said"
  kill "$fake_pid" 2>/dev/null
  wait "$fake_pid" 2>/dev/null
  served=$(wc -l <"$OUT/fake-rpc.jsonl" 2>/dev/null | tr -d ' ')
  echo "  the fake answered ${served:-0} JSON-RPC requests, every one logged in demo/out/fake-rpc.jsonl"
  echo "  request and response bodies as the components saw them: demo/out/rpc-transcript.jsonl"
fi

# ---------------------------------------------------------------- stage 4
stage "stage 4: mainnet read path, optional"
if [[ ${MAINNET:-0} == 1 ]]; then
  python3 "$HERE/mainnet-readpath.py" || fail "the mainnet read-path stage did not complete"
else
  echo "  SKIPPED by default. This is the only stage that leaves 127.0.0.1."
  echo "  It reads mainnet through a public RPC and asks mainnet to simulate an unsigned"
  echo "  transaction this build produced. Simulation never broadcasts, so it moves nothing"
  echo "  and needs no key. Run it with: MAINNET=1 demo/run-demo.sh"
  echo "  The last captured run is committed under demo/artifacts/mainnet-readpath/"
fi

# ---------------------------------------------------------------- stage 5
stage "stage 5: every claim re-derived from the bytes this run staged"
echo "  each check reads a staged artifact or a manifest and exits nonzero if a"
echo "  property does not hold, so none of it asks to be believed"
if bash "$HERE/verify-all.sh" -q >"$OUT/verify-all.log" 2>&1; then
  grep -E '  (pass|FAIL)$|checks pass' "$OUT/verify-all.log" | sed 's/^/  /'
else
  sed 's/^/  /' <"$OUT/verify-all.log" | tail -12
  fail "a claim did not hold, see demo/out/verify-all.log"
fi
echo
echo "  and every one of those checks can be made to fail on purpose:"
if python3 "$HERE/prove-teeth.py" -q >"$OUT/prove-teeth.log" 2>&1; then
  grep -E 'controls provoked' "$OUT/prove-teeth.log" | sed 's/^/  /'
else
  tail -12 "$OUT/prove-teeth.log" | sed 's/^/  /'
  fail "a negative control left its check green, see demo/out/prove-teeth.log"
fi

# ---------------------------------------------------------------- verdict
stage "verdict"
python3 - "$OUT/gates.json" "$OUT/fake-run.json" <<'PY'
import json, sys
gates = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else {}
try:
    cases = json.load(open(sys.argv[2]))
except (OSError, ValueError):
    cases = {}
comps = gates.get("components", {})
for name, c in sorted(comps.items()):
    print(f"  {name} {c['version']}: {c['tests_passed']} tests passed, "
          f"{c['tests_failed']} failed, wasm {c['wasm_bytes']:,} bytes")
print(f"  totals: {gates.get('totals', {}).get('components', 0)} components, "
      f"{gates.get('totals', {}).get('tests_passed', 0)} tests passed")
built = [k for k, v in cases.items() if "tx_bytes" in v]
refused = [k for k, v in cases.items() if not v["ok"]]
no_network = [k for k, v in cases.items() if not v["ok"] and v["rpc_calls"] == 0]
print(f"  scenarios: {len(cases)} run, {len(built)} unsigned transactions built, "
      f"{len(refused)} refusals, {len(no_network)} of those refused before any RPC call")
for k in sorted(built):
    print(f"    {k}: {cases[k]['tx_bytes']} bytes, sha256 {cases[k]['tx_sha256']}")
PY
elapsed=$((SECONDS - START))
echo "  wall clock ${elapsed}s"
echo
echo "  What this run proves: the three components build for wasm32-wasip2, their own"
echo "  test suites pass, the shared core has not drifted, and each component behaves"
echo "  correctly end to end against a live https endpoint, including refusing what it"
echo "  should refuse before it touches the network."
echo "  What it does not prove: stage 3 data is a local fake, so no on-chain state is"
echo "  involved and nothing here was signed, broadcast or paid. Mainnet evidence lives"
echo "  in stage 4 and in demo/artifacts/mainnet-readpath/."
if ((FAILURES)); then
  echo
  echo "  RESULT: $FAILURES stage(s) failed. Read demo/out/ for the raw logs."
  exit 1
fi
echo
echo "  RESULT: green, $((SECONDS - START))s, every number above came from this run."
