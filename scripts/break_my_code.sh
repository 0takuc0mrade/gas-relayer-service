#!/usr/bin/env bash
# Part 4 of the Day 4 lab: "Break My Code".
#
# Runs the whole adversarial suite against a running relayer and prints the scoreboard.
# Defender wins when every attack is refused and the honest traffic in the same run is not.
#
#   ./scripts/break_my_code.sh            # attacks only
#   ./scripts/break_my_code.sh --grief    # also installs a REVERT-ing forwarder with anvil_setCode
#
# Preconditions: anvil on 127.0.0.1:8545, the relayer on 127.0.0.1:3000.
set -uo pipefail

RPC=${RPC_URL:-http://127.0.0.1:8545}
FORWARDER=${FORWARDER_ADDRESS:-0x0000000000000000000000000000000000000000}
SIM=./target/debug/simulator

if [[ ! -x $SIM ]]; then
  echo "building..."
  cargo build --all-targets || exit 1
fi

# Fail loudly if the relayer is not up: a suite that silently scores "0 attacks accepted"
# because nothing answered would be worse than useless.
if [[ "$(curl -s -o /dev/null -w '%{http_code}' 127.0.0.1:3000/health)" != "200" ]]; then
  echo "no relayer on 127.0.0.1:3000 -- start it first:  cargo run" >&2
  exit 1
fi

block() { cast block-number --rpc-url "$RPC"; }
metrics() { curl -s 127.0.0.1:3000/metrics | grep -E '^relayer_(gas_burned|transactions_total\{status="dispatched)' ; }
run() {
  echo
  echo "=== $1 $2 ==="
  $SIM "$1" "$2" 2>&1 | sed -n '/━━━/,$p' | grep -vE 'scoreboard|chain check'
  settle
}

# The relayer is asynchronous: `202 Accepted` means *queued*, not *done*. Before the next phase
# touches on-chain state (installing the reverting forwarder, most importantly) the worker must
# have drained, or the last-chance re-simulation will -- correctly -- refuse the remainder.
settle() {
  for _ in $(seq 1 100); do
    local queued
    queued=$(curl -s 127.0.0.1:3000/metrics | awk '/^relayer_queue_len/ {print $2}')
    if [[ "$queued" == "0" ]]; then
      echo "  [worker drained: dispatched=$(curl -s 127.0.0.1:3000/metrics | awk -F' ' '/status="dispatched"/ {print $2}')]"
      return 0
    fi
    sleep 0.2
  done
  echo "  [warning: queue did not drain]" >&2
}

echo "health: $(curl -s -o /dev/null -w '%{http_code}' 127.0.0.1:3000/health)  blocks: $(block)  $(metrics | tail -1)"

run honest 10
run replay 5
run nonce-reuse 4
run malleable 3
run badsig 3
run expired 3
run far-deadline 3
run empty-calldata 3
run garbage 3
run mixed 40

if [[ "${1:-}" == "--grief" ]]; then
  echo
  echo "=== griefing: installing a REVERT-ing contract at $FORWARDER (anvil_setCode) ==="
  cast rpc anvil_setCode "$FORWARDER" 0x60006000fd --rpc-url "$RPC" >/dev/null
  before=$(block)
  echo "blocks before: $before"
  run honest 5
  echo "blocks after:  $(block)   <- unchanged: nothing was mined, nothing was paid"
  echo "gas burned on reverts: $(curl -s 127.0.0.1:3000/metrics | grep -E '^relayer_gas_burned_on_reverts_wei')"
  echo
  echo "restoring the forwarder..."
  cast rpc anvil_setCode "$FORWARDER" 0x --rpc-url "$RPC" >/dev/null
fi

echo
echo "=== relayer scoreboard ==="
curl -s 127.0.0.1:3000/metrics | grep -vE '^#'
