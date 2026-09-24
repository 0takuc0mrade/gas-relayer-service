# Workshop: Anatomy of a Gas Relayer (90 minutes)

A hands-on, 90-minute session built entirely on this repository.

**Learning outcomes — by the end, students can:**
1. Explain why a gas relayer exists and what an EIP-2771 trusted forwarder adds.
2. Trace an intent from `POST /submit` through an `mpsc` queue, a signing provider, and into a mined transaction.
3. Read a compiler error, fix the **first** one, and explain why a downstream error disappeared on its own.
4. Give two examples of code that compiles cleanly and is still wrong.

**Audience:** Rust beginners (comfortable reading `async`/`await`, ownership basics) with
basic Ethereum transaction concepts.

**Prerequisites:** Rust + cargo, Foundry (`anvil`, `cast`), this repo cloned.

**There is no theory slide deck.** Every claim in this run sheet is demonstrated live, and
almost every command below is a command you run on the projector.

---

## 0. Repo state: the exercise and the answer key

| Ref | What it is |
|---|---|
| `33c147a` | The broken prototype — **the exercise** |
| `HEAD` | The fix — **the answer key** |

Three commands you will use all session:

```bash
git checkout 33c147a -- src/main.rs   # restore the broken version
git checkout HEAD  -- src/main.rs     # restore the fixed version
git diff 33c147a HEAD -- src/main.rs  # the answer key, 60 lines
```

`src/bin/simulator.rs` and the rest of the repo are identical in both commits.

---

## 1. Before students arrive (10 minutes, and worth it)

1. `cargo build --all-targets` — this pre-warms alloy. Every later rebuild in class takes
   ~2–5s instead of several minutes. **Do not skip this**; a 5-minute compile with 20
   people watching is how workshops die.
2. Start `anvil` in **T1** and leave it running for the whole session.
3. Four terminals: **T1** anvil · **T2** the relayer (`cargo run`) · **T3** the simulator · **T4** `cast` / `curl`.
4. Tell students two gotchas up front:
   - Always `curl 127.0.0.1:3000`, **never `localhost`**. The server binds IPv4 only; on
     macOS `localhost` can resolve to `::1` first, and you get a silent, confusing failure.
   - Restart `anvil` when you want the `nonce 0 → 50` demonstration to repeat. Nonces and
     balances persist for the life of the node.
5. Versions every output below was captured on: rustc/cargo **1.93.0**, alloy **2.1.1**,
   axum **0.8.9**, reqwest **0.13.5**, tokio **1.53.1**, anvil **0.2.0**. Exact error
   wording can differ slightly on other versions — run each demo once yourself first.

---

## 2. Running clock

| Clock | Segment | The point |
|---|---|---|
| 0:00–0:05 | Framing | Why a relayer exists at all |
| 0:05–0:12 | Tour of the files + the diagram | The promise: "users need no ETH" |
| 0:12–0:25 | **Act 1:** the 4 compiler errors | Fix the *first* error only |
| 0:25–0:40 | **Act 2:** compiles ≠ correct (2 demos) | The compiler checks types, not intent |
| 0:40–0:45 | Break | |
| 0:45–0:57 | **Act 3:** happy path, end to end | 50 intents → 50 mined transactions |
| 0:57–1:12 | **Act 4:** audit the diagram | It lies in 4 places; then implement `.watch()` |
| 1:12–1:22 | **Act 5:** the queue | Backpressure and durability |
| 1:22–1:30 | Wrap | Homework + the security lesson |

The two acts that carry the most learning are **Act 4** (auditing documentation against
code) and **Act 5** (queue behaviour with real numbers). Protect their time; shorten
the tour if you're running late.

<!-- APPEND-MARKER -->
# Day 4: The Hardened Relayer — Adversarial Design (4 hours)

Days 2 and 3 were about *functionality*. Today is about **survival**. A relayer is a honey-pot: it
holds a funded key and signs transactions for strangers. Every segment below closes one specific way
to steal from it.

**Learning outcomes — by the end, students can:**
1. Explain *griefing* and demonstrate a relayer losing gas without any bug being exploited.
2. Implement the dry-run pattern (`eth_call` before `send_transaction`) and prove the loss went to 0.
3. Explain why a replay cache must key on the EIP-712 **digest** (and the nonce), not the signature.
4. Refactor a key out of global state into a drop-wiped struct, and name the limit of that approach.
5. Route a transaction to a private mempool and explain what that does and does not buy.
6. Audit their own service adversarially instead of optimistically.

**Prerequisites:** Day 3 finished and running (relayer + `simulator` both build).
Anvil and `cast` on `PATH`. **Four terminals**, same as Day 3.

**Repo state:** this is a *new* shape of the code, not a diff. The Day 3 relayer still exists in git
history (`git log --oneline`); today's code lives in `src/lib.rs` + `src/main.rs`.

| Clock | Segment | The point |
|---|---|---|
| 0:00–0:10 | Framing: "who is the adversary?" | The relayer is the target, not the user |
| 0:10–1:10 | **Part 1: griefing + the dry run** | Ask, reject, never pay |
| 1:10–2:40 | **Part 2: replay, malleability, the God Key** | One intent, one spend; one key, one place |
| 2:40–2:50 | Break | |
| 2:50–3:50 | **Part 3: Flashbots-ready infrastructure** | Public mempool = public bet |
| 3:50–4:20 | **Part 4: "Break My Code"** | Self-grade with the audit checklist |
| 4:20–4:30 | Wrap: the five questions | Homework and the audit checklist |

Protect Part 4. A student who can attack their own code has learned more than one who can only
add features.

---

## 0. Before students arrive (10 minutes)

1. `cargo build --all-targets` — pre-warms the build. Non-negotiable.
2. `anvil` in **T1**. Leave it running. Blocks only advance when transactions land, so a rising
   block number *is* your proof that nothing was relayed.
3. Confirm the shape: `cargo test --lib` should print **24 passed**. These are the unit proofs for the
   claims you are about to make — run them live rather than asserting them.
4. Two terminals of state you will point at all session:
   ```bash
   curl -s 127.0.0.1:3000/metrics | grep -v '^#'        # T4: the scoreboard
   watch -n1 'cast block-number'                        # T4: the chain
   ```

---

## Part 1 — The "Griefing" Analysis (60 min)

### The attack, with no bug anywhere

An attacker needs a keypair and patience:

1. build a **perfectly valid** meta-transaction (correct nonce, correct signature);
2. make the calldata something guaranteed to fail on chain;
3. POST it a thousand times.

The relayer pays the gas, the transaction reverts, the attacker keeps the gas. This is **griefing**,
and it is not an exploit of your code — it is your code agreeing to buy failing transactions.

### Demo 1: a relayer with no dry run (2 minutes, and the whole lesson)

Install a contract that reverts at the forwarder address, using anvil's cheat code
(`60006000fd` is `PUSH1 0 PUSH1 0 REVERT` as runtime code):

```bash
cast rpc anvil_setCode 0x0000000000000000000000000000000000000000 0x60006000fd
```

Now run the relayer the way Day 2/3 ran it — every check except the simulation:

```bash
DRY_RUN=0 GAS_LIMIT=100000 cargo run          # T2: banner says "DRY RUN OFF"
# T3:
before=$(cast block-number)
cargo run --bin simulator -- honest 5
sleep 3
cast block-number; echo "was $before"
# T4:
curl -s 127.0.0.1:3000/metrics | grep -E 'dry_run_enabled|status="reverted"|^relayer_gas_burned'
```

Expected: `5 x 202`, five **new blocks**, `reverted 5`, and
`relayer_gas_burned_on_reverts_wei` in the millions. Nobody exploited a bug. The relayer simply
bought five failing transactions.

> `GAS_LIMIT` is not decoration. With the default Alloy fillers, a reverting transaction never gets
> broadcast at all: the filler calls `eth_estimateGas`, the node answers with the revert, and the
> send is aborted. That is a free dry run hiding inside a dependency — useful to know, useless to
> rely on (it is one extra round trip, it does not tell you *why*, and it happens after your queue
> slot is spent). Setting an explicit gas limit — which is what a production relayer does to bound
> its worst case — removes the crutch and makes the loss visible.

Then turn the defence on and repeat, **leaving the reverting forwarder exactly where it is**:

```bash
cargo run                                    # T2: banner says "DRY RUN ON"
cargo run --bin simulator -- honest 5        # 5 x 422 Unprocessable Entity
curl -s 127.0.0.1:3000/metrics | grep -E 'would_revert|^relayer_gas_burned'
cast block-number                            # unchanged
```

Same five intents, same broken destination, zero blocks, zero gas. Then clean up the cheat:
`cast rpc anvil_setCode 0x0000000000000000000000000000000000000000 0x`.

### The lab task (the primary defence)

`src/dry_run.rs` + `submit_handler`. Read the code in this order:

1. `dry_run(provider, tx)` — one `eth_call`; the returned error is classified as
   `WouldRevert` (node executed it and it failed) versus `Unavailable` (the node never answered).
2. `submit_handler` — the gate order: **verify → simulate → claim → queue**. Simulation comes
   *before* claiming the nonce, so a transient simulation failure does not burn a user's slot.
3. `process` — the **last-chance re-simulation**, immediately before the broadcast.

### Proof (the part students must produce, not be told)

```bash
cast rpc anvil_setCode 0x0000000000000000000000000000000000000000 0x60006000fd
before=$(cast block-number)
cargo run --bin simulator -- honest 5      # five *correctly signed*, reverting intents
curl -s 127.0.0.1:3000/metrics | grep -E 'would_revert|dispatched|gas_burned'
after=$(cast block-number)
echo "blocks: $before -> $after"           # identical: nothing was mined, nothing was paid
cast rpc anvil_setCode 0x0000000000000000000000000000000000000000 0x
```

Expected: `5 x 422 Unprocessable Entity`, `would_revert 5`, `dispatched` unchanged,
`gas_burned_on_reverts_wei 0`, and **blocks unchanged**.

### The honest limits — say these out loud

* **TOCTOU.** The simulation runs at one instant, the transaction lands at another. `eth_call` is a
  bookmaker's odds, not a guarantee. It removes the naive flood, not every revert.
* That is why we (a) re-simulate immediately before sending, (b) await receipts, and (c) **measure**
  `relayer_gas_burned_on_reverts_wei`. The number must be 0 — and you must be able to *see* it.

---

## Part 2 — Replay & Malleability Defence (90 min)

### 2a. EIP-712 integrity (45 min)

Open `src/intent.rs` and answer, for each field of `Intent`, *what attack disappears if this field
vanishes*:

| Field | Remove it and an attacker can... |
|---|---|
| `user` | (not removable) — this is *who* authorised it |
| `nonce` | replay the same intent until the gas runs out |
| `deadline` | wait. A leaked signature stays valid forever |
| `dataHash` | make you relay arbitrary calldata the user never signed |
| `chainId` (domain) | take a testnet signature to mainnet, or vice versa |
| `verifyingContract` (domain) | sign once, relay against **any** forwarder, including theirs |
| `name`/`version` (domain) | replay a signature from a different app in the same domain |

Show the domain separator live, then show the test that proves it matters:

```bash
curl -s 127.0.0.1:3000/domain | python3 -m json.tool   # name, version, chain_id, forwarder, separator
cargo test --lib the_domain_separator_changes_with_the_verifying_contract
cargo test --lib a_signature_for_another_contract_is_rejected
```

### Lab task: the Used Signature Registry

`src/replay.rs`. Three things to notice, in this order:

1. **Why a cache at all?** The contract checks nonces — but that check costs a *transaction* to
   discover. A duplicate is only found by paying for a reverted transaction.
2. **Why the digest and not the signature?** ECDSA is malleable: `(r, s)` and `(r, n - s)` are both
   valid for the same message, so a signature-keyed cache has a trivial bypass. `malleable_twin()`
   in `intent.rs` builds the twin in three lines — show them.
3. **Why the second index, `(user, nonce)`?** Two intents with the same nonce and *different*
   deadlines are two different digests and one spent nonce. Without the index, the second one
   reaches the chain, reverts, and you pay.

```bash
cargo run --bin simulator -- replay 5        # 1 x 202, then 4 x 409 "already been relayed"
cargo run --bin simulator -- nonce-reuse 4   # 1 x 202, then 3 x 409 "nonce ... was already spent"
cargo run --bin simulator -- malleable 3     # 3 x 401 "non-canonical (high-s)"
cargo test --lib a_race_of_identical_intents_produces_exactly_one_winner
```

That last test is the one to dwell on: check-and-insert under **one** lock. A read-then-write split
is a race, and the race is the attack.

### 2b. Private key management (45 min)

**The rule:** the relayer's key is the God Key. It signs anything, so it *is* the protocol.

Read `src/secure_key.rs` and enumerate what it refuses to do:

* not a `static` → the key lives on the stack in `main`;
* not in `AppState` → nothing the API can reach holds key material;
* hand-written `Debug` → a stray `println!("{state:?}")` cannot leak it;
* errors never interpolate the value → logs and crash reporters stay clean;
* `Zeroizing<Vec<u8>>` + `Drop` → the buffer is overwritten, not returned to the allocator.

Then the payoff move: **`drop(key)` in `main`, before the listener is bound.** The copy you loaded is
gone before a single request is served.

```bash
cargo test --lib debug_never_prints_the_secret
cargo test --lib malformed_keys_are_refused_without_echoing_them
```

**Say the honest limit:** process memory is not a KMS. The environment block, the `.env` file, the
shell history and the OS page cache all saw the bytes before you did. The production answer is that
the key never enters the process at all (KMS/HSM/`alloy-signer-ledger`). What this struct buys you
is: one place you control, no logs, wiped on exit.

---

## Part 3 — "Flashbots-Ready" Infrastructure (60 min)

The problem, stated plainly: a signed transaction in the public mempool is a **public bet**. Anyone
can see it and pay more to take the profit in front of you.

### Lab task: two providers, two jobs

This is the design idea to take away: **simulation and broadcast are different jobs.**

```
RPC_URL          -> eth_call, chain id, receipts       (a full node: it has state)
PRIVATE_RPC_URL  -> eth_sendRawTransaction only         (a relay: it has orderflow)
```

A private relay cannot serve `eth_call`; that is why `main` builds **both** providers and why the
startup banner prints both. In your own words: *the dry run stays on the public node, the broadcast
leaves the public view.*

### Demo: show the routing, on two local nodes

```bash
anvil -p 8546 &                                        # stand-in for relay.flashbots.net
PRIVATE_RPC_URL=http://127.0.0.1:8546 cargo run        # T2: banner says PRIVATE MEMPOOL
# T4:
cast block-number --rpc-url http://127.0.0.1:8545      # 67  <- public: never saw it
cast block-number --rpc-url http://127.0.0.1:8546      # 0
cargo run --bin simulator -- honest 3
cast block-number --rpc-url http://127.0.0.1:8545      # still 67
cast block-number --rpc-url http://127.0.0.1:8546      # 3   <- the private node did the work
```

### What this does and does not buy

* It hides the transaction until it is in a block: no time to front-run it.
* It is a **trust** decision. You are trusting the relay/builder not to censor, delay, or leak it.
* For real Flashbots: same code, different URL. `https://relay.flashbots.net` plus a signing header.
* Bundles (`eth_sendBundle`) are the next rung: atomic inclusion, failure reverts the whole bundle.
* Note the nonce caveat when you leave anvil: a relay will not answer `eth_getTransactionCount`, so
  production relayers fetch the nonce from the public node and set it explicitly rather than letting
  the filler ask the relay.

---

## Part 4 — The Adversarial "Break My Code" Session (30 min)

Pairs: **A is the Hacker, B is the Defender.** Then swap. The Hacker's goal is narrow and cruel:
make the Defender's relayer **submit a transaction that reverts, or submit the same intent twice.**

One command runs the whole suite:

```bash
./scripts/break_my_code.sh --grief
```

Then let them write their *own* attacks. The mode list is the starter set, not the ceiling — every
mode is ~10 lines inside `src/bin/simulator.rs::build`, and adding one is the actual homework.

**Scoring, agreed up front:**

* Defender wins if **no attack intent is accepted** *and* the same run's honest intents are still
  relayed. A relayer that refuses everything is not secure, it is broken.
* Hacker wins if **any** attack is accepted, or if a refundable cost is created: gas burned,
  a queue slot occupied, a replay slot consumed.

Self-grade with `SECURITY_AUDIT_CHECKLIST.md` (40 points). Ask for the two lines they each cannot
prove — those are the real homework.

### Attacks worth watching for (they always show up)

| Attack | What it targets | Expected answer |
|---|---|---|
| Send the identical intent 5 times concurrently | check-and-insert atomicity | 1×202, 4×409 |
| Same nonce, different deadline (both legitimately signed) | the `(user, nonce)` index | 409 `nonce_taken` |
| Flip the `s` value of a valid signature | canonicality + digest-keyed cache | 401 |
| Sign with your own key but claim the victim's address | recovery | 401 |
| Set `deadline` to `now - 1`, re-sign | the clock | 400 |
| Set `deadline` to `now + 1 year`, re-sign | the deadline window | 400 |
| `data: "0x"` on an empty-account forwarder | empty-calldata rule | 400 |
| 1 MB of calldata | `MAX_CALLDATA_BYTES` | 400 |
| 1000 concurrent intents | queue bound / back-pressure | 202s + some 503s, no OOM |
| Point the forwarder at a reverting contract | the dry run | 422, `gas_burned_on_reverts_wei 0` |
| Restart the relayer and replay an old intent | registry persistence | *documented gap* — say so |

---

## Wrap (10 min): the five questions

1. Who pays for a failed transaction, and how do you know?
2. What exactly is signed, and does it name *this* chain and *this* contract?
3. Can the same authorisation be spent twice — replay, malleability, nonce collision?
4. Where does the key live, for how long, and who can read it?
5. What stops me from sending 10,000 intents a second?

Homework: answer all five for your own relayer, with a line of code and a command for each. Then
run `./scripts/break_my_code.sh --grief` and paste the scoreboard into your README.

> By the end of today you should stop asking *"does this code work?"* and start asking *"how can this
> code be exploited?"* That distinction is the whole job.
