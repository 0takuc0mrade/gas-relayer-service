# Security Audit Checklist — a Relayer

Use this to grade your own relayer (or a partner's) in the Part 4 "Break My Code" session.
Every line is phrased so that **"we thought about it" does not count**: it either points at code, or
it points at a command whose output proves it.

Scoring: **1 point per line, 0 or 1, no partial credit.** `MAX = 40`.

| Score | Verdict |
|---|---|
| 36–40 | Production-shaped. Go get it audited by a human. |
| 28–35 | Solid homework. Find the two lines you cannot prove and fix them. |
| 18–27 | You have a demo, not a relayer. |
| < 18 | You have a donation machine with an HTTP endpoint. |

---

## A. Authentication — "is this really what the user authorised?" (12 points)

- [ ] **A1.** The signature is over an **EIP-712 struct**, not over a hash of the calldata.
      *Prove it:* `src/intent.rs` (`sol! { struct Intent { .. } }`); the client signs
      `eip712_signing_hash(&domain)`, not `keccak256(calldata)`.
- [ ] **A2.** The domain includes **`chainId`**. A signature harvested on mainnet must not be valid
      on your testnet. *Prove it:* `cargo test --lib a_signature_for_another_chain_is_rejected`.
- [ ] **A3.** The domain includes **`verifyingContract`** = your forwarder. This is the line that
      stops "sign once, relay anywhere". *Prove it:*
      `cargo test --lib a_signature_for_another_contract_is_rejected`.
- [ ] **A4.** The signed struct commits to the **exact calldata** (`dataHash`). If the relayer can
      swap the calldata, it is a signing oracle. *Prove it:*
      `cargo test --lib swapping_calldata_invalidates_the_signature`.
- [ ] **A5.** `user` is **recovered**, never trusted. The request's `user` field is a claim.
      *Prove it:* `verify_intent` compares `recover_address_from_prehash(...)` to `req.user`;
      `simulator badsig` returns 401.
- [ ] **A6.** Signatures are **canonical (low-s)**. `(r, s)` and `(r, n - s)` are two valid
      signatures of the same intent — enough to defeat a replay cache keyed on signature bytes.
      *Prove it:* `cargo test --lib a_high_s_signature_is_rejected_as_malleable`;
      `simulator malleable` returns 401.
- [ ] **A7.** There is a **`deadline`**, it is enforced, and it is **short**. A signature worth ten
      years of gas is a liability if it leaks. *Prove it:* `MAX_DEADLINE_WINDOW_SECS`;
      `simulator far-deadline` returns 400.
- [ ] **A8.** Expired intents are refused **before** any expensive work. *Prove it:*
      `simulator expired` returns 400, and the counter `reason="expired"` moves.
- [ ] **A9.** A **nonce** is part of the signed struct (per user, monotonic).
- [ ] **A10.** Calldata is **bounded** in size (`MAX_CALLDATA_BYTES`). Unbounded calldata is
      unbounded gas, paid by you.
- [ ] **A11.** Empty calldata is refused. On an empty account it is a *successful* no-op: you pay
      gas to accomplish nothing. *Prove it:* `simulator empty-calldata` returns 400.
- [ ] **A12.** Malformed input is refused at the **edge**, before any curve arithmetic.
      *Prove it:* `simulator garbage` returns 400; `cargo test --lib a_truncated_signature...`.

## B. Replay — "can the same intent be spent twice?" (8 points)

- [ ] **B1.** The relayer keeps its **own** used-signature registry. The contract's nonce check is
      not enough: a duplicate is only discovered by *paying* for a reverted transaction.
- [ ] **B2.** The registry key is the **EIP-712 digest**, not the signature bytes (malleability).
- [ ] **B3.** The registry also keys on **`(user, nonce)`** — two different digests can share one
      spent nonce. *Prove it:* `cargo test --lib the_same_nonce_under_a_different_digest_is_still_refused`;
      `simulator nonce-reuse` → 409 `nonce_taken`.
- [ ] **B4.** Check-and-insert is **one critical section**. A read-then-write is a race, and the
      race *is* the attack. *Prove it:* `cargo test --lib a_race_of_identical_intents_produces_exactly_one_winner`;
      `simulator replay 20` → exactly 1×202 and 19×409.
- [ ] **B5.** The registry is **bounded** (`MAX_SEEN_ENTRIES`) so an attacker cannot grow your
      memory without limit.
- [ ] **B6.** Eviction is understood, not accidental: once an entry is evicted, a replay is
      *expensive* but not *theft*, because the contract still enforces the nonce. Write this
      sentence in your README.
- [ ] **B7.** The claim happens **before** the queue, and it is **fail-closed**: an intent that is
      never relayed is a support ticket, an intent relayed twice is a theft.
- [ ] **B8.** Restart behaviour is known: an in-memory registry is empty after a restart. Either
      accept that (and say so) or persist it (Redis) — but never *assume* it survived.

## C. Economics — "can an attacker make me pay for nothing?" (8 points)

- [ ] **C1.** An **`eth_call` dry run** runs before every broadcast. *Prove it:* `src/dry_run.rs`.
- [ ] **C2.** The dry run uses **`from` = your relayer address**, otherwise `msg.sender`-dependent
      logic and balance checks simulate as the wrong account.
- [ ] **C3.** The dry run costs the attacker nothing (no gas) and returns the revert reason.
- [ ] **C4.** A would-revert intent is **refused synchronously** with a clear status (422 here),
      not sitting in a queue.
- [ ] **C5.** The dry run is **re-run immediately before sending**. State moves between the
      request and the broadcast; you accept that you cannot close TOCTOU, and you narrow it.
- [ ] **C6.** You measure the loss: `relayer_gas_burned_on_reverts_wei` exists and is **0**.
      *Prove it:* `./scripts/break_my_code.sh --grief` → 5 reverting intents, 0 gas burned,
      block number unchanged.
- [ ] **C7.** You distinguish **"the transaction would revert"** from **"I could not reach the
      node"**. The first is the user's fault; the second is yours, and must not burn the replay
      slot or blame the user. *Prove it:* `Simulation::{WouldRevert, Unavailable}`.
- [ ] **C8.** There is back-pressure: a full queue returns 503 instead of growing without bound.

## D. Key custody — "how does the God Key leak?" (7 points)

- [ ] **D1.** The key is **not in a global/`static`**.
- [ ] **D2.** The key is **not in `AppState`** (nor in anything the API can reach).
- [ ] **D3.** The key is **not `Debug`-printable**. *Prove it:* `cargo test --lib debug_never_prints_the_secret`.
- [ ] **D4.** The key is **not interpolated into error messages**. *Prove it:* `malformed_keys_are_refused_without_echoing_them`.
- [ ] **D5.** Key material is **zeroized on drop** (`Zeroizing` / `zeroize`).
- [ ] **D6.** The copy you loaded is **dropped before the first request is served** (`drop(key)` in
      `main`), leaving exactly one live copy — inside the provider's signer.
- [ ] **D7.** You can state the honest limit out loud: process memory is not a KMS. The real fix
      for production is a signer that never exposes the key (KMS/HSM/`alloy-signer-ledger`) —
      and you documented that instead of pretending the struct is enough.

## E. Orderflow — "who sees my transaction before it lands?" (5 points)

- [ ] **E1.** You can explain front-running: a signed transaction in the public mempool is a
      public bet, and someone can pay more to take it.
- [ ] **E2.** The broadcast endpoint is **configurable** (`PRIVATE_RPC_URL` / `FLASHBOTS_RPC_URL`)
      and the relayer **logs which one is in use** at startup.
- [ ] **E3.** Simulation still runs against a **full node**, because a private relay cannot serve
      `eth_call`. Two providers, two jobs. *Prove it:* banner shows `simulate against` ≠ `broadcast to`.
- [ ] **E4.** You know that private orderflow is a **trust** decision, not a cryptographic one, and
      that it trades censorship risk and latency for protection.
- [ ] **E5.** You know bundles exist (`eth_sendBundle`) and that "Flashbots-ready" for a relayer is
      really "one URL away" — the interesting part is the nonce/filler behaviour, not the URL.

---

## F. The five questions to ask about any relayer (including your own)

1. **Who pays for a failed transaction, and how do you know?** *(If the answer is "we do, and we
   do not measure it", stop.)*
2. **What exactly is signed, and does it name this chain and this contract?**
3. **Can the same authorisation be spent twice — by replay, by malleability, or by a nonce
   collision?**
4. **Where does the key live, for how long, and who can read it?**
5. **What stops me from submitting 10,000 intents a second?** *(Rate limit, queue bound, calldata
   bound, deadline — anything.)*

If you can answer all five with a pointer to a line of code and a command that proves it, you are
not a developer who writes relayer code any more. You are a **protocol engineer**.

---

## Already-known gaps (write them down; do not pretend)

| Gap | Why it is acceptable *for this lab* | What production does |
|---|---|---|
| Replay registry is in-memory and per-process | Single instance, nonce is still enforced on chain | Shared store (Redis) keyed by digest, plus on-chain nonce as source of truth |
| No rate limiting per caller | The lab runs on localhost | Token bucket per IP/user; queue bound is the last resort |
| Dry run cannot close TOCTOU | Narrowed with a pre-broadcast re-check and measured | Bounded gas, private orderflow, receipt monitoring |
| Key is read from an environment variable | Convenient and demonstrative | KMS/HSM signer; the process never holds key bytes |
| `eth_call` is one round trip per intent | Fine at classroom volume | Batch with `eth_callMany` / local state simulation |
