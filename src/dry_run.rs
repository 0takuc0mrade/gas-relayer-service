//! Part 1: the simulation (dry-run) pattern -- the relayer's primary defence.
//!
//! # The attack: griefing
//!
//! An attacker needs nothing but a keypair and a little patience:
//!
//! 1. build a *perfectly valid* meta-transaction (correct nonce, correct signature);
//! 2. make the calldata something that is guaranteed to fail on chain (a transfer with no
//!    balance, a call to a function that reverts, a `require(false)`);
//! 3. POST it a thousand times.
//!
//! The relayer pays `21_000 + calldata` gas for each one, the transaction is mined, it reverts,
//! and the attacker keeps the gas. There is no exploit and no bug -- just a relayer that agrees
//! to buy failing transactions. "Griefing" is the polite word; the balance does not care.
//!
//! # The defence: ask the node first, for free
//!
//! `eth_call` executes the transaction against current state and **throws the result away**. It
//! costs no gas, mines no block, and returns the same revert the transaction would have hit. So
//! the relayer's shape changes from *"sign, pay, discover"* to *"ask, reject, never pay"*.
//!
//! # The honest limits (TOCTOU, and why this is not a proof)
//!
//! * The simulation runs at one instant; the transaction lands at another. Between them a
//!   balance can be spent or a slot can change. `eth_call` is a **bookmaker's odds**, not a
//!   guarantee -- it removes the naive griefing flood, not every possible revert.
//! * We simulate at the `pending` block (Alloy's default), which includes queued transactions
//!   from the same node. That narrows the window but cannot close it.
//! * A reverted transaction is *still* broadcast once it has been sent; the only way to be sure
//!   is to also cap gas, monitor receipts, and act on the numbers. See [`crate::metrics`] --
//!   `relayer_gas_burned_on_reverts_wei` is the number that must stay at zero.

use alloy::primitives::Bytes;
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;

/// The three possible verdicts, kept apart on purpose.
///
/// "The transaction would revert" and "I could not reach the node" are completely different
/// facts, and conflating them is how a relayer drops a legitimate user's intent during a blip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Simulation {
    /// `eth_call` succeeded. The returned bytes are the call's output (usually empty).
    Passed(Bytes),
    /// The node executed the call and it reverted. The intent is bad: drop it, spend nothing.
    WouldRevert(String),
    /// The node never answered. Not the user's fault: retry, do **not** mark the intent spent.
    Unavailable(String),
}

/// Simulate `tx` with `eth_call`. Never touches the chain and never costs gas.
///
/// The `provider` here must be a *read* provider connected to a full node with state. A
/// private-orderflow relay (Flashbots) cannot serve `eth_call`, which is why the relayer keeps
/// two providers: simulate on the public node, broadcast to the private one.
///
/// # Returns
/// [`Simulation::Passed`] when the call succeeds, otherwise the reason it did not.
pub async fn dry_run<P: Provider>(provider: &P, tx: &TransactionRequest) -> Simulation {
    match provider.call(tx.clone()).await {
        Ok(output) => Simulation::Passed(output),
        Err(err) => {
            // `as_error_resp` is `Some` when the *node* rejected the call (revert, out of gas,
            // insufficient funds) and `None` for transport-level problems (DNS, TLS, 502).
            // Only the former is evidence that the intent is bad.
            if let Some(payload) = err.as_error_resp() {
                let revert_data = payload
                    .as_revert_data()
                    .map(|data| format!(" revert_data=0x{}", alloy::hex::encode(&data)))
                    .unwrap_or_default();
                Simulation::WouldRevert(format!(
                    "{} (code {}){}",
                    payload.message, payload.code, revert_data
                ))
            } else {
                Simulation::Unavailable(err.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passed_and_would_revert_are_not_the_same_verdict() {
        // A test that only asserts "it was not Ok" would pass while the relayer dropped every
        // intent during an RPC outage. Encode the distinction instead.
        let passed = Simulation::Passed(Bytes::new());
        let revert = Simulation::WouldRevert("execution reverted".into());
        let down = Simulation::Unavailable("connection refused".into());
        assert_ne!(passed, revert);
        assert_ne!(revert, down);
    }
}
