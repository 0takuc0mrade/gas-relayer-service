//! "Used signature registry": the Relayer's own memory of what it has already relayed.
//!
//! # Why the relayer needs its own cache at all
//!
//! The contract checks nonces. Isn't that enough? No:
//!
//! * a nonce check costs a **transaction** to discover. If the relayer submits a duplicate, the
//!   duplicate reverts on chain and the relayer has paid the gas for the privilege;
//! * the relayer is a fan-out point. The same intent can arrive on `POST /submit` twice, from
//!   two retrying clients, or from two load-balanced API replicas at the same instant. Only a
//!   check-and-insert inside one critical section can stop both copies;
//! * the contract's nonce is *state*, and state is only updated once a block lands. Until then
//!   the on-chain nonce looks free even though a submission is already in flight.
//!
//! # Why the key is the digest and not the signature
//!
//! ECDSA is malleable: `(r, s)` and `(r, n - s)` are both valid signatures for the same message.
//! A cache keyed on signature *bytes* therefore has a trivial bypass -- send the intent once,
//! then send it again with the s-value flipped. Keying on the EIP-712 signing hash makes both
//! forms the same entry. (The API also rejects high-`s` outright; this is defence in depth.)
//!
//! # The second index, and the grief it prevents
//!
//! The digest covers `(user, nonce, deadline, dataHash)`. An attacker who holds a valid
//! signature for nonce 7 cannot reuse nonce 7 with a *different* deadline -- that changes the
//! digest and the signature no longer recovers. But the attacker can take two intents the user
//! legitimately signed with the same nonce (say, a retry with a longer deadline) and submit
//! both: two distinct digests, one spent nonce. Without the `(user, nonce)` index the second
//! one reaches the chain, reverts, and the relayer pays. That is the grief the index stops.

use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;

use alloy::primitives::{Address, B256};

use crate::intent::Reject;

/// One entry of the insertion order log, kept so the registry can be bounded.
type Claim = (B256, Address, u64);

#[derive(Debug)]
struct Inner {
    /// EIP-712 signing hashes we have already accepted.
    digests: HashSet<B256>,
    /// `(user, nonce)` pairs we have already accepted, regardless of digest.
    nonces: HashSet<(Address, u64)>,
    /// FIFO order of claims, for eviction once `capacity` is reached.
    order: VecDeque<Claim>,
    /// Maximum number of claims retained.
    capacity: usize,
}

/// An in-memory record of every intent this relayer has already claimed.
///
/// Uses a `std::sync::Mutex`, not a `tokio::sync::Mutex`: the critical section is a few hash
/// lookups with **no `await` inside**, so holding a blocking lock for microseconds is correct and
/// cheaper than the async alternative. Never hold this across `.await`.
#[derive(Debug)]
pub struct ReplayGuard {
    inner: Mutex<Inner>,
}

impl ReplayGuard {
    /// Create a registry that retains at most `capacity` claims.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                digests: HashSet::new(),
                nonces: HashSet::new(),
                order: VecDeque::new(),
                capacity: capacity.max(1),
            }),
        }
    }

    /// Atomically check **and** insert.
    ///
    /// Two concurrent calls with the same `(digest, user, nonce)` can never both succeed: the
    /// lookup and the insert happen under one lock, so there is no window between them. A
    /// read-then-write split would be a race, and the race is exactly the attack.
    ///
    /// # Errors
    /// * [`Reject::Replayed`] if this exact digest was already claimed;
    /// * [`Reject::NonceTaken`] if this user's nonce was already claimed by another digest.
    pub fn claim(&self, digest: B256, user: Address, nonce: u64) -> Result<(), Reject> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // Two separate questions, two separate answers -- an attacker learns which defence
        // caught them, an operator learns what to alert on.
        if inner.digests.contains(&digest) {
            return Err(Reject::Replayed { digest });
        }
        if inner.nonces.contains(&(user, nonce)) {
            return Err(Reject::NonceTaken { user, nonce });
        }

        inner.digests.insert(digest);
        inner.nonces.insert((user, nonce));
        inner.order.push_back((digest, user, nonce));

        // Bound the memory. Eviction is safe *only* because the contract's nonce check is the
        // real source of truth: after eviction a replay is merely expensive, not theft.
        while inner.order.len() > inner.capacity {
            if let Some((old_digest, old_user, old_nonce)) = inner.order.pop_front() {
                inner.digests.remove(&old_digest);
                inner.nonces.remove(&(old_user, old_nonce));
            }
        }

        Ok(())
    }

    /// Number of claims currently retained. Used by `/metrics`.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .order
            .len()
    }

    /// `true` when nothing has been claimed yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Peek without claiming. **Never use this to gate work** -- it is for tests and diagnostics.
    pub fn contains(&self, digest: B256) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .digests
            .contains(&digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const USER: Address = Address::repeat_byte(0xAA);
    const OTHER: Address = Address::repeat_byte(0xBB);

    fn digest(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    #[test]
    fn the_first_claim_wins_and_the_second_is_flagged_as_a_replay() {
        let guard = ReplayGuard::new(16);
        assert!(guard.claim(digest(1), USER, 7).is_ok());
        assert_eq!(
            guard.claim(digest(1), USER, 7).unwrap_err(),
            Reject::Replayed { digest: digest(1) }
        );
    }

    #[test]
    fn the_same_nonce_under_a_different_digest_is_still_refused() {
        // The grief: a user signs two intents with nonce 7 (say a retry with a new deadline).
        // Both are valid EIP-712 signatures. Only the nonce index catches the second one
        // *before* it reaches the chain and reverts at our expense.
        let guard = ReplayGuard::new(16);
        assert!(guard.claim(digest(1), USER, 7).is_ok());
        let err = guard.claim(digest(2), USER, 7).unwrap_err();
        assert_eq!(
            err,
            Reject::NonceTaken {
                user: USER,
                nonce: 7
            }
        );
        assert_eq!(err.status(), 409);
    }

    #[test]
    fn nonces_are_scoped_per_user() {
        let guard = ReplayGuard::new(16);
        assert!(guard.claim(digest(1), USER, 7).is_ok());
        // A different signer with the same nonce is a different intent, and must pass.
        assert!(guard.claim(digest(2), OTHER, 7).is_ok());
    }

    #[test]
    fn a_race_of_identical_intents_produces_exactly_one_winner() {
        // This is the whole point of check-and-insert under a single lock.
        let guard = Arc::new(ReplayGuard::new(4096));
        let winners = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..64 {
            let guard = Arc::clone(&guard);
            let winners = Arc::clone(&winners);
            handles.push(std::thread::spawn(move || {
                if guard.claim(digest(9), USER, 3).is_ok() {
                    winners.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(winners.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(guard.len(), 1);
    }

    #[test]
    fn eviction_bounds_memory_without_unbounded_growth() {
        let guard = ReplayGuard::new(3);
        for i in 0..10u8 {
            assert!(guard.claim(digest(i), USER, i as u64).is_ok());
        }
        assert_eq!(guard.len(), 3, "the registry must not grow past capacity");

        // The oldest entries were evicted; the newest are still remembered.
        assert!(guard.contains(digest(9)));
        assert!(!guard.contains(digest(0)));

        // Note the honest caveat: after eviction a replay is possible again. It is merely
        // expensive, not theft -- the contract's nonce is still the source of truth.
        assert!(guard.claim(digest(0), USER, 0).is_ok());
    }
}
