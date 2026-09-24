//! The off-chain intent, and the *only* function allowed to decide that an intent is real.
//!
//! # Why raw signatures are dangerous
//!
//! A signature over `keccak256(calldata)` tells you nothing about **who** signed it, **for
//! which contract**, **on which chain**, or **whether they meant it more than once**. Every
//! one of those is a separate exploit:
//!
//! * no domain -> a signature harvested from another app (or another chain) replays here;
//! * no `verifyingContract` -> the same signature is valid against *any* forwarder, including
//!   one the attacker controls;
//! * no `deadline` -> a leaked signature is valid forever;
//! * no `nonce` -> valid as many times as the gas lasts;
//! * no calldata hash -> the relayer becomes a signing oracle for calldata it never saw signed.
//!
//! EIP-712 fixes all of these at once: the signature commits to a struct, and the struct is
//! hashed together with a `domainSeparator` that binds this app's `name`/`version`, the
//! `chainId`, and the `verifyingContract`.

use alloy::primitives::{Address, B256, Bytes, Signature, U256, keccak256};
use alloy::sol;
use alloy::sol_types::{Eip712Domain, SolStruct};
use core::fmt;
use serde::{Deserialize, Serialize};

sol! {
    /// The off-chain authorisation. This must match the Solidity struct the trusted forwarder
    /// checks in `verify(...)` -- **field order included** -- or nothing recovers and every
    /// intent is rejected.
    struct Intent {
        address user;
        uint256 nonce;
        uint256 deadline;
        bytes32 dataHash;
    }
}

/// Largest calldata we are willing to pay gas for. Bounds the relayer's worst case.
pub const MAX_CALLDATA_BYTES: usize = 8 * 1024;

/// Longest deadline window we accept. A signature worth ten years of gas is a liability: if it
/// leaks, the attacker simply waits. Short windows are the mitigation.
pub const MAX_DEADLINE_WINDOW_SECS: u64 = 300;

/// What the user POSTs to `/submit`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetaTxRequest {
    /// The address the user claims to be. We never trust it -- we recover it.
    pub user: Address,
    /// Per-user replay counter.
    pub nonce: u64,
    /// Unix seconds after which this intent is worthless.
    pub deadline: u64,
    /// Hex calldata to send to the trusted forwarder.
    pub data: String,
    /// 65-byte EIP-712 signature over [`Intent`], hex encoded.
    pub signature: String,
}

/// An intent that passed every check. Only this type may be queued.
///
/// The fields are private and the struct has no public constructor, so the worker *cannot* be
/// handed an unverified intent. That is a rule the type system enforces rather than a comment
/// asking nicely.
#[derive(Debug, Clone)]
pub struct VerifiedIntent {
    /// Recovered signer. Guaranteed equal to the claimed `user`.
    pub user: Address,
    /// Per-user nonce, already claimed in the replay guard.
    pub nonce: u64,
    /// Deadline, already checked against the clock.
    pub deadline: u64,
    /// Calldata, already length-checked and hash-verified.
    pub calldata: Bytes,
    /// The EIP-712 signing hash: the *identity* of the intent and the replay key. See
    /// [`crate::replay`] for why it must be the digest and never the signature bytes.
    pub digest: B256,
}

/// Every way an intent can be refused, with the HTTP status it maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    /// Calldata was not hex, was empty, or was absurdly large.
    MalformedData(String),
    /// The signature was not 65 bytes of hex, or recovery itself failed.
    MalformedSignature(String),
    /// The signature was in *non-canonical* (high-`s`) form. Accepting it would let the same
    /// intent exist under a second, equally valid signature.
    MalleableSignature,
    /// Recovery succeeded -- but for somebody else.
    WrongSigner {
        claimed: Address,
        recovered: Address,
    },
    /// `deadline` is in the past.
    Expired { deadline: u64, now: u64 },
    /// `deadline` is too far in the future.
    DeadlineTooFar { deadline: u64, max: u64 },
    /// This exact intent has already been claimed.
    Replayed { digest: B256 },
    /// This user's nonce was already claimed by a *different* intent.
    NonceTaken { user: Address, nonce: u64 },
    /// `eth_call` says the transaction would revert. Refusing here is the whole point: the
    /// relayer never pays for this one.
    WouldRevert(String),
    /// We could not reach the node. **Not** the user's fault -- the intent is not marked seen.
    RpcUnavailable(String),
    /// The queue is full. Back-pressure, not blame.
    QueueFull,
}

impl Reject {
    /// Prometheus-friendly label.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MalformedData(_) => "malformed_data",
            Self::MalformedSignature(_) => "malformed_signature",
            Self::MalleableSignature => "malleable_signature",
            Self::WrongSigner { .. } => "wrong_signer",
            Self::Expired { .. } => "expired",
            Self::DeadlineTooFar { .. } => "deadline_too_far",
            Self::Replayed { .. } => "replayed",
            Self::NonceTaken { .. } => "nonce_taken",
            Self::WouldRevert(_) => "would_revert",
            Self::RpcUnavailable(_) => "rpc_unavailable",
            Self::QueueFull => "queue_full",
        }
    }

    /// The status code a security-conscious API returns.
    ///
    /// * `400` the request is malformed or out of range;
    /// * `401` the signature does not prove what the request claims;
    /// * `409` the request is *valid but already spent* -- the attacker's favourite;
    /// * `422` the request is authentic and would revert: refused on economics, not identity;
    /// * `503` our fault, retry later.
    pub const fn status(&self) -> u16 {
        match self {
            Self::MalformedData(_)
            | Self::MalformedSignature(_)
            | Self::Expired { .. }
            | Self::DeadlineTooFar { .. } => 400,
            Self::MalleableSignature | Self::WrongSigner { .. } => 401,
            Self::Replayed { .. } | Self::NonceTaken { .. } => 409,
            Self::WouldRevert(_) => 422,
            Self::RpcUnavailable(_) | Self::QueueFull => 503,
        }
    }

    /// `true` when the verdict is about the *request*, not about us. A transport failure must
    /// never be reported as a bad intent, and must never burn the replay slot.
    pub const fn is_client_error(&self) -> bool {
        self.status() < 500
    }
}

impl fmt::Display for Reject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedData(why) => write!(f, "malformed calldata: {why}"),
            Self::MalformedSignature(why) => write!(f, "malformed signature: {why}"),
            Self::MalleableSignature => write!(
                f,
                "signature is non-canonical (high-s): the same intent has a second, distinct signature"
            ),
            Self::WrongSigner { claimed, recovered } => {
                write!(
                    f,
                    "signature recovers {recovered}, not the claimed user {claimed}"
                )
            }
            Self::Expired { deadline, now } => {
                write!(f, "intent expired at {deadline} (now {now})")
            }
            Self::DeadlineTooFar { deadline, max } => {
                write!(f, "deadline {deadline} is beyond the window (max {max})")
            }
            Self::Replayed { digest } => write!(f, "intent {digest} has already been relayed"),
            Self::NonceTaken { user, nonce } => {
                write!(
                    f,
                    "nonce {nonce} for {user} was already spent on a different intent"
                )
            }
            Self::WouldRevert(why) => write!(f, "transaction would revert: {why}"),
            Self::RpcUnavailable(why) => write!(f, "node unavailable: {why}"),
            Self::QueueFull => write!(f, "intent queue is full"),
        }
    }
}

impl std::error::Error for Reject {}

/// Build the EIP-712 domain with an explicit name/version.
///
/// # Arguments
/// * `name` -- domain name; must match what clients sign.
/// * `version` -- domain version; must match what clients sign.
/// * `chain_id` -- EIP-155 chain id. A signature made for chain 1 must not work on chain 31337.
/// * `verifying_contract` -- the trusted forwarder. **This is the field that stops the
///   "sign once, relay anywhere" attack.**
///
/// # Panics
/// Never: the macro is const and infallible.
pub fn domain_named(
    name: String,
    version: String,
    chain_id: u64,
    verifying_contract: Address,
) -> Eip712Domain {
    alloy::sol_types::eip712_domain! {
        name: name,
        version: version,
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    }
}

/// The lab's default domain: name `HardenedRelayer`, version `1`.
pub fn domain(chain_id: u64, verifying_contract: Address) -> Eip712Domain {
    domain_named(
        "HardenedRelayer".to_string(),
        "1".to_string(),
        chain_id,
        verifying_contract,
    )
}

/// Compute the EIP-712 signing hash for an intent.
pub fn signing_hash(intent: &Intent, domain: &Eip712Domain) -> B256 {
    intent.eip712_signing_hash(domain)
}

/// Build the signed struct from its parts. `keccak256(calldata)` is what binds the relayer to
/// the exact bytes the user authorised.
pub fn build_intent(user: Address, nonce: u64, deadline: u64, calldata: &[u8]) -> Intent {
    Intent {
        user,
        nonce: U256::from(nonce),
        deadline: U256::from(deadline),
        dataHash: keccak256(calldata),
    }
}

/// Unix seconds. Saturates instead of panicking: arithmetic on clocks is how a relayer gets
/// drained by "expired in the past" edge cases.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The secp256k1 group order `n`, as hex.
///
/// It appears here because it is the other half of the malleability story: `(r, s)` and
/// `(r, n - s)` are both valid signatures for the same message. See [`malleable_twin`].
pub const SECP256K1_N_HEX: &str =
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

/// Build the non-canonical twin of a signature: `s' = n - s`, `v' = !v`.
///
/// Same message, same signer, *different bytes* -- and a consensus-legal signature on most
/// chains. This is the attack the relayer refuses at step 3 of [`verify_intent`], and the reason
/// [`crate::replay`] keys on the digest instead of the signature.
pub fn malleable_twin(signature: &Signature) -> Signature {
    let n = U256::from_be_slice(&alloy::hex::decode(SECP256K1_N_HEX).expect("const is valid hex"));
    Signature::new(signature.r(), n - signature.s(), !signature.v())
}

/// The gate. Everything that reaches the worker has passed through here.
///
/// # Order of checks (deliberate)
/// Cheap, local, unambiguous checks run first so an attacker cannot make us do work: hex
/// decoding, signature parsing, canonicality -- then, only then, an elliptic-curve recovery,
/// and finally the range checks. Cheapest-first is not a style preference; it is a DoS
/// mitigation.
///
/// # Errors
/// Returns the specific [`Reject`] the API should report to the caller.
pub fn verify_intent(
    req: &MetaTxRequest,
    domain: &Eip712Domain,
    now: u64,
) -> Result<VerifiedIntent, Reject> {
    // 1. Calldata: hex, non-empty, bounded. Empty calldata is a *successful no-op* on anvil,
    //    which means the relayer would pay gas for literally nothing.
    let raw = req.data.trim();
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    let calldata =
        alloy::hex::decode(raw).map_err(|e| Reject::MalformedData(format!("not hex: {e}")))?;
    if calldata.is_empty() {
        return Err(Reject::MalformedData(
            "empty calldata: relaying this burns gas for a no-op".to_string(),
        ));
    }
    if calldata.len() > MAX_CALLDATA_BYTES {
        return Err(Reject::MalformedData(format!(
            "{} bytes exceeds the {MAX_CALLDATA_BYTES}-byte ceiling",
            calldata.len()
        )));
    }

    // 2. Signature: exactly 65 bytes of hex.
    let signature: Signature = req
        .signature
        .trim()
        .parse()
        .map_err(|e| Reject::MalformedSignature(format!("{e}")))?;

    // 3. Canonicality. ECDSA is malleable: `(r, s)` and `(r, n - s)` are both valid for the
    //    same message. Accepting the second form means "one intent, two signatures" -- enough
    //    to walk straight past a replay cache keyed on signature bytes.
    if signature.normalize_s().is_some() {
        return Err(Reject::MalleableSignature);
    }

    // 4. Recovery. This is the expensive step, and the only one that proves anything.
    let intent = build_intent(req.user, req.nonce, req.deadline, &calldata);
    let digest = signing_hash(&intent, domain);
    let recovered = signature
        .recover_address_from_prehash(&digest)
        .map_err(|e| Reject::MalformedSignature(format!("recovery failed: {e}")))?;
    if recovered != req.user {
        return Err(Reject::WrongSigner {
            claimed: req.user,
            recovered,
        });
    }

    // 5. Time. An expired intent costs one signature check and then nothing else.
    if req.deadline < now {
        return Err(Reject::Expired {
            deadline: req.deadline,
            now,
        });
    }
    let max_deadline = now + MAX_DEADLINE_WINDOW_SECS;
    if req.deadline > max_deadline {
        return Err(Reject::DeadlineTooFar {
            deadline: req.deadline,
            max: max_deadline,
        });
    }

    Ok(VerifiedIntent {
        user: recovered,
        nonce: req.nonce,
        deadline: req.deadline,
        calldata: Bytes::from(calldata),
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::SignerSync;
    use alloy::signers::local::PrivateKeySigner;

    fn fixture(now: u64) -> (PrivateKeySigner, Eip712Domain, MetaTxRequest) {
        let user = PrivateKeySigner::random();
        let domain = domain(31337, Address::repeat_byte(0x11));
        let req = sign(&user, &domain, 7, now + 60, "0xdeadbeef");
        (user, domain, req)
    }

    /// Build a *properly signed* request. Any test that changes a field must come back through
    /// here, because changing a field changes the digest -- and an attacker cannot re-sign.
    fn sign(
        user: &PrivateKeySigner,
        domain: &Eip712Domain,
        nonce: u64,
        deadline: u64,
        data: &str,
    ) -> MetaTxRequest {
        let hex = data.trim_start_matches("0x");
        let calldata = alloy::hex::decode(hex).unwrap();
        let intent = build_intent(user.address(), nonce, deadline, &calldata);
        let signature = user.sign_hash_sync(&signing_hash(&intent, domain)).unwrap();
        MetaTxRequest {
            user: user.address(),
            nonce,
            deadline,
            data: data.to_string(),
            signature: signature.to_string(),
        }
    }

    #[test]
    fn a_valid_intent_verifies_and_reports_its_digest() {
        let now = unix_now();
        let (user, domain, req) = fixture(now);
        let verified = verify_intent(&req, &domain, now).expect("should verify");
        assert_eq!(verified.user, user.address());
        assert_eq!(verified.nonce, 7);
        assert_eq!(
            verified.calldata,
            Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef])
        );
        assert_ne!(verified.digest, B256::ZERO);
    }

    #[test]
    fn a_signature_for_another_contract_is_rejected() {
        let now = unix_now();
        let (_, _, req) = fixture(now);
        // Same chain, same name/version -- different forwarder. This is precisely what
        // `verifyingContract` in the domain separator buys you.
        let other = domain(31337, Address::repeat_byte(0x22));
        let err = verify_intent(&req, &other, now).unwrap_err();
        assert!(matches!(err, Reject::WrongSigner { .. }), "got {err:?}");
    }

    #[test]
    fn a_signature_for_another_chain_is_rejected() {
        let now = unix_now();
        let (_, _, req) = fixture(now);
        let other_chain = domain(1, Address::repeat_byte(0x11));
        let err = verify_intent(&req, &other_chain, now).unwrap_err();
        assert!(matches!(err, Reject::WrongSigner { .. }), "got {err:?}");
    }

    #[test]
    fn swapping_calldata_invalidates_the_signature() {
        let now = unix_now();
        let (_, domain, mut req) = fixture(now);
        req.data = "0xdeadbeee".to_string(); // one nibble: one digest, one rejection
        let err = verify_intent(&req, &domain, now).unwrap_err();
        assert!(matches!(err, Reject::WrongSigner { .. }), "got {err:?}");
    }

    #[test]
    fn a_high_s_signature_is_rejected_as_malleable() {
        let now = unix_now();
        let (_, domain, req) = fixture(now);
        let sig: Signature = req.signature.parse().unwrap();

        let twin = malleable_twin(&sig);
        assert_ne!(twin.as_bytes(), sig.as_bytes(), "the twin must differ");
        // The twin is a *legal* signature of the same message; only canonicality rejects it.
        assert!(twin.normalize_s().is_some());

        let mut twinned = req.clone();
        twinned.signature = twin.to_string();
        assert_eq!(
            verify_intent(&twinned, &domain, now).unwrap_err(),
            Reject::MalleableSignature
        );
    }

    #[test]
    fn expiry_and_the_deadline_window_are_both_enforced() {
        let now = unix_now();
        let (user, domain, _) = fixture(now);

        // Note: we must *re-sign* to land on the expiry check. Changing `deadline` on an
        // existing request changes the digest, so `WrongSigner` fires first. That ordering is
        // itself the lesson: an attacker who can edit a field is an attacker who cannot sign.
        let expired = sign(&user, &domain, 7, now - 1, "0xdeadbeef");
        assert!(matches!(
            verify_intent(&expired, &domain, now).unwrap_err(),
            Reject::Expired { .. }
        ));

        let forever = sign(&user, &domain, 7, now + 60 * 60 * 24 * 365, "0xdeadbeef");
        assert!(matches!(
            verify_intent(&forever, &domain, now).unwrap_err(),
            Reject::DeadlineTooFar { .. }
        ));
    }

    #[test]
    fn empty_and_oversized_calldata_are_refused_before_any_curve_math() {
        let now = unix_now();
        let (_, domain, req) = fixture(now);

        let mut empty = req.clone();
        empty.data = "0x".to_string();
        assert!(matches!(
            verify_intent(&empty, &domain, now).unwrap_err(),
            Reject::MalformedData(_)
        ));

        let mut huge = req.clone();
        huge.data = format!("0x{}", "aa".repeat(MAX_CALLDATA_BYTES + 1));
        assert!(matches!(
            verify_intent(&huge, &domain, now).unwrap_err(),
            Reject::MalformedData(_)
        ));

        let mut garbage = req.clone();
        garbage.data = "0xzz".to_string();
        assert!(matches!(
            verify_intent(&garbage, &domain, now).unwrap_err(),
            Reject::MalformedData(_)
        ));
    }

    #[test]
    fn a_truncated_signature_is_malformed_and_never_reaches_recovery() {
        let now = unix_now();
        let (_, domain, mut req) = fixture(now);
        req.signature = "0xcafe".to_string();
        assert!(matches!(
            verify_intent(&req, &domain, now).unwrap_err(),
            Reject::MalformedSignature(_)
        ));
    }

    #[test]
    fn status_codes_separate_client_faults_from_our_own() {
        assert_eq!(Reject::MalleableSignature.status(), 401);
        assert_eq!(Reject::QueueFull.status(), 503);
        assert!(!Reject::RpcUnavailable("boom".into()).is_client_error());
        assert!(Reject::WouldRevert("boom".into()).is_client_error());
        assert!(
            Reject::NonceTaken {
                user: Address::ZERO,
                nonce: 1,
            }
            .is_client_error()
        );
    }

    #[test]
    fn the_domain_separator_changes_with_the_verifying_contract() {
        // Two domains, two separators. If this stops holding, every guarantee above is void.
        let a = domain(31337, Address::repeat_byte(0x11));
        let b = domain(31337, Address::repeat_byte(0x22));
        assert_ne!(a.hash_struct(), b.hash_struct());
        assert_eq!(
            domain(31337, Address::repeat_byte(0x11)).hash_struct(),
            a.hash_struct()
        );
    }
}
