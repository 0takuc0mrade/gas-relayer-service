//! The relayer's key is the "God Key". Treat every line of this file as load-bearing.
//!
//! # The three rules
//!
//! 1. **Never in a global.** Statics live for the whole process and are readable by every
//!    thread (and by every dependency you will ever add). The key is loaded on the stack, in
//!    `main`, and dropped before the first request is served.
//! 2. **Never printable.** A `#[derive(Debug)]` on a struct holding a key is a key leak waiting
//!    for a `println!("{state:?}")`. [`RelayerKey`] has a hand-written `Debug` that redacts.
//! 3. **Wiped on drop.** The bytes live in a [`Zeroizing`] buffer, so when this value goes out
//!    of scope the memory is overwritten with zeroes instead of being handed back to the
//!    allocator to be read later by whoever reuses the page.
//!
//! # Honest limits (say these out loud in class)
//!
//! * Rust may have copied the bytes elsewhere before we ever saw them: the environment block,
//!   the `.env` file on disk, the shell's history, and the operating system's page cache.
//! * [`PrivateKeySigner`] keeps its own copy internally and does not expose a wipe API.
//! * Therefore the real answer for production is **not** "a safer struct". It is: never let the
//!   key enter the process at all -- put it in a KMS/HSM (AWS KMS, GCP KMS, Fireblocks, a
//!   Ledger behind `alloy-signer-ledger`) and ask the boundary to sign a digest. What this
//!   module buys you is: the key is in exactly one place we control, it never reaches a log,
//!   and our copy is gone when the process exits.

use alloy::network::EthereumWallet;
use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use core::fmt;
use zeroize::{Zeroize, Zeroizing};

/// Environment variable the key is read from.
pub const KEY_ENV: &str = "PRIVATE_KEY";

/// Why the key could not be loaded. Deliberately does not echo the offending bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// The variable is set but empty.
    Empty,
    /// The value is not 32 bytes of hex.
    Malformed,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "{KEY_ENV} is set but empty"),
            // Note: the *value* is never interpolated. Error messages travel to logs and
            // crash reporters; secrets do not belong in them.
            Self::Malformed => write!(f, "{KEY_ENV} must be 32 bytes of hex (64 characters)"),
        }
    }
}

impl std::error::Error for KeyError {}

/// A live private key, wiped when dropped.
pub struct RelayerKey {
    /// `Zeroizing` zeroes the buffer on drop, including on early return and on panic-unwind.
    key: Zeroizing<Vec<u8>>,
}

impl RelayerKey {
    /// Load from `PRIVATE_KEY`.
    ///
    /// Returns `Ok(None)` when the variable is unset, so the caller can decide whether that is
    /// fatal (production) or a throwaway key is acceptable (this lab).
    ///
    /// # Errors
    /// [`KeyError`] when the variable is present but unusable.
    pub fn from_env() -> Result<Option<Self>, KeyError> {
        match std::env::var(KEY_ENV) {
            Err(_) => Ok(None),
            Ok(raw) if raw.trim().is_empty() => Err(KeyError::Empty),
            Ok(raw) => Self::from_hex(&raw).map(Some),
        }
    }

    /// Parse `0x`-prefixed (or bare) 32-byte hex.
    ///
    /// # Errors
    /// [`KeyError::Malformed`] when the length or the hex is wrong.
    pub fn from_hex(raw: &str) -> Result<Self, KeyError> {
        let trimmed = raw.trim();
        let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        // `hex::decode` already gives us an owned `Vec<u8>`; wrap it immediately so there is no
        // unwiped intermediate copy of the secret on the stack.
        let decoded = Zeroizing::new(alloy::hex::decode(hex_str).map_err(|_| KeyError::Malformed)?);
        if decoded.len() != 32 {
            return Err(KeyError::Malformed);
        }
        // Validate by building a signer once: catches "32 bytes of hex, but not a valid scalar".
        PrivateKeySigner::from_slice(&decoded).map_err(|_| KeyError::Malformed)?;
        Ok(Self { key: decoded })
    }

    /// A throwaway key for the lab, when no `PRIVATE_KEY` is configured.
    pub fn generate() -> Self {
        let signer = PrivateKeySigner::random();
        Self::from_hex(&signer.to_bytes().to_string())
            .expect("a freshly generated key is always valid")
    }

    /// The relayer's public address. Safe to log, print, and hard-code.
    pub fn address(&self) -> Address {
        self.ephemeral_signer().address()
    }

    /// A signer for the duration of one call. The returned value is *not* zeroized -- prefer
    /// [`Self::wallet`] at startup over calling this per request.
    pub fn signer(&self) -> PrivateKeySigner {
        self.ephemeral_signer()
    }

    /// Consume into the wallet the provider needs.
    ///
    /// Call this exactly once, in `main`, then `drop` the [`RelayerKey`] before serving traffic.
    pub fn wallet(&self) -> EthereumWallet {
        EthereumWallet::from(self.ephemeral_signer())
    }

    /// Build a signer from the current buffer.
    fn ephemeral_signer(&self) -> PrivateKeySigner {
        PrivateKeySigner::from_slice(&self.key)
            .expect("validated in from_hex; the buffer is immutable for the value's lifetime")
    }
}

impl fmt::Debug for RelayerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Rule 2. If you ever see a real key in a log, the bug is here.
        f.write_str("RelayerKey(<redacted>)")
    }
}

impl Drop for RelayerKey {
    fn drop(&mut self) {
        // `Zeroizing` would do this anyway; being explicit is how a reader learns that it does.
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANVIL_KEY_0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    #[test]
    fn a_known_key_derives_its_known_address() {
        // anvil's first default account. If this test fails, the key handling is broken.
        let key = RelayerKey::from_hex(ANVIL_KEY_0).unwrap();
        assert_eq!(
            key.address().to_string().to_lowercase(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
    }

    #[test]
    fn the_bare_hex_form_is_accepted_too() {
        let prefixed = RelayerKey::from_hex(ANVIL_KEY_0).unwrap();
        let bare = RelayerKey::from_hex(&ANVIL_KEY_0[2..]).unwrap();
        assert_eq!(prefixed.address(), bare.address());
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let key = RelayerKey::from_hex(ANVIL_KEY_0).unwrap();
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "RelayerKey(<redacted>)");
        // Belt and braces: no 8-character slice of the secret may appear in the output.
        for window in ANVIL_KEY_0.as_bytes()[2..].windows(8) {
            let needle = core::str::from_utf8(window).unwrap();
            assert!(
                !rendered.contains(needle),
                "Debug output leaked a fragment of the key"
            );
        }
    }

    #[test]
    fn malformed_keys_are_refused_without_echoing_them() {
        assert_eq!(RelayerKey::from_hex("0x").unwrap_err(), KeyError::Malformed);
        assert_eq!(
            RelayerKey::from_hex("0xcafe").unwrap_err(),
            KeyError::Malformed
        );
        assert_eq!(
            RelayerKey::from_hex("0xzz").unwrap_err(),
            KeyError::Malformed
        );
        // 32 bytes, but not a valid secp256k1 scalar (the group order itself).
        let n = "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
        assert_eq!(RelayerKey::from_hex(n).unwrap_err(), KeyError::Malformed);

        let err = RelayerKey::from_hex("0xdeadbeef").unwrap_err().to_string();
        assert!(
            !err.contains("deadbeef"),
            "error messages must not leak input: {err}"
        );
    }

    #[test]
    fn a_generated_key_is_usable_and_unique() {
        let a = RelayerKey::generate();
        let b = RelayerKey::generate();
        assert_ne!(a.address(), b.address());
        // Round trip through the wallet path the provider actually uses.
        assert_eq!(a.wallet().default_signer().address(), a.address());
    }
}
