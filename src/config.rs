//! Relayer configuration, loaded from the environment.
//!
//! Two things worth noticing:
//!
//! 1. **`load_dotenv` is 20 lines instead of a dependency.** Students were asked (Day 1
//!    exercise #2) to make `.env` load automatically. Here it is, in full, with no crate.
//! 2. **`Config` deliberately does not contain the private key.** A config struct gets
//!    `Debug`-printed, `Clone`d into closures, and logged on startup. The "God Key" is
//!    loaded by [`crate::secure_key::RelayerKey`] and by nothing else.

use std::env;

use alloy::primitives::Address;

/// Where the relayer listens for intents.
pub const DEFAULT_BIND_ADDR: &str = "127.0.0.1:3000";
/// A stock anvil node.
pub const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8545";
/// `FORWARDER_ADDRESS` default: the zero address is a *successful no-op* on anvil, so the
/// whole pipeline is demonstrable before anyone has deployed an EIP-2771 forwarder.
pub const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

/// Read `.env` into the process environment. Real environment variables always win.
///
/// Deliberately dumb: no interpolation, no `export`, no multi-line values. Those are the
/// reasons to reach for `dotenvy` in production; for this lab, dumb is auditable.
pub fn load_dotenv() {
    let Ok(text) = std::fs::read_to_string(".env") else {
        return; // no `.env` is fine — the shell may already export everything.
    };

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || env::var_os(key).is_some() {
            continue; // never let a stray file shadow the real environment
        }
        let value = value.trim().trim_matches('"').trim_matches('\'');
        // SAFETY: single-threaded, called before any worker is spawned.
        unsafe { env::set_var(key, value) };
    }
}

/// Everything the relayer needs except the key.
#[derive(Clone, Debug)]
pub struct Config {
    /// Address the API binds to.
    pub bind_addr: String,
    /// The node we *simulate* against — must be a full node with state.
    pub rpc_url: String,
    /// Where transactions are actually broadcast to. Equal to `rpc_url` unless a private
    /// mempool is configured (Part 3).
    pub broadcast_url: String,
    /// `true` when `PRIVATE_RPC_URL` / `FLASHBOTS_RPC_URL` is set.
    pub private_mempool: bool,
    /// The trusted forwarder every intent is relayed to. Bound into the EIP-712 domain.
    pub forwarder: Address,
    /// EIP-712 domain name.
    pub eip712_name: String,
    /// EIP-712 domain version.
    pub eip712_version: String,
    /// Upper bound on the replay registry, so an attacker cannot grow it without limit.
    pub max_seen_entries: usize,
    /// Depth of the in-process intent queue.
    pub queue_capacity: usize,
    /// Wait for receipts so `metrics` can report real gas burned.
    pub await_receipts: bool,
    /// **Lab switch.** When `false` (`DRY_RUN=0`), the `eth_call` dry run is skipped entirely and
    /// the relayer buys failing transactions exactly like the Day 2/3 version did.
    ///
    /// It exists so the Part 1 demo can show the *loss* — gas burned on reverts, a non-zero number
    /// — and then show it go back to zero. A defence you cannot switch off is a defence you cannot
    /// demonstrate, and a defence you cannot demonstrate is a defence you will not trust.
    pub dry_run: bool,
    /// **Lab switch.** When set (`GAS_LIMIT=100000`), every relayer transaction carries this gas
    /// limit instead of letting Alloy estimate one.
    ///
    /// This matters more than it looks. Alloy's default filler calls `eth_estimateGas` before
    /// sending, and **estimation itself reverts**: a node asked to estimate a call that fails
    /// answers with the revert, so a reverting transaction never gets broadcast at all. That is a
    /// free dry run hiding inside your dependency — worth knowing, and worth not relying on:
    /// estimation is *one* extra round trip, it does not classify the failure for you, and it
    /// happens after your queue slot is consumed. Setting an explicit gas limit (as a production
    /// relayer does, to bound its worst case) removes that accidental protection, which is exactly
    /// what makes the Part 1 "before" demo honest.
    pub gas_limit: Option<u64>,
}

impl Config {
    /// Read the whole configuration from the environment.
    ///
    /// # Errors
    /// Returns a human-readable message if a variable is present but unparseable.
    pub fn from_env() -> Result<Self, String> {
        let rpc_url = env_or("RPC_URL", DEFAULT_RPC_URL);
        let private = env_opt("PRIVATE_RPC_URL").or_else(|| env_opt("FLASHBOTS_RPC_URL"));
        let (broadcast_url, private_mempool) = match &private {
            Some(url) => (url.clone(), true),
            None => (rpc_url.clone(), false),
        };

        let forwarder_raw = env_or("FORWARDER_ADDRESS", ZERO_ADDRESS);
        let forwarder = forwarder_raw
            .parse::<Address>()
            .map_err(|e| format!("FORWARDER_ADDRESS={forwarder_raw:?} is not an address: {e}"))?;

        Ok(Self {
            bind_addr: env_or("BIND_ADDR", DEFAULT_BIND_ADDR),
            rpc_url,
            broadcast_url,
            private_mempool,
            forwarder,
            eip712_name: env_or("EIP712_NAME", "HardenedRelayer"),
            eip712_version: env_or("EIP712_VERSION", "1"),
            max_seen_entries: env_parse("MAX_SEEN_ENTRIES", 100_000)?,
            queue_capacity: env_parse("QUEUE_CAPACITY", 100)?,
            await_receipts: env_bool("AWAIT_RECEIPTS", true)?,
            dry_run: env_bool("DRY_RUN", true)?,
            gas_limit: env_opt("GAS_LIMIT")
                .map(|raw| {
                    raw.parse::<u64>()
                        .map_err(|e| format!("GAS_LIMIT={raw:?} is not a number: {e}"))
                })
                .transpose()?,
        })
    }
}

/// `env::var` with a fallback.
pub fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

/// `env::var` as an optional non-empty value.
pub fn env_opt(key: &str) -> Option<String> {
    env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// Parse an integer or boolean variable, with a fallback when it is unset.
///
/// A variable that is *set but wrong* is a hard error: silently defaulting a security
/// knob is how relayers get drained.
pub fn env_parse<T>(key: &str, default: T) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env_opt(key) {
        None => Ok(default),
        Some(raw) => raw
            .parse::<T>()
            .map_err(|e| format!("{key}={raw:?} could not be parsed: {e}")),
    }
}

/// `AWAIT_RECEIPTS` accepts the usual truthy spellings; `env_parse` handles `true`/`false`,
/// this wrapper accepts the rest.
pub fn parse_bool(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Boolean variant of [`env_parse`], used by the metrics/receipt knobs.
pub fn env_bool(key: &str, default: bool) -> Result<bool, String> {
    match env_opt(key) {
        None => Ok(default),
        Some(raw) => parse_bool(&raw).ok_or_else(|| format!("{key}={raw:?} is not a boolean")),
    }
}
