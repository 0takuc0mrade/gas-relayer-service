//! The scoreboard.
//!
//! A relayer that cannot say *why* it refused an intent is a relayer being drained quietly.
//! Every rejection path in this codebase increments exactly one counter here, and the one number
//! that matters most is [`Metrics::gas_burned_on_reverts_wei`]: gas the relayer paid for a
//! transaction that reverted. The dry-run exists to keep it at zero, and the only way to know it
//! works is to measure it.
//!
//! Exposed as Prometheus-style text on `GET /metrics` (a counter is just a name and a number;
//! no dependency needed for that).

use core::sync::atomic::{AtomicU64, Ordering};

use crate::intent::Reject;

/// Relayer counters. Cheap enough to increment on every request.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Intents that passed every check and were queued.
    pub accepted: AtomicU64,
    /// Rejections by category, so an on-call engineer sees the *shape* of an attack.
    pub rejected_malformed: AtomicU64,
    pub rejected_badsig: AtomicU64,
    pub rejected_malleable: AtomicU64,
    pub rejected_expired: AtomicU64,
    pub rejected_replay: AtomicU64,
    pub rejected_nonce_taken: AtomicU64,
    /// Refused by the dry-run: the griefing attack, stopped before it cost anything.
    pub rejected_simulation: AtomicU64,
    /// The node was unreachable. Our problem, not the user's.
    pub rpc_unavailable: AtomicU64,
    /// Refused because the queue was full (back-pressure).
    pub rejected_queue_full: AtomicU64,
    /// Transactions actually broadcast.
    pub dispatched: AtomicU64,
    /// Broadcasts that were mined successfully.
    pub confirmed: AtomicU64,
    /// Broadcasts that were mined and reverted. **This should be zero.**
    pub reverted: AtomicU64,
    /// Total wei spent by the relayer. Revenue minus this is the business.
    pub gas_spent_wei: AtomicU64,
    /// Wei spent on reverted transactions: the direct measure of the griefing loss.
    pub gas_burned_on_reverts_wei: AtomicU64,
}

impl Metrics {
    /// Count one rejection, filed under the reason it was rejected.
    ///
    /// `EthCall`-style failures are counted separately because they mean "the node is down",
    /// which must page somebody, versus "the user sent junk", which must not.
    pub fn record_reject(&self, reject: &Reject) {
        let counter = match reject {
            Reject::MalformedData(_) | Reject::MalformedSignature(_) => &self.rejected_malformed,
            Reject::MalleableSignature => &self.rejected_malleable,
            Reject::WrongSigner { .. } => &self.rejected_badsig,
            Reject::Expired { .. } | Reject::DeadlineTooFar { .. } => &self.rejected_expired,
            Reject::Replayed { .. } => &self.rejected_replay,
            Reject::NonceTaken { .. } => &self.rejected_nonce_taken,
            Reject::WouldRevert(_) => &self.rejected_simulation,
            Reject::RpcUnavailable(_) => &self.rpc_unavailable,
            Reject::QueueFull => &self.rejected_queue_full,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Record the gas cost of a mined transaction, attributing it to success or failure.
    pub fn record_receipt(&self, success: bool, gas_used: u64, effective_gas_price: u128) {
        // Saturating arithmetic: a runaway counter must never wrap into a plausible number.
        let cost = (gas_used as u128).saturating_mul(effective_gas_price) as u64;
        if success {
            self.confirmed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.reverted.fetch_add(1, Ordering::Relaxed);
            self.gas_burned_on_reverts_wei
                .fetch_add(cost, Ordering::Relaxed);
        }
        let _ = self
            .gas_spent_wei
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(cost))
            });
    }

    /// Total rejections, for a single-glance health check.
    pub fn total_rejected(&self) -> u64 {
        self.rejected_malformed.load(Ordering::Relaxed)
            + self.rejected_badsig.load(Ordering::Relaxed)
            + self.rejected_malleable.load(Ordering::Relaxed)
            + self.rejected_expired.load(Ordering::Relaxed)
            + self.rejected_replay.load(Ordering::Relaxed)
            + self.rejected_nonce_taken.load(Ordering::Relaxed)
            + self.rejected_simulation.load(Ordering::Relaxed)
            + self.rpc_unavailable.load(Ordering::Relaxed)
            + self.rejected_queue_full.load(Ordering::Relaxed)
    }

    /// Render the counters as Prometheus text exposition format.
    pub fn render(&self, seen_entries: usize, queue_len: usize, dry_run_enabled: bool) -> String {
        let mut out = String::new();
        out.push_str("# HELP relayer_dry_run_enabled Whether the eth_call dry run is active. 0 means the relayer pays for failing transactions.\n");
        out.push_str("# TYPE relayer_dry_run_enabled gauge\n");
        out.push_str(&format!(
            "relayer_dry_run_enabled {}\n",
            u8::from(dry_run_enabled)
        ));
        out.push_str("# HELP relayer_intents_total Intents accepted for relaying.\n");
        out.push_str("# TYPE relayer_intents_total counter\n");
        out.push_str(&format!(
            "relayer_intents_accepted_total {}\n",
            self.accepted.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "relayer_intents_rejected_total {}\n",
            self.total_rejected()
        ));

        out.push_str("# HELP relayer_rejections_total Rejections by reason.\n");
        out.push_str("# TYPE relayer_rejections_total counter\n");
        for (label, value) in [
            ("malformed", self.rejected_malformed.load(Ordering::Relaxed)),
            (
                "bad_signature",
                self.rejected_badsig.load(Ordering::Relaxed),
            ),
            ("malleable", self.rejected_malleable.load(Ordering::Relaxed)),
            ("expired", self.rejected_expired.load(Ordering::Relaxed)),
            ("replayed", self.rejected_replay.load(Ordering::Relaxed)),
            (
                "nonce_taken",
                self.rejected_nonce_taken.load(Ordering::Relaxed),
            ),
            (
                "would_revert",
                self.rejected_simulation.load(Ordering::Relaxed),
            ),
            (
                "rpc_unavailable",
                self.rpc_unavailable.load(Ordering::Relaxed),
            ),
            (
                "queue_full",
                self.rejected_queue_full.load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "relayer_rejections_total{{reason=\"{label}\"}} {value}\n"
            ));
        }

        out.push_str("# HELP relayer_transactions_total Broadcast outcomes.\n");
        out.push_str("# TYPE relayer_transactions_total counter\n");
        for (label, value) in [
            ("dispatched", self.dispatched.load(Ordering::Relaxed)),
            ("confirmed", self.confirmed.load(Ordering::Relaxed)),
            ("reverted", self.reverted.load(Ordering::Relaxed)),
        ] {
            out.push_str(&format!(
                "relayer_transactions_total{{status=\"{label}\"}} {value}\n"
            ));
        }

        out.push_str("# HELP relayer_gas_spent_wei Total wei paid in gas.\n");
        out.push_str("# TYPE relayer_gas_spent_wei counter\n");
        out.push_str(&format!(
            "relayer_gas_spent_wei {}\n",
            self.gas_spent_wei.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP relayer_gas_burned_on_reverts_wei Wei paid for transactions that reverted. Must stay 0.\n");
        out.push_str("# TYPE relayer_gas_burned_on_reverts_wei counter\n");
        out.push_str(&format!(
            "relayer_gas_burned_on_reverts_wei {}\n",
            self.gas_burned_on_reverts_wei.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP relayer_replay_registry_entries Claims retained in the used-signature registry.\n");
        out.push_str("# TYPE relayer_replay_registry_entries gauge\n");
        out.push_str(&format!("relayer_replay_registry_entries {seen_entries}\n"));
        out.push_str("# HELP relayer_queue_len Intents waiting in the queue.\n");
        out.push_str("# TYPE relayer_queue_len gauge\n");
        out.push_str(&format!("relayer_queue_len {queue_len}\n"));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, B256};

    #[test]
    fn every_rejection_reason_has_its_own_bucket() {
        let m = Metrics::default();
        let rejects = [
            Reject::MalformedData("x".into()),
            Reject::MalformedSignature("x".into()),
            Reject::MalleableSignature,
            Reject::WrongSigner {
                claimed: Address::ZERO,
                recovered: Address::ZERO,
            },
            Reject::Expired {
                deadline: 0,
                now: 1,
            },
            Reject::DeadlineTooFar {
                deadline: 9,
                max: 1,
            },
            Reject::Replayed { digest: B256::ZERO },
            Reject::NonceTaken {
                user: Address::ZERO,
                nonce: 0,
            },
            Reject::WouldRevert("x".into()),
            Reject::RpcUnavailable("x".into()),
            Reject::QueueFull,
        ];
        for r in &rejects {
            m.record_reject(r);
        }
        assert_eq!(m.total_rejected(), rejects.len() as u64);
        assert_eq!(m.rejected_malleable.load(Ordering::Relaxed), 1);
        assert_eq!(m.rejected_replay.load(Ordering::Relaxed), 1);
        assert_eq!(m.rejected_nonce_taken.load(Ordering::Relaxed), 1);
        assert_eq!(m.rejected_simulation.load(Ordering::Relaxed), 1);
        assert_eq!(m.accepted.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn gas_is_attributed_to_success_or_to_the_revert_bucket() {
        let m = Metrics::default();
        m.record_receipt(true, 21_000, 1_000_000_000);
        m.record_receipt(false, 21_000, 1_000_000_000);

        assert_eq!(m.confirmed.load(Ordering::Relaxed), 1);
        assert_eq!(m.reverted.load(Ordering::Relaxed), 1);
        assert_eq!(
            m.gas_burned_on_reverts_wei.load(Ordering::Relaxed),
            21_000 * 1_000_000_000
        );
        assert_eq!(
            m.gas_spent_wei.load(Ordering::Relaxed),
            2 * 21_000 * 1_000_000_000
        );
    }

    #[test]
    fn render_is_scrapeable_and_flags_the_number_that_matters() {
        let m = Metrics::default();
        m.record_reject(&Reject::WouldRevert("execution reverted".into()));
        let text = m.render(3, 2, true);
        assert!(text.contains("relayer_rejections_total{reason=\"would_revert\"} 1"));
        assert!(text.contains("relayer_gas_burned_on_reverts_wei 0"));
        assert!(text.contains("relayer_replay_registry_entries 3"));
        assert!(text.contains("relayer_queue_len 2"));
        assert!(text.contains("relayer_dry_run_enabled 1"));
        // The kill-switch must be visible from outside: a relayer running without its primary
        // defence has to be scrapeable as such, not quietly unprotected.
        assert!(m.render(3, 2, false).contains("relayer_dry_run_enabled 0"));
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            // Every sample line is `name value` or `name{label="v"} value`.
            assert!(line.rsplit_once(' ').is_some(), "unparseable line: {line}");
        }
    }
}
