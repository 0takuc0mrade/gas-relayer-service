//! Day 4 lab: **the hardened relayer**.
//!
//! Compare this with the Day 2/3 version. Same shape -- axum in, queue in the middle, one
//! sequential worker out -- with six additions, each of which closes a specific way to steal
//! from the relayer:
//!
//! ```text
//!  POST /submit
//!      |
//!      v
//!  [1] verify_intent()      EIP-712: recovery, canonicality, deadline window, calldata bound
//!      |
//!      v
//!  [2] ReplayGuard::claim() check-and-insert under ONE lock: digest + (user, nonce)
//!      |
//!      v
//!  [3] mpsc queue            back-pressure instead of unbounded growth
//!      |
//!      v
//!  [4] dry_run(eth_call)     THE PRIMARY DEFENCE: never pay for a transaction that reverts
//!      |
//!      v
//!  [5] send_transaction()    to the *private* mempool when one is configured (Part 3)
//!      |
//!      v
//!  [6] receipts -> metrics   gas burned on reverts must stay at zero, and we can prove it
//! ```
//!
//! Run it:
//! ```text
//! anvil                                            # terminal 1
//! cargo run                                        # terminal 2 (this file)
//! cargo run --bin simulator -- honest 20           # terminal 3
//! cargo run --bin simulator -- hacker mixed 30     # terminal 3, the Part 4 game
//! curl 127.0.0.1:3000/metrics                      # terminal 4, the scoreboard
//! ```

use std::sync::Arc;
use std::sync::atomic::Ordering;

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::sol_types::Eip712Domain;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use tokio::sync::mpsc;

use traffic_simulator::config::{Config, load_dotenv};
use traffic_simulator::dry_run::{Simulation, dry_run};
use traffic_simulator::intent::{
    MetaTxRequest, Reject, VerifiedIntent, domain_named, unix_now, verify_intent,
};
use traffic_simulator::metrics::Metrics;
use traffic_simulator::replay::ReplayGuard;
use traffic_simulator::secure_key::RelayerKey;

/// HTTP-facing state. Note what is **not** here: the private key. It was wiped before `main`
/// finished wiring the provider.
struct AppState {
    /// Hand-off to the single sequential worker.
    tx_sender: mpsc::Sender<VerifiedIntent>,
    /// Configured queue depth, so `/metrics` can report how full the queue is.
    queue_capacity: usize,
    /// The used-signature registry (Part 2).
    replay: Arc<ReplayGuard>,
    /// The EIP-712 domain every intent must have been signed against.
    domain: Eip712Domain,
    /// Counters, so the relayer can be audited from outside.
    metrics: Arc<Metrics>,
    /// Read-only node used for `eth_call`. Type-erased (`DynProvider`) because the concrete
    /// Alloy provider type is a stack of filler generics that nothing should have to spell out.
    /// The worker gets its own clone and re-simulates at the last moment.
    sim_provider: DynProvider,
    /// Address every intent is relayed to.
    forwarder: Address,
    /// Our own address, so simulations run with `msg.sender = relayer`.
    relayer: Address,
    /// `false` only when `DRY_RUN=0` (the Part 1 `before` demo).
    dry_run_enabled: bool,
    /// Explicit gas limit, when `GAS_LIMIT` is set. Also suppresses `eth_estimateGas`.
    gas_limit: Option<u64>,
}

/// Translate an intent into the on-chain call it becomes: `to = trusted forwarder`,
/// `input = the user's calldata`, `from = relayer` (so `msg.sender`-dependent logic simulates
/// correctly and the node charges the right account for a dry-run that never happens).
///
/// When `gas_limit` is set, the transaction carries it explicitly. Alloy's fillers only fill what
/// is *missing*, so an explicit limit also means "do not call `eth_estimateGas`" — which is how a
/// production relayer bounds its worst-case loss, and how the lab demonstrates what happens when
/// the dry run is switched off.
fn build_call(
    forwarder: Address,
    relayer: Address,
    gas_limit: Option<u64>,
    intent: &VerifiedIntent,
) -> TransactionRequest {
    let request = TransactionRequest::default()
        .with_from(relayer)
        .with_to(forwarder)
        .with_input(Bytes::clone(&intent.calldata));
    match gas_limit {
        Some(limit) => request.with_gas_limit(limit),
        None => request,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    load_dotenv();
    let config = Config::from_env()?;

    // ---------------------------------------------------------------------------------
    // Part 2b: the God Key.
    //
    // It is loaded here, on the stack, converted into the wallet the provider needs, and
    // then explicitly dropped -- which zeroes the buffer. It never enters `AppState`, never
    // becomes a `static`, and never appears in a log line (see `secure_key::RelayerKey`).
    // ---------------------------------------------------------------------------------
    let key = match RelayerKey::from_env()? {
        Some(key) => key,
        None => {
            eprintln!(
                "⚠️  PRIVATE_KEY is not set. Generating a THROWAWAY key for this run.\n   \
                 Production relayers load this from a KMS/HSM and never from a file."
            );
            RelayerKey::generate()
        }
    };
    let relayer = key.address();
    let wallet = key.wallet();
    drop(key); // wipe our copy before a single request is served

    // ---------------------------------------------------------------------------------
    // Part 3: two providers, on purpose.
    //
    //  * `sim_provider`  -- a plain full node. `eth_call` needs real state, so the public node
    //                       is the only thing that can answer it.
    //  * `tx_provider`   -- where transactions are broadcast. Identical to the public node
    //                       unless PRIVATE_RPC_URL/FLASHBOTS_RPC_URL is set, in which case the
    //                       signed transaction never enters the public mempool.
    //
    // Building both *before* spawning the worker means a wrong key or an unreachable RPC
    // fails loudly at startup instead of silently killing a background task.
    // ---------------------------------------------------------------------------------
    let sim_provider = ProviderBuilder::new().connect(&config.rpc_url).await?;
    let tx_provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(&config.broadcast_url)
        .await?;

    // The chain id is bound into the EIP-712 domain, so a signature harvested on another
    // chain cannot be replayed here.
    let chain_id = sim_provider.get_chain_id().await?;

    // A forwarder with **no code** is the lab's default (the zero address). Sending calldata to an
    // account with no code *succeeds* and does nothing: every relay is confirmed, no user state
    // changes, and nothing is forwarded. That is exactly what you want before you have deployed
    // anything, and exactly the failure you never notice in production — so check, and say so.
    let forwarder_is_contract = !sim_provider.get_code_at(config.forwarder).await?.is_empty();

    // Two clones of one connection: one for the request handler (fast, synchronous rejections),
    // one for the worker (last-chance check). `DynProvider` is `Arc<dyn Provider>` internally, so
    // cloning is cheap and both share the same connection pool.
    let sim_for_worker = sim_provider.clone().erased();
    let sim_for_state = sim_provider.erased();
    let eip712_domain = domain_named(
        config.eip712_name.clone(),
        config.eip712_version.clone(),
        chain_id,
        config.forwarder,
    );

    // ---------------------------------------------------------------------------------
    // Part 2a: the used-signature registry.
    // ---------------------------------------------------------------------------------
    let replay = Arc::new(ReplayGuard::new(config.max_seen_entries));
    let metrics = Arc::new(Metrics::default());

    // Bounded queue: 100 intents in flight by default. A full queue returns 503 instead of
    // letting memory grow until the box dies.
    let (tx_sender, tx_receiver) = mpsc::channel::<VerifiedIntent>(config.queue_capacity);
    let queue_capacity = config.queue_capacity;

    banner(&config, relayer, chain_id, forwarder_is_contract);

    // ---------------------------------------------------------------------------------
    // The worker: sequential, and the reason is nonces. One transaction at a time in arrival
    // order keeps `nonce` monotonic without any fancy nonce manager.
    // ---------------------------------------------------------------------------------
    let worker_metrics = Arc::clone(&metrics);
    let worker_config = config.clone();
    let worker = tokio::spawn(async move {
        let mut tx_receiver = tx_receiver;
        while let Some(intent) = tx_receiver.recv().await {
            process(
                intent,
                &sim_for_worker,
                &tx_provider,
                &worker_config,
                &worker_metrics,
                relayer,
            )
            .await;
        }
        println!("📭 queue drained and closed -- worker exiting");
    });

    // ---------------------------------------------------------------------------------
    // The API.
    // ---------------------------------------------------------------------------------
    let state = Arc::new(AppState {
        tx_sender,
        queue_capacity,
        replay,
        domain: eip712_domain,
        metrics,
        sim_provider: sim_for_state,
        forwarder: config.forwarder,
        relayer,
        dry_run_enabled: config.dry_run,
        gas_limit: config.gas_limit,
    });
    let app = Router::new()
        .route("/submit", post(submit_handler))
        .route("/domain", get(domain_handler))
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .with_state(Arc::clone(&state));

    let listener = tokio::net::TcpListener::bind(&config.bind_addr)
        .await
        .map_err(|e| {
            format!(
                "cannot bind {}: {e}\n   is another relayer already running? \
                 check with: lsof -nP -iTCP:3000 -sTCP:LISTEN",
                config.bind_addr
            )
        })?;
    println!("🚀 relayer listening on http://{}\n", config.bind_addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // Dropping the last sender closes the channel; the worker drains what is in flight and
    // exits. Nothing is lost, and no key material outlives the process.
    drop(state);
    let _ = worker.await;
    println!("👋 relayer stopped cleanly (key material zeroed on drop)");
    Ok(())
}

/// Startup summary. Note that it prints the relayer's **address**, never its key.
fn banner(config: &Config, relayer: Address, chain_id: u64, forwarder_is_contract: bool) {
    println!("┌─ hardened relayer ─────────────────────────────────────────────");
    println!("│ relayer address   {relayer}");
    println!("│ chain id          {chain_id}");
    println!("│ simulate against  {}", config.rpc_url);
    println!(
        "│ broadcast to      {}{}",
        config.broadcast_url,
        if config.private_mempool {
            "   ← PRIVATE MEMPOOL (no public front-running)"
        } else {
            "   ← PUBLIC mempool: anyone can see and front-run this"
        }
    );
    println!("│ trusted forwarder {}", config.forwarder);
    if !forwarder_is_contract {
        println!("│   ⚠️  that address has NO CODE on chain {chain_id}.");
        println!("│       Relays will be mined, report success, and forward nothing.");
        println!("│       Fine for the lab; set FORWARDER_ADDRESS for anything real.");
    }
    println!(
        "│ EIP-712 domain    {}/{}",
        config.eip712_name, config.eip712_version
    );
    println!("│ queue capacity    {}", config.queue_capacity);
    println!(
        "│ replay registry   {} entries max",
        config.max_seen_entries
    );
    println!(
        "│ DRY RUN           {}",
        if config.dry_run {
            "ON  (eth_call before every broadcast)"
        } else {
            "OFF ⚠️  the relayer will pay for transactions that revert"
        }
    );
    if let Some(limit) = config.gas_limit {
        println!("│ gas limit         {limit} (explicit: eth_estimateGas is skipped)");
    }
    println!("└────────────────────────────────────────────────────────────────");
}

/// Handle one verified intent: simulate, then (only then) broadcast.
///
/// This is the function that must never spend money on a losing transaction.
async fn process<P, Q>(
    intent: VerifiedIntent,
    sim_provider: &P,
    tx_provider: &Q,
    config: &Config,
    metrics: &Metrics,
    relayer: Address,
) where
    P: Provider,
    Q: Provider,
{
    // `from` is set so the simulation runs as the relayer, not as a random caller: `msg.sender`
    // checks, balance checks and nonce checks are all only meaningful with it filled in.
    let call = build_call(config.forwarder, relayer, config.gas_limit, &intent);

    // ---------------------------------------------------------------------------------
    // [4] LAST-CHANCE RE-SIMULATION.
    //
    // The handler already simulated this intent and returned 202. That answer is now stale:
    // a block may have landed since. This second `eth_call` is the difference between "we
    // checked once, a while ago" and "we checked immediately before spending gas". It costs
    // nothing, and everything past this line costs money.
    // ---------------------------------------------------------------------------------
    if config.dry_run {
        match dry_run(sim_provider, &call).await {
            Simulation::Passed(_) => {}
            Simulation::WouldRevert(reason) => {
                let reject = Reject::WouldRevert(reason.clone());
                metrics.record_reject(&reject);
                println!(
                    "🛑 {} nonce {} would revert -- refused BEFORE paying gas: {reason}",
                    intent.user, intent.nonce
                );
                return;
            }
            Simulation::Unavailable(reason) => {
                // Deliberately *not* treated as a bad intent. The user did nothing wrong, and the
                // replay slot already claimed is not refunded -- fail closed, never fail open.
                let reject = Reject::RpcUnavailable(reason.clone());
                metrics.record_reject(&reject);
                eprintln!(
                    "⚠️  {} nonce {} not relayed: {reason}",
                    intent.user, intent.nonce
                );
                return;
            }
        }
    }

    // ---------------------------------------------------------------------------------
    // [5] Broadcast. Same code as Day 2 -- only the URL changed.
    // ---------------------------------------------------------------------------------
    match tx_provider.send_transaction(call).await {
        Ok(pending) => {
            metrics.dispatched.fetch_add(1, Ordering::Relaxed);
            let hash = *pending.tx_hash();
            println!(
                "✅ relayed {} nonce {} -> {hash}",
                intent.user, intent.nonce
            );

            // -------------------------------------------------------------------------
            // [6] Receipts turn "I think it worked" into a number. If a transaction reverts
            // anyway (state moved between simulation and mining) we want to *see* the gas go.
            // -------------------------------------------------------------------------
            if config.await_receipts {
                match pending.get_receipt().await {
                    Ok(receipt) => {
                        let success = receipt.inner.is_success();
                        metrics.record_receipt(
                            success,
                            receipt.gas_used,
                            receipt.effective_gas_price,
                        );
                        if !success {
                            println!(
                                "🔥 {hash} REVERTED on chain: the dry run missed it -- {} gas burned",
                                receipt.gas_used
                            );
                        }
                    }
                    Err(err) => eprintln!("⚠️  no receipt for {hash}: {err}"),
                }
            }
        }
        Err(err) => {
            metrics.record_reject(&Reject::RpcUnavailable(err.to_string()));
            eprintln!(
                "❌ broadcast failed for {} nonce {}: {err}",
                intent.user, intent.nonce
            );
        }
    }
}

// =======================================================================================
// HTTP layer
// =======================================================================================

/// `POST /submit` -- the only way in.
///
/// The order of the gates matters, and so does the order of the *last two*:
///
/// 1. **verify** (Part 2): cryptographic proof that this is what the user authorised;
/// 2. **simulate** (Part 1): `eth_call` -- if this transaction would revert, refuse now, for
///    free, and never touch the chain;
/// 3. **claim** (Part 2a): atomically mark the intent spent, so no second copy can slip through;
/// 4. **queue**: hand it to the worker, which re-simulates and broadcasts.
///
/// Simulation comes *before* the claim on purpose: a simulation that fails because the node is
/// behind, or because an earlier nonce from the same user has not been mined yet, must not burn
/// the user's replay slot. Claiming is fail-closed, so it is reserved for intents we have already
/// proven are executable.
async fn submit_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<MetaTxRequest>,
) -> Response {
    let now = unix_now();

    // [1] Verify the signature against the domain.
    let verified = match verify_intent(&req, &state.domain, now) {
        Ok(verified) => verified,
        Err(reject) => return refuse(&state, &reject),
    };

    // [2] THE DRY RUN. `eth_call` costs nothing, mines nothing, and reports the same revert the
    // real transaction would hit. This is the line that makes griefing unprofitable.
    //
    // `DRY_RUN=0` skips it, which is the whole point of the switch: run the Part 1 demo with the
    // defence off, watch `relayer_gas_burned_on_reverts_wei` rise, then turn it on and watch it
    // stay at zero. Never ship with this off -- `/metrics` reports it either way.
    if state.dry_run_enabled {
        let call = build_call(state.forwarder, state.relayer, state.gas_limit, &verified);
        match dry_run(&state.sim_provider, &call).await {
            Simulation::Passed(_) => {}
            Simulation::WouldRevert(reason) => {
                return refuse(&state, &Reject::WouldRevert(reason));
            }
            Simulation::Unavailable(reason) => {
                return refuse(&state, &Reject::RpcUnavailable(reason));
            }
        }
    }

    // [3] Atomically claim. Only now is the intent allowed to be called spent.
    let (digest, user, nonce) = (verified.digest, verified.user, verified.nonce);
    if let Err(reject) = state.replay.claim(digest, user, nonce) {
        return refuse(&state, &reject);
    }

    // [4] Hand off. `try_send` never blocks a request handler.
    match state.tx_sender.try_send(verified) {
        Ok(()) => {
            state.metrics.accepted.fetch_add(1, Ordering::Relaxed);
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "accepted": true,
                    "user": user,
                    "nonce": nonce,
                    "digest": digest,
                    "status": "queued -- simulation and broadcast happen next",
                })),
            )
                .into_response()
        }
        Err(_) => refuse(&state, &Reject::QueueFull),
    }
}

/// Turn a [`Reject`] into a counted HTTP response.
///
/// Every refusal in the program comes through here, so the metrics can never disagree with what
/// clients were told.
fn refuse(state: &AppState, reject: &Reject) -> Response {
    state.metrics.record_reject(reject);
    println!("⛔ {} -> {}", reject.status(), reject);
    let status = StatusCode::from_u16(reject.status()).unwrap_or(StatusCode::BAD_REQUEST);
    (
        status,
        Json(json!({
            "accepted": false,
            "code": reject.code(),
            "reason": reject.to_string(),
        })),
    )
        .into_response()
}

/// `GET /domain` -- the EIP-712 parameters a client must sign against.
///
/// Nothing here is secret: `chainId` and `verifyingContract` are the *point*. Publishing them is
/// how a client proves it meant to talk to **this** relayer and **this** forwarder.
async fn domain_handler(State(state): State<Arc<AppState>>) -> Response {
    let d = &state.domain;
    Json(json!({
        "name": d.name,
        "version": d.version,
        "chain_id": d.chain_id.map(|c| c.to_string()),
        "verifying_contract": d.verifying_contract,
        "domain_separator": format!("{}", d.hash_struct()),
        "primary_type": "Intent(address user,uint256 nonce,uint256 deadline,bytes32 dataHash)",
    }))
    .into_response()
}

/// `GET /metrics` -- the scoreboard. `relayer_gas_burned_on_reverts_wei` must be 0.
async fn metrics_handler(State(state): State<Arc<AppState>>) -> Response {
    // `capacity()` is the *remaining* room, so the queue length is the difference.
    let queued = state
        .queue_capacity
        .saturating_sub(state.tx_sender.capacity());
    let body = state
        .metrics
        .render(state.replay.len(), queued, state.dry_run_enabled);
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
        .into_response()
}

/// `GET /health` -- liveness only. Says nothing about the node or the balance.
async fn health_handler() -> Response {
    (StatusCode::OK, "ok").into_response()
}

/// Resolve on Ctrl-C so the worker can drain and the process can exit in order.
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    println!("\n🛑 shutdown signal: refusing new intents, draining the queue...");
}
