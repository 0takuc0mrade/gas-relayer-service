use axum::{Json, Router, extract::State, routing::post};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::mpsc;
// Note: Ensure alloy is configured in Cargo.toml
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, Bytes};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;

// 1. Define Request Payload
#[derive(Deserialize, Clone)]
struct MetaTxRequest {
    user: String,
    data: String,
    signature: String,
}

// 2. Application State
struct AppState {
    tx_sender: mpsc::Sender<MetaTxRequest>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 3. Setup MPSC Channel (Buffer of 100)
    let (tx_sender, mut tx_receiver) = mpsc::channel::<MetaTxRequest>(100);

    // 4. Relayer wallet + provider.
    //    Built *before* spawning the worker so that a bad key / unreachable RPC fails
    //    loudly at startup instead of silently killing the background task.
    let signer: PrivateKeySigner = std::env::var("PRIVATE_KEY")
        .expect("PRIVATE_KEY not set")
        .parse()?;
    let wallet = EthereumWallet::from(signer);

    let rpc_url = std::env::var("RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    let provider = ProviderBuilder::new().wallet(wallet).connect(&rpc_url).await?;

    // EIP-2771 trusted forwarder that every intent is relayed to.
    // TODO: point this at your deployed forwarder, or export FORWARDER_ADDRESS.
    let forwarder: Address = std::env::var("FORWARDER_ADDRESS")
        .unwrap_or_else(|_| Address::ZERO.to_string())
        .parse()?;

    // 5. Background Sequential Worker (The Heart of the Relayer)
    tokio::spawn(async move {
        // Process intents sequentially: one transaction at a time, in arrival order.
        while let Some(req) = tx_receiver.recv().await {
            // NOTE: `signature` is only logged -- it is never verified. A real relayer MUST
            // recover the signer from it and reject intents that do not match `req.user`.
            println!("Processing intent for: {} (sig: {})", req.user, req.signature);

            // Translate the off-chain intent into an on-chain call:
            // to = trusted forwarder, input = the intent's calldata.
            let call = TransactionRequest::default()
                .with_to(forwarder)
                .with_input(Bytes::from(alloy::hex::decode(&req.data).unwrap_or_default()));

            // Simulation Step (Dry-run)
            // if !dry_run(&provider, &call).await { continue; }

            // Dispatch Transaction
            match provider.send_transaction(call).await {
                Ok(tx) => println!("Dispatched: {:?}", tx.tx_hash()),
                Err(e) => eprintln!("Execution Error: {}", e),
            }
        }
    });

    // 6. REST API Layer
    let state = Arc::new(AppState { tx_sender });
    let app = Router::new()
        .route("/submit", post(submit_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("🚀 Relayer API listening on port 3000");
    axum::serve(listener, app).await?;

    Ok(())
}

async fn submit_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<MetaTxRequest>,
) -> &'static str {
    // Non-blocking handoff to queue
    let _ = state.tx_sender.send(payload).await;
    "Transaction Queued"
}
