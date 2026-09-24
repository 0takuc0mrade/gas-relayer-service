use alloy::primitives::{Bytes, keccak256};
use alloy::signers::local::PrivateKeySigner;
use reqwest::Client;
use std::sync::Arc;
use tokio::task;

#[tokio::main]
async fn main() {
    let client = Arc::new(Client::new());
    let url = "http://127.0.0.1:3000/submit";
    let mut handles = Vec::new();

    for _ in 0..500 {
        let client_ref = Arc::clone(&client);
        let url_ref = url.to_string();
        let signer = PrivateKeySigner::random();

        handles.push(task::spawn(async move {
            let payload = serde_json::json!({
                // "user": format!("user_{}", i),
                // "signature": "0xcafe"
                "user": &signer.address(),
                "data": "0xdeadbeef",
                "signature": keccak256(Bytes::from(alloy::hex::decode(&signer.address()).unwrap_or_default()))
            });
            let _ = client_ref.post(url_ref).json(&payload).send().await;
        }));
    }

    for h in handles {
        let _ = h.await;
    }
    println!("Finished bombarding the Relayer.");
}
