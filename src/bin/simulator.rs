use reqwest::Client;
use std::sync::Arc;
use tokio::task;

#[tokio::main]
async fn main() {
    let client = Arc::new(Client::new());
    let url = "http://127.0.0.1:3000/submit";
    let mut handles = Vec::new();

    for i in 0..50 {
        let client_ref = Arc::clone(&client);
        let url_ref = url.to_string();

        handles.push(task::spawn(async move {
            let payload = serde_json::json!({
                "user": format!("user_{}", i),
                "data": "0xdeadbeef",
                "signature": "0xcafe"
            });
            let _ = client_ref.post(url_ref).json(&payload).send().await;
        }));
    }

    for h in handles {
        let _ = h.await;
    }
    println!("Finished bombarding the Relayer.");
}
