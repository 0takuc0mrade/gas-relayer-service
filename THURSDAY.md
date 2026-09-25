Today's class is to build upon yesterday's class.

This session is arguably the most critical for **Protocol Engineers**. While Days 2 and 3 focus on *functionality*, Today (Thursday) focuses on *survival*. Relayers are honey-pots; if they aren't hardened, they will be drained.

### **Lab Title: "The Hardened Relayer: Adversarial Design"**
**Objective:** Students will transition from building an "optimistic" service to an "adversarial" one. They will implement defensive patterns to prevent gas theft, unauthorized relaying, and state-manipulation.

---

### **Part 1: The "Griefing" Analysis (60 Mins)**
Students need to understand how an attacker can bleed the Relayer dry.
*   **The Scenario:** A malicious user sends a meta-transaction that is perfectly signed, but the *actual call* on-chain will `revert` (e.g., they send a transfer they don't have funds for).
*   **The Impact:** The Relayer pays the gas fee for the transaction submission, the transaction fails on-chain, and the Relayer loses money.
*   **Defense Mechanism:** **The Simulation (Dry-Run) Pattern.**
    *   **The Lab Task:** Implement an `eth_call` before the `send_transaction`. If the simulation returns an error, the Relayer must reject the request immediately without ever touching the blockchain.

---

### **Part 2: Replay & Malleability Defense (90 Mins)**
*   **Topic: EIP-712 Integrity:**
    *   Explain why raw signatures are dangerous. Students must ensure they are using EIP-712 correctly, specifically the `domainSeparator`.
    *   **The Challenge:** Build a "Used Signature Registry." Even if the contract checks nonces, the Relayer itself should keep a cache (in-memory `HashSet`) of seen signatures to prevent the same request from being submitted to the network twice by the Relayer's own internal logic.
*   **Topic: Private Key Management:**
    *   **The Rule:** The Relayer's key is the "God Key."
    *   **The Lab Task:** Refactor the code so the key is never loaded into global state. It should be inside a secure `struct` that can be dropped/wiped from memory when the process terminates.

---

### **Part 3: The "Flashbots-Ready" Infrastructure (60 Mins)**
*   **Topic: Front-Running & MEV Protection:**
    *   Explain that if a transaction sits in the public mempool, someone can see it and "front-run" it.
    *   **The Strategy:** Introduce the students to the idea of "Private Mempools" (like Flashbots). 
    *   **Lab Task:** Modify the Alloy `provider` to send the transaction to a Flashbots RPC URL instead of a standard public node.

---

### **Part 4: The Adversarial "Break My Code" Session (30 Mins)**
*   **The "Hacker" Game:** Split students into pairs. Student A acts as the "Hacker," Student B acts as the "Defender" (the Relayer).
*   **Goal:** The Hacker tries to force the Defender’s Relayer to submit a transaction that reverts or repeats.
*   **Takeaway:** If the Relayer survives the attack without spending gas on reverted transactions, the Defender wins.

---

### **Teacher’s Cheat Sheet: The Dry-Run Logic**
Give them this logic as the "Primary Defense" for their Relayer:

```rust
async fn dry_run(provider: &impl Provider, tx: TransactionRequest) -> Result<(), String> {
    // We use eth_call to simulate the transaction. 
    // If it reverts, this will return an error.
    match provider.call(&tx).await {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Transaction will revert: {}", e)),
    }
}
```

### **Why this makes them better engineers:**
By the end of this class, they won't just ask *"Does this code work?"*; they will ask *"How can this code be exploited?"* This distinction is what separates a developer from a **Security-First Protocol Engineer**.

**Would you like me to create a "Security Audit Checklist" for their final project that they can use to self-grade their Relayer?**

