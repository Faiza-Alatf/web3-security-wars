# Web3 Security Wars – Assignment Guide

## Assignment Overview

Blockchain Assignment No. 2 is a **Blockchain Security Hackathon**. The team has **45 minutes** to investigate, exploit, detect, or secure a blockchain security problem.

Marks are based on:

* Working code
* Correct security findings
* Problem-solving and security thinking
* Smart and critical use of AI
* Creativity
* Ability to explain and defend the solution

### Evaluation Formula

**Working Code + Correct Security Finding + Successful Test + Clear Explanation**

There are **7 challenges**. Normally, a team is assigned one challenge, but all seven challenges are included in this repository.

| # | Challenge              | Folder | Run Command                                                          |
| - | ---------------------- | ------ | -------------------------------------------------------------------- |
| 1 | Private Key Guardian   | `c1`   | `python key_guardian.py sample_secrets.txt --mask-output masked.txt` |
| 2 | Transaction Detective  | `c2`   | `python tx_detective.py transactions.txt`                            |
| 3 | Reentrancy Detector    | `c3`   | `python simulate_reentrancy.py` + Remix demo                         |
| 4 | Fake Token Detector    | `c4`   | `python token_detector.py`                                           |
| 5 | Phishing Detector      | `c5`   | `python phishing_detector.py`                                        |
| 6 | Smart Contract Auditor | `c6`   | `python vuln_scanner.py VulnerableVault.sol`                         |
| 7 | AI vs Hacker           | `c7`   | `python test_ai_claims.py` + `AI_vs_HUMAN_REPORT.md`                 |

For the Python scripts, **Python 3** is required.

For Challenge 2 graph generation:

```bash
pip install matplotlib
```

Solidity challenges can be tested using [Remix IDE](https://remix.ethereum.org).

Recommended Solidity compiler version: **0.8.20+**

---

# Step-by-Step Procedure

## Step 1 – Challenge Allocation (0–5 minutes)

Identify which challenge has been assigned to your team and open the corresponding folder.

## Step 2 – Development and Investigation (5–30 minutes)

Run the command provided in the table above.

Then:

* Understand the program output.
* Read the source code.
* Understand what each function does.
* Identify the security issue.
* Prepare an explanation of the vulnerability and solution.

## Step 3 – Testing and Attack Simulation (30–38 minutes)

Test the solution using the provided sample data.

Where possible, create additional test cases, such as:

* A new suspicious URL
* A different token
* A new transaction
* Additional secret values

For Solidity challenges (C3, C6, and C7), use Remix to compile and test the vulnerable and secure contracts.

## Step 4 – Live Demonstration (38–45 minutes)

Prepare a **2-minute live demonstration** using the following structure:

1. Problem
2. Attack / Security Finding
3. Solution
4. Working Output
5. Key Lesson

## Step 5 – Demonstrate Bonus Features

Make sure to demonstrate available bonus features such as:

* Secret masking
* Transaction graph
* `nonReentrant`
* Custom detection rules
* Phishing warning mockup
* Automated vulnerability scanner
* AI security validation

---

# Remix Reentrancy Demonstration – C3

Follow these steps to demonstrate the reentrancy vulnerability:

### 1. Load the Contracts

Open Remix and add:

* `VulnerableBank.sol`
* `Attacker.sol`
* `SecureBank.sol`

Compile the contracts using Solidity **0.8.20+**.

### 2. Deploy VulnerableBank

Using Account A:

* Deploy `VulnerableBank`
* Call `deposit`
* Send **10 ETH**

### 3. Deploy the Attacker

Using Account B:

* Deploy `Attacker(bankAddress)` with **1 ETH**
* Call `attack()`

### 4. Observe the Result

Check:

```text
totalFunds() = 0
loot() = 11 ETH
```

This demonstrates that the vulnerable bank can be drained through a reentrancy attack.

### 5. Test SecureBank

Repeat the attack using `SecureBank`.

The attack should revert because the secure contract uses reentrancy protection.

---

# 2-Minute Demo Script

The following structure can be used for any challenge.

### 1. Problem – 20 seconds

> "Our challenge was to identify and solve a blockchain security problem, such as exposed private keys."

### 2. Attack / Finding – 30 seconds

> "This vulnerability could allow an attacker to steal sensitive information, manipulate transactions, or exploit the smart contract."

### 3. Solution – 30 seconds

> "We implemented a security mechanism such as pattern detection, risk scoring, Checks-Effects-Interactions, access control, or reentrancy protection."

### 4. Working Output – 30 seconds

Run the program live and demonstrate:

* Detection result
* Risk score
* Security warning
* Successful attack/failure
* Secure result

### 5. Key Lesson – 10 seconds

> "AI and automated tools can assist security analysis, but security findings must always be tested and validated by humans."

---

# Possible Viva Questions

### Reentrancy

* What is a reentrancy attack?
* Why is the Checks-Effects-Interactions pattern important?
* How does `nonReentrant` prevent reentrancy?

### Risk Scoring

* How is the risk score calculated?
* How are individual security rules assigned points?
* Why is the maximum score 100?

### Blockchain Security

* What is the difference between a private key and a wallet address?
* Why must private keys remain secret?
* What is the difference between `tx.origin` and `msg.sender`?
* How does Solidity 0.8 handle arithmetic overflow?
* What does `unchecked` mean?

### AI Security Analysis

* What mistakes did the AI make?
* Which vulnerabilities did the AI miss?
* How did you verify the AI's claims?
* Why should AI-generated security findings be tested?

---

# Final Submission Checklist

Before submission, make sure the following requirements are completed.

### General

* [ ] Run the code and capture screenshots of the output.
* [ ] Include team members' names and submission date.
* [ ] Mention the AI tool used during the assignment.
* [ ] Practice the live demonstration.
* [ ] Make sure every team member understands the assigned challenge.

### C1 – Private Key Guardian

* [ ] Detect private keys
* [ ] Detect wallet addresses
* [ ] Detect API keys and other secrets
* [ ] Generate a risk score from 0–100
* [ ] Display security warnings
* [ ] Demonstrate secret masking

### C2 – Transaction Detective

* [ ] Parse blockchain transactions
* [ ] Identify suspicious wallets
* [ ] Detect large transfers
* [ ] Calculate risk scores
* [ ] Generate security alerts
* [ ] Generate transaction graph

### C3 – Reentrancy Detector

* [ ] Identify the reentrancy vulnerability
* [ ] Explain the attack
* [ ] Demonstrate the vulnerable contract
* [ ] Apply Checks-Effects-Interactions
* [ ] Use `nonReentrant`
* [ ] Test the secure contract

### C4 – Fake Token Detector

* [ ] Check contract address
* [ ] Check token name
* [ ] Check token symbol
* [ ] Check ownership
* [ ] Check metadata
* [ ] Detect duplicate tokens
* [ ] Detect unusual ownership
* [ ] Apply custom detection rules

### C5 – Phishing Detector

* [ ] Detect HTTP URLs
* [ ] Analyze suspicious domains
* [ ] Check security-related keywords
* [ ] Detect urgency/scam language
* [ ] Analyze long or suspicious URLs
* [ ] Generate a phishing warning
* [ ] Demonstrate the warning mockup

### C6 – Smart Contract Auditor

* [ ] Detect at least 5 vulnerabilities
* [ ] Explain each vulnerability
* [ ] Explain the danger
* [ ] Describe a possible attack
* [ ] Provide a recommended fix
* [ ] Provide secure code
* [ ] Run the automated scanner

### C7 – AI vs Hacker

* [ ] Generate or analyze an AI security report
* [ ] Test the AI's security claims
* [ ] Identify at least 2 AI mistakes
* [ ] Document the testing results
* [ ] Identify missed vulnerabilities
* [ ] Prepare an improved human security report

---

# Important Note

Each team member should understand the assigned challenge and be able to explain the code, vulnerability, attack, testing process, and solution during the viva.

**Do not rely blindly on AI-generated security analysis. Always verify security claims through code review, testing, and practical validation.**

---

## Key Principle

> **Working Code + Correct Security Finding + Successful Test + Clear Explanation**

### Web3 Security Wars

**Find the vulnerability. Break the logic. Secure the chain.**
