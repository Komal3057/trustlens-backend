🔐 TrustLens — Real-Time Trust & Fraud Scoring Backend

**TrustLens** is a **backend-first trust intelligence system** that detects suspicious user behavior and dynamically calculates a **real-time trust score (0–100)**.
It simulates how modern fintech, banking, and security platforms **prevent fraud, abuse, and account takeover** at scale.

This project is built as **proof of execution** for:

* Backend system design
* Fraud signal modeling
* Risk scoring engines
* Secure authentication workflows

🎯 Why TrustLens?

Most applications authenticate users — **TrustLens evaluates whether they should be trusted**.

It continuously monitors user actions (logins, OTP requests, devices, IPs) and converts them into **risk signals**, resulting in a live trust score that evolves with user behavior.



⚙️ Key Capabilities

🔑 Authentication & Security

* Secure user registration & login
* JWT-based authentication
* Password hashing using bcrypt
* Token-protected APIs

📊 Event-Driven Risk Engine

* Centralized event ingestion (`/events`)
* Tracks security-sensitive actions in real time
* Immutable audit trail stored in MongoDB

🚨 Fraud Detection Signals

* **OTP abuse detection** (rate-based)
* **Failed login spike detection**
* **New device identification**
* IP + device correlation

 🧠 Trust Scoring Engine

* Rule-based scoring logic
* Score auto-adjusts on every event
* Trust score clamped between **0–100**
* Risk classification:

  * `NORMAL`
  * `HIGH`

🔍 Transparency & Auditing

* Full event history per user
* Debuggable trust score changes
* Designed for explainable risk decisions

🧠 Trust Scoring Rules (Deterministic & Explainable)

| Event                             | Impact |
| --------------------------------- | ------ |
| New device detected               | −10    |
| 3+ OTP requests within 10 minutes | −25    |
| 3+ failed logins within 5 minutes | −20    |
| Successful login                  | +2     |

> Trust score is **always clamped between 0 and 100**


📡 Core API Endpoints

🔐 Authentication

* `POST /auth/register` — Create a new user
* `POST /auth/login` — Authenticate & issue JWT

📊 Events & Trust

* `POST /events` — Send user activity events
* `GET /trust/me` — Fetch current trust score & risk level

🛠 Tech Stack

* **Node.js** — Backend runtime
* **Express.js** — REST API framework
* **MongoDB + Mongoose** — Persistent audit storage
* **JWT** — Stateless authentication
* **bcrypt** — Secure password hashing
* **Postman** — API testing & validation

---

## ▶️ Run Locally

```bash
npm install
npm run dev
```

Server runs on:
http://localhost:3000

