# 🛡️ Scam Shield

> **A private, on-device scam and spam detector that explains itself.**  
> *Your device's own scam bodyguard. Private by design, clear in plain language, and it helps you protect your family too.*

---

## 💡 The Idea in One Paragraph

**Scam Shield** lets anyone paste a suspicious SMS, WhatsApp message, or email and instantly see:
1. **A big 1-glance verdict** designed specifically for hurried or stressed users ("🛑 DO NOT REPLY, CLICK, OR PAY").
2. **Transparent risk scoring (0–100)** and highlighted red-flag keywords.
3. **Plain-language explanation** and 3 concrete action steps written by a local, open-weights language model (via Ollama).
4. **A one-tap copyable "Warn my family" message** to safeguard parents, grandparents, and group chats.

**100% On-Device & Private**: Scam messages contain private and sensitive details—phone numbers, bank names, account numbers, and OTPs. With Scam Shield, **zero data ever leaves your device**.

---

## 🚨 The Core Problem: The Hurried User

Scammers rarely rely on sophisticated text; they manufacture **fear, urgency, and confusion** ("account blocked in 2 hours", "arrest warrant", "final notice").

* Urgency intentionally turns off analytical thinking.
* Hurried, elderly, or stressed individuals will **not** cross-reference checklists.
* Cloud checkers require users to paste sensitive financial data into third-party servers.

### How Scam Shield Solves This
* **Glanceable Decision**: High-contrast, color-coded verdict banner before any complex metrics or text.
* **Deterministic Scoring**: 14 regex-based rules detect pressure tactics, credential harvesting, fake KYC, and spoofed links without hallucination risk.
* **Local Explainer**: A lightweight open model (Gemma) generates plain advice a grandparent can understand.
* **Safe Fallback**: If the local model is offline or slow, built-in safety rules ensure the app **never crashes** on stage or in production.

---

## 📊 Measured Evaluation

Tested on a benchmark dataset of 30 representative messages (20 scam attacks, 10 genuine notifications):

```
=============================================
       SCAM SHIELD EVALUATION REPORT       
=============================================
Scams caught: 19/20 (95%)
False alarms: 0/10 (0%)

MISSED SCAMS:
 [  0] Hello sir, I accidentally sent Rs 5,00,000 to your account. Kindly return it to my number.
=============================================
```

> **Honesty in Evaluation**: The only missed scam is a polite social-engineering trick without trigger words ("sent money by mistake"). Standard bank messages containing "Do not share OTP" produce **0% false alarms** due to pre-cleaning safeguards.

---

## 🛠️ Architecture

| Layer | Technology | Why this choice |
| :--- | :--- | :--- |
| **Detection** | Deterministic Python rules (`rules.py`) | Fast, explainable, zero hallucination risk, auditable. |
| **Explanation** | Local LLM via Ollama (`explain.py`) | 100% private, runs offline, plain-language guidance. |
| **UI** | Streamlit (`app.py`) | Fast, clean, reactive interface with 1-glance verdict cards. |
| **Benchmarking** | `evaluate.py` + `tests.csv` | Measurable proof of accuracy and false-alarm resistance. |

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+
- [Ollama](https://ollama.com/) running locally with an open model:
  ```bash
  ollama run gemma3:1b "Say hello"
  ```
  *(Compatible with `gemma3:1b`, `gemma3:4b`, `mistral`, `phi3`, etc.)*

### 2. Setup Virtual Environment
```bash
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Run Benchmark
```bash
python evaluate.py
```

### 4. Launch the App
```bash
streamlit run app.py
```
Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## 🗺️ Roadmap: From Hackathon to Ecosystem

* **Phase 1 (Hackathon MVP)**: Instant paste-and-check, deterministic 0–100 scoring, local LLM explainer, family warning generator.
* **Phase 2 (On-Device Background Guard)**: Local Android/Desktop notification listener (with explicit user consent) that intercepts incoming scam texts before users open them.
* **Phase 3 (Speed Bump at Risky Moments)**: A 10-second delay prompt before opening flagged links or transferring to unverified numbers.
* **Phase 4 (Encrypted Family Safety Circle)**: Automatic, end-to-end encrypted alerts sent to trusted family members when an elderly or vulnerable relative receives a high-risk scam.

---

## ⚖️ Transparency Statement

* **Runtime**: The application runs 100% locally on the device. It uses only open-weights models served locally through Ollama (`gemma3`). No cloud APIs or external web requests are executed while the product runs.
* **License**: MIT License.

