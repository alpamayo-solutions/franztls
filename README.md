# 🛡️ Franztls — Simple ACME Certificate Manager for Python


`franztls` is a lightweight, open-source ACME client for automating TLS certificate issuance and renewal.  
It works similarly to Let's Encrypt clients, but is designed for embedding directly in Python services or scripts.

---

## 🚀 Features

- Fully self-contained ACME (RFC 8555) client
- Automatic certificate **issuance** and **renewal**
- Built-in **HTTP-01** challenge server
- Generates and stores **account**, **domain keys**, and **CSRs**
- Works with **local or public ACME servers**
- Minimal dependencies (`cryptography`, `acme`, `josepy`)
- Compatible with **Python ≥3.10**

---

## 📦 Installation

```bash
pip install franztls
