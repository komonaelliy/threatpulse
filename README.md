# 🛰️ ThreatPulse

> **Free & Open Threat Intelligence Feed Generator**  
> Automated collection of cybersecurity threats, CVEs, and trending vulnerabilities — updated every 20 minutes.

---

## ⚡ Overview

**ThreatPulse** is an open-source project that continuously fetches the latest cybersecurity data from public sources, verifies it, and publishes a unified feed (`data/threat_feed.json`).

Perfect for:
- Security researchers 🧠  
- Blue teams 🔒  
- SOC dashboards 📊  
- Open threat intelligence sharing 🌐  

---

## 🧠 Features

- 🕵️‍♂️ Collects from **free sources**:
  - NVD (official CVE feed)
  - Reddit [`r/netsec`](https://reddit.com/r/netsec)
  - ThreatPost
  - HackerNews
  - CVE Trends (last 24 hours)
- ⚙️ Auto-refresh every **20 minutes**
- 🧩 Optional AI verification (if `OPENAI_API_KEY` is provided)
- 💾 Saves unified feed to `data/threat_feed.json`
- 🌍 Designed for GitHub Pages and public use

---

## 🏗️ Repository Structure


