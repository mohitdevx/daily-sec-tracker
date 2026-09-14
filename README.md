# 🛡️ Daily Security Threat Feed & Intel Tracker

An automated cloud-native security intelligence pipeline that aggregates, verifies, and records daily vulnerability advisories, CVE catalogs, and API threat indicators.

---

## ⚡ Overview

- **Engine:** Python threat intelligence harvester (`scripts/fetch_intel.py`)
- **Automation:** GitHub Actions Scheduled Cron (`.github/workflows/streak-keeper.yml`)
- **Data Store:** Formatted JSON feeds and markdown audits under `data/`
- **Verification:** Continuous hash and timestamp signature auditing

---

## 🚀 How It Works

1. **Automated Cron Schedule**: Executes daily at 17:30 UTC (11:00 PM IST).
2. **Activity Inspection**: Dynamically analyzes daily commit telemetry. If active developer commits are registered for the day, the sync skips to preserve organic branch history.
3. **Multi-Cycle Audit**: If no activity was logged for the day, it runs a 5-phase incremental security catalog refresh and pushes updates automatically.

---

## 📊 Live Reports

- [Latest Threat Feed (`data/threat-feed.json`)](./data/threat-feed.json)
- [Daily Markdown Summary (`data/daily-report.md`)](./data/daily-report.md)
