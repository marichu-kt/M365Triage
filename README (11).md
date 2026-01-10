# Microsoft 365 Forensic Triage (Offline)

An **offline forensic triage** tool for Microsoft 365 exported CSV logs. It helps incident responders and forensic analysts quickly **understand what happened**, **who was involved**, and **what looks suspicious**, using **only local processing** (no Microsoft API calls).

The project is designed for real-world investigations where you receive a folder of exports (e.g., Unified Audit Log CSV and Azure AD / Entra ID sign-in CSV exports) and you need to turn that into a **structured dataset** plus a **professional, court-friendly HTML report** that is easy to read for both technical and non-technical stakeholders.

---

## What this project does

### 1) Ingests common M365 exported logs (CSV)
The tool recursively scans a directory and ingests supported CSV exports, including:

- **Unified Audit Log (UAL)** exports (large CSVs supported via chunked/streaming ingestion).
- **Sign-in logs** exports (Interactive / NonInteractive / AuthDetails variants, depending on your export).

It automatically tries to detect delimiters/encoding, skips empty files, and logs what was ingested vs. skipped.

### 2) Normalizes and stores data locally (SQLite)
During ingestion, data is normalized and written to an **SQLite database** in your output directory.  
This enables fast correlation queries and makes the result reproducible and auditable.

### 3) Detects suspicious activity and produces findings
The tool runs a set of **triage detections** and correlation logic to produce findings such as:

- Unusual sign-in patterns (impossible travel / unusual locations, suspicious client/app patterns, etc. depending on log availability)
- Potential account compromise indicators across sign-in + audit activity
- Mailbox and Exchange-related suspicious activity patterns (where present in UAL)
- Potential BEC-style signals (high-level heuristics and pivots)

> **Important:** This is triage, not “magic.” A finding is a **lead** supported by evidence anchors (source log rows and fields). It does not automatically prove malicious intent.

### 4) Generates a professional HTML forensic report
A single self-contained **HTML report** is generated (one theme only, professional layout).  
The report is designed like vulnerability scanners (e.g., Nessus/Acunetix) in terms of readability:

- Executive overview (risk, key counts, scope)
- Findings grouped by severity/type
- Evidence-focused details per finding (what triggered it, where it came from)
- Quick pivots (top users, top IPs, timelines, etc. where data is available)
- Case metadata header (case ID, client, analyst, classification, title)

The report is built to be readable on any screen size (responsive layout) and suitable for professional delivery.

---

## Key features

- **Offline-first:** no cloud calls, processes only local CSV exports.
- **Streaming ingestion:** handles very large CSVs using chunk processing.
- **SQLite backend:** normalized storage for correlation and repeatability.
- **Deep mode vs quick mode:** faster triage vs deeper correlation.
- **Professional HTML report:** single-theme, responsive, evidence-friendly.
- **Case metadata flags:** embed case/analyst/classification into the report header.
- **Robust ingestion:** delimiter/encoding detection, empty/unknown file handling.

---

## Dependencies (requirements)

You only need Python and to install the dependencies from `requirements.txt`:

```bash
pip install -r requirements.txt
```

Typical environment:
- **Python 3.10+** recommended (tested commonly with 3.11/3.12).
- Works on Windows/macOS/Linux as long as Python and dependencies are available.

---

## How to run

Basic run:

```bash
python m365_triage.py --logdir ./logs --outdir ./out --mode deep -vv
```

- `--logdir`: folder containing exported CSV logs (recursive)
- `--outdir`: where outputs (DB + report) are written
- `--mode`: `quick` or `deep`
- `-v / -vv`: verbosity level

### Run with case metadata (recommended for professional reports)

```bash
python m365_triage.py --logdir ./logs --outdir ./out --mode deep -vv   --case-id "INC-2026-001"   --client "EVILCORP"   --analyst "MR ROBOT"   --report-title "Microsoft 365 Forensic Triage Report"   --classification "CONFIDENTIAL"
```

```bash
```

---

## Output artifacts

After a successful run, `--outdir` will contain (names may vary slightly):

- **SQLite database** (normalized ingested data)
- **HTML report** (main deliverable)
- Optional exports (CSV/JSON/MD) depending on enabled features and mode

The HTML report is intended to be the **primary deliverable** for stakeholders, while the SQLite DB is the **technical substrate** for deeper analysis and reproducibility.

---

## Notes for forensic usage

- Preserve your original exported files (read-only where possible).
- Keep the output directory as part of your evidence set if you need reproducibility.
- Treat detections as **leads**: validate with additional context (tenant configuration, user roles, mailbox rules, device posture, etc.).
- If you need strict chain-of-custody, consider hashing the source exports and storing those hashes alongside the report.

---

## Limitations

- The tool’s accuracy depends on the **quality and completeness** of the exported logs.
- Some exports may not include timestamp fields or may use unexpected schemas; those files are skipped with a warning.
- Findings are heuristic in nature; this is not a replacement for full DFIR workflow.

---

## Repository structure (high level)

- `m365_triage.py` — main tool (CLI + ingestion + detections + report generation)
- `requirements.txt` — Python dependencies
- `README.md` — documentation
- `LICENSE` — license terms

---

## Disclaimer

This tool is provided for forensic triage and incident response support.  
The author provides no guarantee that it will detect all threats or cover all investigative scenarios. The user is responsible for validating results and for the lawful and appropriate use of the tool.
