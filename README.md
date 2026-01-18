# Microsoft 365 Forensic Triage (Offline)

![M365Triage Banner](images/banner.png)

### **A**utomated **C**orrelation of **M**365 **E**vents

An **offline forensic triage** tool that converts Microsoft 365 exported CSV logs into a **normalized local dataset (SQLite)** and a **professional, court‑friendly HTML report**. 

It is built for real incident response and forensic workflows where you receive a folder of exports (e.g., **Unified Audit Log** and **Entra ID / Azure AD sign‑in logs**) and you need to quickly answer:

- **What happened?**
- **Which accounts, IPs, and actions are involved?**
- **What is suspicious, and why?**
- **Where is the supporting evidence in the original logs?**

> [!IMPORTANT]  
> **Offline-first by design:** the tool performs **local processing only**. It does **not** call Microsoft APIs and it does not require tenant connectivity.

---

## What this project does (end-to-end)

### 1) Ingests Microsoft 365 exported CSV logs (recursive folder scan)
The tool scans a directory tree and ingests supported CSV exports. It is designed to handle real export quirks:

- Detects delimiters/encodings where possible
- Skips empty files safely
- Logs which files were ingested vs. skipped
- Uses **chunked / streaming ingestion** for very large UAL exports

Common families supported in this project include:

- **Unified Audit Log (UAL)** CSV exports (high volume)
- **Sign-in logs** CSV exports (Interactive / NonInteractive / AuthDetails variants, depending on export)

> [!NOTE]  
> Some export types may not include timestamps or may have unexpected schemas. Those files are skipped with a warning so the pipeline remains reproducible.

---

### 2) Normalizes and stores data locally (SQLite)
During ingestion, relevant fields are normalized and written to an **SQLite database** inside your output directory. This enables:

- Fast correlation queries (sign-ins ↔ audit activity ↔ users ↔ IPs)
- Repeatable results (same inputs ⇒ same output)
- Auditability (you can re-query the dataset for validation)

---

### 3) Produces findings (triage detections + correlations)
After ingestion, the tool runs correlation logic and triage detections to create **findings** (leads) backed by evidence anchors (source rows/fields).

Examples of what you can typically surface (depending on the exported logs available):

- **Risky sign-ins** / unusual patterns (location, app/client anomalies, risk flags)
- **Legacy authentication** usage and other risky client protocols
- **Suspicious audit operations** (UAL) that are relevant in account compromise / BEC contexts
- Pivot-ready aggregates: **top users**, **top IPs**, **top categories**, **time distribution**

> [!WARNING]  
> Findings are **triage leads**, not absolute proof of malicious intent. Always validate with additional context (tenant controls, user roles, device posture, mailbox rules review, etc.).

---

### 4) Generates a professional, single-theme HTML report (Nessus-style readability)
A self-contained **HTML report** is generated with a clean, professional layout designed for technical and non-technical readers—similar in readability to vulnerability scanners (e.g., Nessus / Acunetix), but focused on Microsoft 365 forensic triage.

The report is optimized for:
- **Executive overview** (scope, risk score, key KPIs)
- **Findings grouped by severity and category**
- **Evidence-first details** per finding (what triggered it, where it came from)
- **Timeline + pivots** (users, IPs, categories)
- **Integrity/evidence inventory** (hashes, processing notes)
- **Responsive layout** that adapts automatically to screen size

The report also supports **case metadata** so it can be delivered as a professional forensic document:
- Case ID
- Client
- Analyst
- Classification
- Report title

---

## Screenshots

### Run from VS Code (example)
![Execution](images/execution.png)

### HTML report (high-level overview)
![Report Overview](images/report-1.png)

### Findings (table view)
![Findings Table](images/report-2.png)

### Findings (case-file view)
![Findings Case File](images/report-3.png)

### Timeline and heatmap
![Timeline](images/report-4.png)

### Sign-ins pivots
![Sign-ins](images/report-5.png)

### UAL / BEC checklist pivots
![BEC Checklist](images/report-6.png)

### Evidence / integrity section
![Evidence](images/report-7.png)

### Exports section
![Exports](images/report-8.png)

### Raw markdown section (for ticketing / quick sharing)
![Raw](images/report-9.png)

---

## Dependencies (setup)

You only need **Python 3.10+** and the dependencies in `requirements.txt`.

### Recommended: use a virtual environment

**Windows (PowerShell):**
```powershell
# 1) Create venv
py -m venv .venv

# 2) Activate venv
.\.venv\Scripts\Activate.ps1

# 3) Install dependencies
pip install -r requirements.txt
```

**Linux/macOS (bash/zsh):**
```bash
# 1) Create venv
python3 -m venv .venv

# 2) Activate venv
source .venv/bin/activate

# 3) Install dependencies
pip install -r requirements.txt
```

---

## How to run

### Basic run
```bash
python m365_triage.py --logdir ./logs --outdir ./out --mode deep -vv
```

### Run with case metadata (recommended for deliverables)
```bash
python m365_triage.py --logdir ./logs --outdir ./out --mode deep -vv \
  --case-id "INC-2026-001" \
  --client "EVILCORP" \
  --analyst "MR ROBOT" \
  --report-title "Microsoft 365 Forensic Triage Report" \
  --classification "CONFIDENTIAL"
```

---

## Output artifacts

The `--outdir` folder will typically contain:

- `triage.sqlite` — normalized SQLite dataset
- `report.html` — primary deliverable (professional report)
- `report.md` — quick-share / ticket-friendly markdown
- `report_data.json` — structured data embedded/used by the report
- `findings.csv` / `findings.jsonl` — machine-readable findings exports
- `timeline.csv` / `timeline.jsonl` — events timeline exports
- `schema_profiles.json` — schemas observed per file/family
- `cases/` — per-identity “case file” summaries (when enabled)

---

## Sample logs in this repository

> [!WARNING]  
> Any sample logs included with this repository are **synthetic / simulated (fake) datasets** created for testing and demonstration.  
> They do **not** contain real tenant data, real users, or confidential information.

---

## Links (repository-local)

## 🔗 LINKS
> - **Script:** [`m365_triage.py`](m365_triage.py)  
> - **Dependencies:** [`requirements.txt`](requirements.txt)  
> - **Sample report (HTML):** [`out/report.html`](out/report.html)  
> - **Sample report (PDF):** [`out/report.pdf`](out/report.pdf)  
>   - If `out/report.pdf` is not present, generate it from the HTML using the report's **Print / PDF** button.  
> - **License:** [`LICENSE`](LICENSE)

> [!NOTE]  
> `out/` is typically generated output. You can commit a **sanitized demo** output folder if you want GitHub to render the sample report link.

---

## Disclaimer and limitations

> [!WARNING]  
> This tool is provided for forensic triage and incident response support.  
> It may not cover every investigative scenario and it does not guarantee detection of all threats.

- Results depend on the **quality and completeness** of exported logs
- Findings are **heuristic** and must be validated by an analyst
- Use at your own risk; the user is responsible for lawful and appropriate use

---

## Project status

> [!CAUTION]  
> **Beta / prototype release:** this is a preliminary version intended to be improved.  
> Expect changes, refactors, and additional validation work.

---

## License

This project is **subject to the repository license**: see [`LICENSE`](LICENSE).
