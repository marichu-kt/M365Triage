#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
m365_triage.py — Offline forensic triage for Microsoft 365 exported CSV logs (Sign-ins + Unified Audit Log).

Goals
- Work *offline* on exported CSVs (no Graph/Portal API required).
- Be robust to messy CSVs: BOM, Excel "sep=,", unknown delimiters, odd headers, empty files.
- Produce clean, structured output for incident response & forensics:
  - report.md + report.html (human readable)
  - findings.csv + findings.jsonl (machine readable)
  - timeline.csv + timeline.jsonl
  - file_ranges.csv + schema_profiles.json
  - cases/<user>.md (per-user case views)
  - (optional) report.xlsx

Detections (high-level)
- Risky sign-ins (RiskLevel* / RiskState / RiskDetail)
- Legacy auth (IMAP/POP/SMTP/ActiveSync/MAPI/Basic Auth indicators)
- Password spray and brute force (campaign-style)
- Success-after-failures sequences (credential guessed / MFA fatigue indicators)
- Impossible travel (country changes between successful sign-ins in a short time)
- Unified Audit Log: suspicious operations (rules, forwarding, permissions, transport rules, OAuth/app consent, admin changes)
- MailItemsAccessed spikes (mailbox hunting / exfil indications)
- Correlation: link UAL sensitive actions to prior successful sign-in context
- YAML rule engine (optional) for custom detections without code changes
- Evidence: per finding includes file, row number, sha256, and minimal raw context

Dependencies (minimum)
- pandas
- python-dateutil

Optional (improves output)
- pyyaml (for rules.yml)
- openpyxl (for --xlsx)
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import os
import re
import sqlite3
import sys
import textwrap
import warnings
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import pandas as pd
from pandas.errors import EmptyDataError, ParserError


# -----------------------------
# Tool metadata
# -----------------------------
TOOL_VERSION = "2.0.0"  # visual report build

# -----------------------------
# Logging
# -----------------------------

def setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Reduce noisy pandas warnings for mixed timestamp formats
    warnings.filterwarnings("ignore", message="Could not infer format")


# -----------------------------
# CSV robustness helpers
# -----------------------------

DELIMITER_CANDIDATES = [",", ";", "\t", "|"]

def sniff_delimiter(path: Path) -> str:
    try:
        with path.open("r", encoding="utf-8-sig", errors="ignore") as f:
            sample = f.read(8192)
        # handle Excel sep=
        sample2 = sample.splitlines()
        if sample2 and sample2[0].lower().startswith("sep="):
            sample = "\n".join(sample2[1:])
        dialect = csv.Sniffer().sniff(sample, delimiters=DELIMITER_CANDIDATES)
        return dialect.delimiter
    except Exception:
        return ","


def detect_skiprows_for_excel_sep(path: Path) -> int:
    try:
        with path.open("r", encoding="utf-8-sig", errors="ignore") as f:
            first = f.readline().strip().lower()
        if first.startswith("sep="):
            return 1
    except Exception:
        pass
    return 0


def read_csv_any(path: Path, delimiter: str, **kwargs) -> pd.DataFrame:
    """
    Robust read_csv wrapper:
    - auto-skips Excel/portal first line "sep=,"
    - tries engine='c' first; falls back to engine='python' (removing low_memory which is unsupported there)
    - tries encoding utf-8-sig then latin1
    """
    if kwargs.get("skiprows", None) is None:
        kwargs["skiprows"] = detect_skiprows_for_excel_sep(path)

    # Avoid pandas dtype inference surprises for chunky files by default
    # (callers may override dtype)
    encodings = ["utf-8-sig", "latin1"]
    last_err: Optional[Exception] = None

    for enc in encodings:
        # Try fast engine
        try:
            return pd.read_csv(path, encoding=enc, sep=delimiter, engine="c", **kwargs)
        except Exception as e:
            last_err = e

        # Fallback python engine (remove low_memory)
        try:
            kwargs2 = dict(kwargs)
            kwargs2.pop("low_memory", None)
            return pd.read_csv(path, encoding=enc, sep=delimiter, engine="python", **kwargs2)
        except Exception as e:
            last_err = e

    assert last_err is not None
    raise last_err


def auto_detect_time_column(path: Path, delimiter: str, sample_rows: int = 2000) -> Optional[str]:
    """
    Detect the most likely timestamp column by parsing a sample and scoring columns.

    Heuristics:
    - Prefer columns whose names look like time/date fields.
    - Support ISO strings and "mixed" formats.
    - Support epoch seconds/milliseconds when the name hints at time/date.
    """
    try:
        df = read_csv_any(path, delimiter, nrows=sample_rows, dtype=str, keep_default_na=False)
    except (EmptyDataError, ParserError):
        return None
    except Exception:
        return None

    if df is None or df.empty or len(df.columns) == 0:
        return None

    time_name_hint = re.compile(r"(time|date|created|creation|generated|activity|occur|timestamp|signin)", re.I)
    digit_ts = re.compile(r"^\d{10,13}$")

    best_col: Optional[str] = None
    best_score: float = 0.0

    for c in df.columns:
        name = str(c)
        ser = df[c].astype(str)

        # Skip mostly-empty columns early
        non_empty = (ser != "").mean()
        if non_empty < 0.15:
            continue

        # 1) Try normal datetime parsing (mixed format)
        try:
            dt = pd.to_datetime(ser, errors="coerce", utc=True, format="mixed")
        except TypeError:
            dt = pd.to_datetime(ser, errors="coerce", utc=True)

        ratio = float(dt.notna().mean())
        score = ratio

        # 2) Try epoch parsing (only if the column name strongly hints time/date)
        if ratio < 0.55 and time_name_hint.search(name):
            digits_ratio = float(ser.str.match(digit_ts, na=False).mean())
            if digits_ratio > 0.80:
                nums = pd.to_numeric(ser, errors="coerce")
                nums_clean = nums.dropna()
                if not nums_clean.empty:
                    med = float(nums_clean.median())
                    unit = None
                    if med > 1e12:
                        unit = "ms"
                    elif med > 1e9:
                        unit = "s"
                    if unit:
                        dt2 = pd.to_datetime(nums, errors="coerce", utc=True, unit=unit)
                        # plausibility check
                        try:
                            miny = int(dt2.dropna().min().year) if dt2.notna().any() else 0
                            maxy = int(dt2.dropna().max().year) if dt2.notna().any() else 9999
                        except Exception:
                            miny, maxy = 0, 9999
                        if 2000 <= miny <= 2100 and 2000 <= maxy <= 2100:
                            ratio2 = float(dt2.notna().mean())
                            if ratio2 > ratio:
                                score = ratio2

        # Name hint bonus
        if time_name_hint.search(name):
            score += 0.15

        if score > best_score:
            best_score = score
            best_col = name

    # Accept fairly low ratios because some exports have sparse timestamps (still useful).
    if best_col and best_score >= 0.35:
        return best_col
    return None


# -----------------------------
# Common helpers
# -----------------------------

def safe_str(x: Any) -> str:
    if x is None:
        return ""
    try:
        if pd.isna(x):
            return ""
    except Exception:
        pass
    return str(x)


def to_dt_series(series: pd.Series) -> pd.Series:
    """Robust datetime parsing across mixed formats."""
    try:
        return pd.to_datetime(series, errors="coerce", utc=True, format="mixed")
    except TypeError:
        return pd.to_datetime(series, errors="coerce", utc=True)


def epoch_from_dt(dt: Any) -> Optional[int]:
    try:
        if dt is None or pd.isna(dt):
            return None
        if isinstance(dt, str):
            dt = pd.to_datetime(dt, errors="coerce", utc=True)
        if hasattr(dt, "to_pydatetime"):
            dt = dt.to_pydatetime()
        if isinstance(dt, datetime):
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
    except Exception:
        return None
    return None


def iso_from_epoch(epoch: Optional[int]) -> str:
    if epoch is None:
        return ""
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat()
    except Exception:
        return ""


def epoch_to_iso(epoch: Optional[int]) -> str:
    """Backward-compatible alias used by report builder."""
    return iso_from_epoch(epoch)



def find_col(columns: Iterable[str], candidates: Sequence[str]) -> Optional[str]:
    cols = [c.strip() for c in columns]
    lower_map = {c.lower(): c for c in cols}
    cand_lowers = [c.lower() for c in candidates]

    # exact
    for cl in cand_lowers:
        if cl in lower_map:
            return lower_map[cl]

    # substring
    for c in cols:
        cl = c.lower()
        for cand in cand_lowers:
            if cand in cl:
                return c
    return None


def sha256_file(path: Path, bufsize: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(bufsize)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def md_table(rows: List[Dict[str, Any]], headers: List[str], max_rows: int = 25) -> str:
    """
    Lightweight markdown table without requiring tabulate.
    """
    rows = rows[:max_rows]
    # Compute widths
    widths = {h: len(h) for h in headers}
    for r in rows:
        for h in headers:
            widths[h] = max(widths[h], len(safe_str(r.get(h, ""))[:200]))
    # Build
    def fmt_row(r: Dict[str, Any]) -> str:
        return "| " + " | ".join(safe_str(r.get(h, ""))[:200].ljust(widths[h]) for h in headers) + " |"
    head = "| " + " | ".join(h.ljust(widths[h]) for h in headers) + " |"
    sep = "| " + " | ".join("-" * widths[h] for h in headers) + " |"
    body = "\n".join(fmt_row(r) for r in rows) if rows else ""
    return "\n".join([head, sep, body]).strip()


# -----------------------------
# Log family detection
# -----------------------------

def detect_family(path: Path, columns: Optional[List[str]] = None) -> str:
    n = path.name.lower()
    if "interactivesignins" in n or "noninteractivesignins" in n or "msisignins" in n or "applicationsignins" in n:
        return "signin"
    if "ual" in n or "audit" in n or "unified" in n:
        return "ual"
    if columns:
        cols_l = " ".join(c.lower() for c in columns)
        if "auditdata" in cols_l or "workload" in cols_l and "operation" in cols_l:
            return "ual"
        if "userprincipalname" in cols_l and ("appdisplayname" in cols_l or "clientappused" in cols_l):
            return "signin"
    return "unknown"


# -----------------------------
# Detection dictionaries
# -----------------------------

LEGACY_CLIENT_PATTERNS = [
    "imap", "imap4", "pop", "pop3", "smtp", "authenticated smtp",
    "activesync", "mapi", "other clients", "legacy", "basic auth"
]

AADSTS_HINTS = {
    "50126": "Invalid username/password (brute force/spray)",
    "50053": "Account locked",
    "50055": "Password expired",
    "50076": "MFA required (attacker may have password)",
    "53003": "Blocked by Conditional Access",
}

DANGEROUS_OAUTH_SCOPES = {
    "mail.read", "mail.readwrite", "mail.send", "mailboxsettings.read", "mailboxsettings.readwrite",
    "offline_access", "ewsr", "full_access_as_app", "calendars.read", "calendars.readwrite",
    "user.readbasic.all", "files.read", "files.readwrite", "sites.read.all", "sites.readwrite.all",
}

UAL_SUSPICIOUS_PATTERNS = {
    "high": [
        r"inboxrule", r"updateinboxrules", r"new-inboxrule", r"set-inboxrule",
        r"set-mailbox", r"add-mailboxpermission", r"add-mailboxfolderpermission",
        r"set-mailboxfolderpermission", r"new-transportrule", r"set-transportrule",
        r"new-inboundconnector", r"set-inboundconnector", r"new-outboundconnector", r"set-outboundconnector",
        r"add-rolegroupmember", r"new-managementroleassignment", r"add management role assignment",
        r"add service principal", r"add app role assignment", r"grant", r"oauth", r"consent",
        r"set-organizationconfig", r"set-transportconfig", r"set-authenticationpolicy",
        r"set-omeconfiguration", r"set-irmconfiguration",
    ],
    "medium": [
        r"add user", r"reset user password", r"update user", r"set user",
        r"add group", r"add member", r"update group",
        r"set-casmailbox", r"set-mailboxcalendarconfiguration",
    ],
}

FORWARDING_KEYWORDS = [
    "forwardingsmtpaddress", "forwardingaddress", "delivertomailboxandforward",
    "redirectto", "forwardto", "smtpforward", "deliver to mailbox and forward",
    "forwarding smtp address", "redirect",
]

INBOX_RULE_KEYWORDS = [
    "inboxrule", "updateinboxrules", "new-inboxrule", "set-inboxrule",
    "moved to rss", "move to rss", "delete", "markasread", "stopprocessingrules",
    "forwardto", "redirectto", "sendto", "remove",
]

# Precompiled regex for fast keyword detection in large AuditData strings
FORWARD_RE = re.compile("|".join(re.escape(k) for k in FORWARDING_KEYWORDS), re.I)
INBOX_RULE_RE = re.compile("|".join(re.escape(k) for k in INBOX_RULE_KEYWORDS), re.I)

MAILITEMS_ACCESS_OPS = {"mailitemsaccessed", "mailitemsaccessedv2", "mailread", "mailitemsaccessed (preview)"}


# -----------------------------
# Data model for findings
# -----------------------------

@dataclass
class Finding:
    finding_id: str
    severity: str
    category: str
    title: str
    timestamp: str
    user: str
    ip: str
    country: str
    file: str
    rownum: str
    sha256: str
    details: str
    evidence: Dict[str, Any]

    def to_row(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "timestamp": self.timestamp,
            "user": self.user,
            "ip": self.ip,
            "country": self.country,
            "file": self.file,
            "rownum": self.rownum,
            "sha256": self.sha256,
            "details": self.details,
            "evidence_json": json.dumps(self.evidence, ensure_ascii=False),
        }

    def to_json(self) -> Dict[str, Any]:
        d = self.to_row()
        d["evidence"] = self.evidence
        d.pop("evidence_json", None)
        return d


# -----------------------------
# SQLite storage
# -----------------------------

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS files (
  file_id INTEGER PRIMARY KEY AUTOINCREMENT,
  path TEXT UNIQUE,
  name TEXT,
  family TEXT,
  sha256 TEXT,
  rows INTEGER,
  delimiter TEXT,
  skiprows INTEGER,
  start_epoch INTEGER,
  end_epoch INTEGER,
  columns_json TEXT,
  profile_json TEXT,
  error TEXT
);

CREATE TABLE IF NOT EXISTS signin (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER,
  rownum INTEGER,
  ts_epoch INTEGER,
  ts_iso TEXT,
  user TEXT,
  ip TEXT,
  app TEXT,
  client_app TEXT,
  user_agent TEXT,
  device_id TEXT,
  correlation_id TEXT,
  result_type TEXT,
  error_code TEXT,
  failure_reason TEXT,
  status TEXT,
  risk_level TEXT,
  risk_state TEXT,
  risk_detail TEXT,
  country TEXT,
  state TEXT,
  city TEXT,
  raw_json TEXT,
  FOREIGN KEY(file_id) REFERENCES files(file_id)
);

CREATE TABLE IF NOT EXISTS ual (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER,
  rownum INTEGER,
  ts_epoch INTEGER,
  ts_iso TEXT,
  user TEXT,
  ip TEXT,
  operation TEXT,
  workload TEXT,
  record_type TEXT,
  object_id TEXT,
  auditdata TEXT,
  raw_json TEXT,
  FOREIGN KEY(file_id) REFERENCES files(file_id)
);

CREATE INDEX IF NOT EXISTS idx_signin_ts ON signin(ts_epoch);
CREATE INDEX IF NOT EXISTS idx_signin_user_ts ON signin(user, ts_epoch);
CREATE INDEX IF NOT EXISTS idx_signin_ip_ts ON signin(ip, ts_epoch);

CREATE INDEX IF NOT EXISTS idx_ual_ts ON ual(ts_epoch);
CREATE INDEX IF NOT EXISTS idx_ual_user_ts ON ual(user, ts_epoch);
CREATE INDEX IF NOT EXISTS idx_ual_op ON ual(operation);
"""

def db_connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.executescript(SCHEMA_SQL)
    return conn


def db_insert_file(conn: sqlite3.Connection, meta: Dict[str, Any]) -> int:
    cols = [
        "path","name","family","sha256","rows","delimiter","skiprows",
        "start_epoch","end_epoch","columns_json","profile_json","error"
    ]
    vals = [meta.get(c) for c in cols]
    conn.execute(
        f"INSERT OR REPLACE INTO files({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",
        vals
    )
    # get file_id
    cur = conn.execute("SELECT file_id FROM files WHERE path=?", (meta["path"],))
    return int(cur.fetchone()[0])


def db_bulk_insert_signin(conn: sqlite3.Connection, rows: List[Tuple[Any,...]]) -> None:
    conn.executemany(
        """INSERT INTO signin(
             file_id,rownum,ts_epoch,ts_iso,user,ip,app,client_app,user_agent,device_id,correlation_id,
             result_type,error_code,failure_reason,status,risk_level,risk_state,risk_detail,
             country,state,city,raw_json
           ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        rows
    )


def db_bulk_insert_ual(conn: sqlite3.Connection, rows: List[Tuple[Any,...]]) -> None:
    conn.executemany(
        """INSERT INTO ual(
             file_id,rownum,ts_epoch,ts_iso,user,ip,operation,workload,record_type,object_id,auditdata,raw_json
           ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        rows
    )


# -----------------------------
# Profiling
# -----------------------------

def schema_profile_from_sample(df: pd.DataFrame, max_examples: int = 3) -> Dict[str, Any]:
    prof: Dict[str, Any] = {
        "columns": [],
        "n_sample": int(len(df)),
    }
    for c in df.columns:
        s = df[c]
        null_ratio = float(pd.isna(s).mean()) if len(s) else 1.0
        # examples
        examples = []
        try:
            for v in s.dropna().astype(str).head(50).unique()[:max_examples]:
                examples.append(v[:200])
        except Exception:
            pass
        prof["columns"].append({
            "name": c,
            "null_ratio": null_ratio,
            "examples": examples
        })
    return prof


# -----------------------------
# Ingestion: Sign-ins
# -----------------------------

SIGNIN_TIME_CANDIDATES = [
    # Common M365 export column names for event time
    "CreatedDateTime", "createdDateTime", "createdDateTimeUtc", "CreatedDateTimeUtc",
    "TimeGenerated", "timeGenerated", "Timestamp", "timestamp",
    "DateTime", "datetime", "Date", "date", "CreationDate", "creationDate",
    "createdDateTime (UTC)", "CreatedDateTime (UTC)", "Created Date Time", "CreatedDate Time",
    "ActivityDateTime", "activityDateTime", "ActivityDate", "activityDate",
    "SignInDateTime", "signInDateTime", "logDateTime", "LogDateTime"
]

def ingest_signin_file(conn: sqlite3.Connection, path: Path, file_id: int, delimiter: str, chunk_rows: int, verbosity: int) -> Tuple[int, Optional[int], Optional[int]]:
    # Read header
    head = read_csv_any(path, delimiter, nrows=0)
    cols = [c.strip() for c in head.columns]
    time_col = find_col(cols, SIGNIN_TIME_CANDIDATES) or auto_detect_time_column(path, delimiter)

    if not time_col:
        logging.warning(f"[skip] no timestamp column found in {path.name} (signin).")
        return 0, None, None

    # column mapping
    user_col = find_col(cols, ["UserPrincipalName","userPrincipalName","User","UserId","User ID","UPN"])
    ip_col = find_col(cols, ["IPAddress","ipAddress","ClientIP","Client IP Address","ip"])
    app_col = find_col(cols, ["AppDisplayName","ResourceDisplayName","Application","App","Resource"])
    client_col = find_col(cols, ["ClientAppUsed","Client App Used","AuthenticationProtocol","ClientApp"])
    ua_col = find_col(cols, ["UserAgent","userAgent","User Agent"])
    device_col = find_col(cols, ["DeviceId","deviceId","Device ID"])
    corr_col = find_col(cols, ["CorrelationId","correlationId","RequestId","requestId"])

    # status / result
    result_type_col = find_col(cols, ["ResultType","resultType","Status.errorCode","errorCode","Status Error Code"])
    fail_reason_col = find_col(cols, ["Status.failureReason","failureReason","FailureReason","StatusDetails","statusDetails"])
    status_col = find_col(cols, ["Status","ResultStatus","resultStatus"])

    # risk
    risk_level_col = find_col(cols, ["RiskLevelDuringSignIn","RiskLevelAggregated","RiskLevel","riskLevel"])
    risk_state_col = find_col(cols, ["RiskState","riskState"])
    risk_detail_col = find_col(cols, ["RiskDetail","riskDetail"])

    # location
    country_col = find_col(cols, ["Location.countryOrRegion","countryOrRegion","Country","CountryOrRegion","Location Country"])
    state_col = find_col(cols, ["Location.state","State","Location State"])
    city_col = find_col(cols, ["Location.city","City","Location City"])

    reader = read_csv_any(
        path, delimiter,
        chunksize=chunk_rows,
        dtype=str,
        keep_default_na=False,
        na_values=[""],
    )

    total_rows = 0
    min_epoch: Optional[int] = None
    max_epoch: Optional[int] = None

    batch: List[Tuple[Any,...]] = []
    for chunk_i, df in enumerate(reader, start=1):
        total_rows += len(df)
        # timestamps
        ts = to_dt_series(df[time_col]) if time_col in df.columns else pd.to_datetime(pd.Series([None]*len(df)), utc=True)
        ts_epoch = ts.map(epoch_from_dt)
        # min/max
        ce_min = ts_epoch.dropna().min() if not ts_epoch.dropna().empty else None
        ce_max = ts_epoch.dropna().max() if not ts_epoch.dropna().empty else None
        if ce_min is not None:
            min_epoch = ce_min if min_epoch is None else min(min_epoch, int(ce_min))
        if ce_max is not None:
            max_epoch = ce_max if max_epoch is None else max(max_epoch, int(ce_max))

        for idx, row in df.iterrows():
            rownum = int(idx) + 1 + (chunk_i-1) * chunk_rows
            te = ts_epoch.iloc[idx] if idx < len(ts_epoch) else None
            te_int = int(te) if te is not None and str(te) != "nan" else None
            ts_iso = iso_from_epoch(te_int)
            user = safe_str(row.get(user_col,"")) if user_col else ""
            ip = safe_str(row.get(ip_col,"")) if ip_col else ""
            app = safe_str(row.get(app_col,"")) if app_col else ""
            client_app = safe_str(row.get(client_col,"")) if client_col else ""
            user_agent = safe_str(row.get(ua_col,"")) if ua_col else ""
            device_id = safe_str(row.get(device_col,"")) if device_col else ""
            corr = safe_str(row.get(corr_col,"")) if corr_col else ""
            result_type = safe_str(row.get(result_type_col,"")) if result_type_col else ""
            status = safe_str(row.get(status_col,"")) if status_col else ""
            fail_reason = safe_str(row.get(fail_reason_col,"")) if fail_reason_col else ""

            # Parse error_code from result_type if numeric
            error_code = ""
            rt = result_type.strip()
            if rt:
                m = re.search(r"(\d{3,6})", rt)
                if m:
                    error_code = m.group(1)

            risk_level = safe_str(row.get(risk_level_col,"")) if risk_level_col else ""
            risk_state = safe_str(row.get(risk_state_col,"")) if risk_state_col else ""
            risk_detail = safe_str(row.get(risk_detail_col,"")) if risk_detail_col else ""

            country = safe_str(row.get(country_col,"")) if country_col else ""
            state = safe_str(row.get(state_col,"")) if state_col else ""
            city = safe_str(row.get(city_col,"")) if city_col else ""

            raw_json = json.dumps({c: safe_str(row.get(c,"")) for c in df.columns}, ensure_ascii=False)

            batch.append((
                file_id, rownum, te_int, ts_iso, user, ip, app, client_app, user_agent, device_id, corr,
                result_type, error_code, fail_reason, status, risk_level, risk_state, risk_detail,
                country, state, city, raw_json
            ))

        if len(batch) >= 5000:
            db_bulk_insert_signin(conn, batch)
            conn.commit()
            batch.clear()

        if verbosity >= 2 and chunk_i % 5 == 0:
            logging.debug(f"[signin] {path.name}: processed {total_rows} rows...")

    if batch:
        db_bulk_insert_signin(conn, batch)
        conn.commit()

    return total_rows, min_epoch, max_epoch


# -----------------------------
# Ingestion: Unified Audit Log (UAL)
# -----------------------------

UAL_TIME_CANDIDATES = [
    "CreationDate","CreationTime","TimeGenerated","Timestamp","Date","creationDate"
]

def _try_json(s: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(s)
    except Exception:
        return None


def ingest_ual_file(conn: sqlite3.Connection, path: Path, file_id: int, delimiter: str, chunk_rows: int, verbosity: int) -> Tuple[int, Optional[int], Optional[int]]:
    head = read_csv_any(path, delimiter, nrows=0)
    cols = [c.strip() for c in head.columns]

    time_col = find_col(cols, UAL_TIME_CANDIDATES) or auto_detect_time_column(path, delimiter)
    if not time_col:
        logging.warning(f"[skip] no timestamp column found in {path.name} (signin).")
        return 0, None, None

    auditdata_col = find_col(cols, ["AuditData","auditData"])
    op_col = find_col(cols, ["Operation","Operations"])
    user_col = find_col(cols, ["UserId","UserIds","User","Actor","ActorUserId"])
    ip_col = find_col(cols, ["ClientIP","Client IP","IPAddress","ipAddress","ClientIPAddress"])
    workload_col = find_col(cols, ["Workload"])
    rectype_col = find_col(cols, ["RecordType","recordType"])
    obj_col = find_col(cols, ["ObjectId","objectId","TargetObjectId","targetObjectId"])

    reader = read_csv_any(
        path, delimiter,
        chunksize=chunk_rows,
        dtype=str,
        keep_default_na=False,
        na_values=[""],
    )

    total_rows = 0
    min_epoch: Optional[int] = None
    max_epoch: Optional[int] = None

    batch: List[Tuple[Any,...]] = []
    for chunk_i, df in enumerate(reader, start=1):
        total_rows += len(df)
        ts = to_dt_series(df[time_col]) if time_col in df.columns else pd.to_datetime(pd.Series([None]*len(df)), utc=True)
        ts_epoch = ts.map(epoch_from_dt)

        ce_min = ts_epoch.dropna().min() if not ts_epoch.dropna().empty else None
        ce_max = ts_epoch.dropna().max() if not ts_epoch.dropna().empty else None
        if ce_min is not None:
            min_epoch = ce_min if min_epoch is None else min(min_epoch, int(ce_min))
        if ce_max is not None:
            max_epoch = ce_max if max_epoch is None else max(max_epoch, int(ce_max))

        for idx, row in df.iterrows():
            rownum = int(idx) + 1 + (chunk_i-1) * chunk_rows
            te = ts_epoch.iloc[idx] if idx < len(ts_epoch) else None
            te_int = int(te) if te is not None and str(te) != "nan" else None
            ts_iso = iso_from_epoch(te_int)

            user = safe_str(row.get(user_col,"")) if user_col else ""
            ip = safe_str(row.get(ip_col,"")) if ip_col else ""
            workload = safe_str(row.get(workload_col,"")) if workload_col else ""
            record_type = safe_str(row.get(rectype_col,"")) if rectype_col else ""
            object_id = safe_str(row.get(obj_col,"")) if obj_col else ""

            operation = ""
            auditdata = ""

            if op_col and op_col in df.columns:
                operation = safe_str(row.get(op_col,""))
            if auditdata_col and auditdata_col in df.columns:
                auditdata = safe_str(row.get(auditdata_col,""))
                if not operation:
                    ad = _try_json(auditdata)
                    if ad and isinstance(ad, dict):
                        operation = safe_str(ad.get("Operation",""))

            raw_json = json.dumps({c: safe_str(row.get(c,"")) for c in df.columns}, ensure_ascii=False)

            batch.append((
                file_id, rownum, te_int, ts_iso, user, ip, operation, workload, record_type, object_id, auditdata, raw_json
            ))

        if len(batch) >= 5000:
            db_bulk_insert_ual(conn, batch)
            conn.commit()
            batch.clear()

        if verbosity >= 2 and chunk_i % 5 == 0:
            logging.debug(f"[ual] {path.name}: processed {total_rows} rows...")

    if batch:
        db_bulk_insert_ual(conn, batch)
        conn.commit()

    return total_rows, min_epoch, max_epoch


# -----------------------------
# Rule engine (optional YAML)
# -----------------------------

def load_yaml_rules(rules_path: Optional[Path]) -> List[Dict[str, Any]]:
    if not rules_path:
        return []
    if not rules_path.exists():
        logging.warning(f"[rules] rules file not found: {rules_path}")
        return []

    try:
        import yaml  # type: ignore
    except Exception:
        logging.warning("[rules] pyyaml not installed; skipping YAML rules. Install with: pip install pyyaml")
        return []

    try:
        data = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    except Exception as e:
        logging.warning(f"[rules] failed to parse YAML: {e}")
        return []

    if not data:
        return []
    if isinstance(data, dict) and "rules" in data:
        data = data["rules"]
    if not isinstance(data, list):
        logging.warning("[rules] YAML must be a list or {rules: [...]}")
        return []

    rules: List[Dict[str, Any]] = []
    for r in data:
        if not isinstance(r, dict) or "name" not in r:
            continue
        rules.append(r)
    logging.info(f"[rules] loaded {len(rules)} rules from {rules_path}")
    return rules


def apply_rules(conn: sqlite3.Connection, rules: List[Dict[str, Any]], file_sha_map: Dict[int, str]) -> List[Finding]:
    findings: List[Finding] = []
    if not rules:
        return findings

    def match_rule_text(rule: Dict[str, Any], text: str) -> bool:
        # supports contains_any / contains_all / regex
        m = rule.get("match", {}) or {}
        text_l = text.lower()

        ca = m.get("contains_any")
        if ca:
            if not any(str(x).lower() in text_l for x in ca):
                return False
        cb = m.get("contains_all")
        if cb:
            if not all(str(x).lower() in text_l for x in cb):
                return False
        rx = m.get("regex")
        if rx:
            if not re.search(rx, text, flags=re.IGNORECASE):
                return False
        return True

    for rule in rules:
        family = str(rule.get("family", "")).lower().strip()
        severity = str(rule.get("severity", "medium")).lower().strip()
        category = str(rule.get("category", "custom_rule")).strip()
        title = str(rule.get("title", rule.get("name", "Custom rule"))).strip()
        name = str(rule.get("name", title)).strip()

        if family == "ual":
            cur = conn.execute("SELECT file_id,rownum,ts_iso,user,ip,operation,auditdata FROM ual")
            for file_id,rownum,ts_iso,user,ip,op,auditdata in cur:
                text = f"{op}\n{auditdata}"
                if not match_rule_text(rule, text):
                    continue
                sha = file_sha_map.get(int(file_id), "")
                fid = f"RULE-{name}-{file_id}-{rownum}"
                findings.append(Finding(
                    finding_id=fid,
                    severity=severity,
                    category=category,
                    title=title,
                    timestamp=safe_str(ts_iso),
                    user=safe_str(user),
                    ip=safe_str(ip),
                    country="",
                    file=str(file_id),
                    rownum=str(rownum),
                    sha256=sha,
                    details=safe_str(rule.get("description","")),
                    evidence={"rule": rule, "operation": op}
                ))
        elif family == "signin":
            cur = conn.execute("SELECT file_id,rownum,ts_iso,user,ip,app,client_app,status,result_type,error_code,failure_reason,raw_json FROM signin")
            for (file_id,rownum,ts_iso,user,ip,app,client_app,status,result_type,error_code,failure_reason,raw_json) in cur:
                text = f"{app}\n{client_app}\n{status}\n{result_type}\n{error_code}\n{failure_reason}\n{raw_json}"
                if not match_rule_text(rule, text):
                    continue
                sha = file_sha_map.get(int(file_id), "")
                fid = f"RULE-{name}-{file_id}-{rownum}"
                findings.append(Finding(
                    finding_id=fid,
                    severity=severity,
                    category=category,
                    title=title,
                    timestamp=safe_str(ts_iso),
                    user=safe_str(user),
                    ip=safe_str(ip),
                    country="",
                    file=str(file_id),
                    rownum=str(rownum),
                    sha256=sha,
                    details=safe_str(rule.get("description","")),
                    evidence={"rule": rule, "app": app, "client_app": client_app}
                ))

    return findings


# -----------------------------
# Detections
# -----------------------------

def _is_success_signin(result_type: str, status: str) -> bool:
    rt = safe_str(result_type).strip()
    st = safe_str(status).lower()
    # Many M365 exports: ResultType 0 => success
    if rt.isdigit():
        return int(rt) == 0
    # otherwise look for keywords
    if "success" in st:
        return True
    if "fail" in st or "error" in st or "denied" in st or "blocked" in st:
        return False
    return False


def _is_failure_signin(result_type: str, status: str) -> bool:
    rt = safe_str(result_type).strip()
    st = safe_str(status).lower()
    if rt.isdigit():
        return int(rt) != 0
    return bool(re.search(r"fail|error|denied|blocked", st))


def detect_risky_signins(conn: sqlite3.Connection, file_sha_map: Dict[int, str]) -> List[Finding]:
    findings: List[Finding] = []
    cur = conn.execute("""
        SELECT file_id,rownum,ts_iso,user,ip,country,app,client_app,risk_level,risk_state,risk_detail,raw_json
        FROM signin
    """)
    for file_id,rownum,ts_iso,user,ip,country,app,client_app,rl,rs,rd,raw in cur:
        rl_s = safe_str(rl).strip().lower()
        rs_s = safe_str(rs).strip().lower()
        rd_s = safe_str(rd).strip().lower()
        if not rl_s and not rs_s and not rd_s:
            continue
        if rl_s in {"none","low",""} and rs_s in {"none",""} and rd_s in {"none",""}:
            continue
        sha = file_sha_map.get(int(file_id), "")
        fid = f"RISKY-SIGNIN-{file_id}-{rownum}"
        findings.append(Finding(
            finding_id=fid,
            severity="high" if rl_s in {"high","medium"} or "at risk" in rs_s else "medium",
            category="risky_signin",
            title="Risky sign-in flagged by Entra risk fields",
            timestamp=safe_str(ts_iso),
            user=safe_str(user),
            ip=safe_str(ip),
            country=safe_str(country),
            file=str(file_id),
            rownum=str(rownum),
            sha256=sha,
            details=f"risk_level={rl} risk_state={rs} risk_detail={rd} app={app} client={client_app}",
            evidence={"risk_level": rl, "risk_state": rs, "risk_detail": rd, "app": app, "client_app": client_app}
        ))
    return findings


def detect_legacy_auth(conn: sqlite3.Connection, file_sha_map: Dict[int, str]) -> List[Finding]:
    findings: List[Finding] = []
    cur = conn.execute("""
        SELECT file_id,rownum,ts_iso,user,ip,country,app,client_app,result_type,status,error_code,failure_reason
        FROM signin
    """)
    for file_id,rownum,ts_iso,user,ip,country,app,client_app,rt,st,ec,fr in cur:
        txt = f"{app} {client_app}".lower()
        if not any(p in txt for p in LEGACY_CLIENT_PATTERNS):
            continue
        is_success = _is_success_signin(rt, st)
        sev = "high" if is_success else "medium"
        sha = file_sha_map.get(int(file_id), "")
        fid = f"LEGACY-AUTH-{file_id}-{rownum}"
        details = f"legacy_client='{client_app}' app='{app}' success={is_success}"
        if safe_str(ec):
            details += f" error_code={ec}"
        if safe_str(fr):
            details += f" reason={fr}"
        findings.append(Finding(
            finding_id=fid,
            severity=sev,
            category="legacy_auth",
            title="Legacy authentication / risky client protocol",
            timestamp=safe_str(ts_iso),
            user=safe_str(user),
            ip=safe_str(ip),
            country=safe_str(country),
            file=str(file_id),
            rownum=str(rownum),
            sha256=sha,
            details=details,
            evidence={"app": app, "client_app": client_app, "status": st, "result_type": rt}
        ))
    return findings


def detect_password_spray(conn: sqlite3.Connection, file_sha_map: Dict[int, str], window_minutes: int, min_failures: int, min_users: int) -> List[Finding]:
    """
    Password spray: 1 IP -> many users failures in a short window.
    """
    findings: List[Finding] = []
    win = int(window_minutes) * 60
    # bucket by epoch window
    cur = conn.execute("""
        SELECT ip, (ts_epoch / ?) as bucket, COUNT(*) as fails, COUNT(DISTINCT user) as users,
               MIN(ts_epoch) as min_ts, MAX(ts_epoch) as max_ts
        FROM signin
        WHERE ts_epoch IS NOT NULL
          AND ip != ''
          AND user != ''
          AND (result_type != '' OR status != '')
          AND (CASE WHEN result_type GLOB '[0-9]*' THEN CAST(result_type as INTEGER) != 0
                    ELSE lower(status) LIKE '%fail%' OR lower(status) LIKE '%error%' OR lower(status) LIKE '%denied%' OR lower(status) LIKE '%blocked%' END)
        GROUP BY ip, bucket
        HAVING fails >= ? AND users >= ?
        ORDER BY fails DESC, users DESC
        LIMIT 200
    """, (win, min_failures, min_users))
    for ip,bucket,fails,users,min_ts,max_ts in cur:
        fid = f"SPRAY-{ip}-{bucket}"
        findings.append(Finding(
            finding_id=fid,
            severity="high",
            category="password_spray",
            title="Password spray suspected",
            timestamp=iso_from_epoch(int(min_ts)) if min_ts else "",
            user="",
            ip=safe_str(ip),
            country="",
            file="multiple",
            rownum="",
            sha256="",
            details=f"failures={fails} distinct_users={users} window={window_minutes}m start={iso_from_epoch(int(min_ts))} end={iso_from_epoch(int(max_ts))}",
            evidence={"ip": ip, "failures": int(fails), "distinct_users": int(users), "window_minutes": window_minutes,
                      "start": iso_from_epoch(int(min_ts)), "end": iso_from_epoch(int(max_ts))}
        ))
    return findings


def detect_bruteforce(conn: sqlite3.Connection, file_sha_map: Dict[int, str], window_minutes: int, min_failures: int, min_ips: int) -> List[Finding]:
    """
    Brute force: 1 user -> many IP failures in a window.
    """
    findings: List[Finding] = []
    win = int(window_minutes) * 60
    cur = conn.execute("""
        SELECT user, (ts_epoch / ?) as bucket, COUNT(*) as fails, COUNT(DISTINCT ip) as ips,
               MIN(ts_epoch) as min_ts, MAX(ts_epoch) as max_ts
        FROM signin
        WHERE ts_epoch IS NOT NULL
          AND ip != ''
          AND user != ''
          AND (result_type != '' OR status != '')
          AND (CASE WHEN result_type GLOB '[0-9]*' THEN CAST(result_type as INTEGER) != 0
                    ELSE lower(status) LIKE '%fail%' OR lower(status) LIKE '%error%' OR lower(status) LIKE '%denied%' OR lower(status) LIKE '%blocked%' END)
        GROUP BY user, bucket
        HAVING fails >= ? AND ips >= ?
        ORDER BY fails DESC, ips DESC
        LIMIT 200
    """, (win, min_failures, min_ips))
    for user,bucket,fails,ips,min_ts,max_ts in cur:
        fid = f"BRUTE-{user}-{bucket}"
        findings.append(Finding(
            finding_id=fid,
            severity="medium",
            category="bruteforce",
            title="Brute force suspected",
            timestamp=iso_from_epoch(int(min_ts)) if min_ts else "",
            user=safe_str(user),
            ip="",
            country="",
            file="multiple",
            rownum="",
            sha256="",
            details=f"failures={fails} distinct_ips={ips} window={window_minutes}m start={iso_from_epoch(int(min_ts))} end={iso_from_epoch(int(max_ts))}",
            evidence={"user": user, "failures": int(fails), "distinct_ips": int(ips), "window_minutes": window_minutes,
                      "start": iso_from_epoch(int(min_ts)), "end": iso_from_epoch(int(max_ts))}
        ))
    return findings


def detect_success_after_failures(conn: sqlite3.Connection, file_sha_map: Dict[int, str], max_minutes: int = 30, min_fails: int = 5) -> List[Finding]:
    """
    For each user: N failures then a success within max_minutes.
    """
    findings: List[Finding] = []
    # get users with both fails and successes
    users = [r[0] for r in conn.execute("""
        SELECT user
        FROM signin
        WHERE user != '' AND ts_epoch IS NOT NULL
        GROUP BY user
        HAVING SUM(CASE WHEN (CASE WHEN result_type GLOB '[0-9]*' THEN CAST(result_type as INTEGER) != 0
                                  ELSE lower(status) LIKE '%fail%' OR lower(status) LIKE '%error%' OR lower(status) LIKE '%denied%' OR lower(status) LIKE '%blocked%' END)
                        THEN 1 ELSE 0 END) >= ?
           AND SUM(CASE WHEN (CASE WHEN result_type GLOB '[0-9]*' THEN CAST(result_type as INTEGER) = 0
                                  ELSE lower(status) LIKE '%success%' END)
                        THEN 1 ELSE 0 END) >= 1
        LIMIT 2000
    """, (min_fails,))]

    window = max_minutes * 60
    for user in users:
        cur = conn.execute("""
            SELECT file_id,rownum,ts_epoch,ts_iso,ip,country,app,client_app,result_type,status,error_code,failure_reason
            FROM signin
            WHERE user=? AND ts_epoch IS NOT NULL
            ORDER BY ts_epoch ASC
        """, (user,))
        # sliding count
        fails: List[Tuple[int,str,str]] = []  # (epoch, ip, file_id-rownum)
        for file_id,rownum,ts_epoch,ts_iso,ip,country,app,client_app,rt,st,ec,fr in cur:
            is_fail = _is_failure_signin(rt, st)
            is_succ = _is_success_signin(rt, st)
            te = int(ts_epoch)
            # prune old fails
            fails = [(t,i,ref) for (t,i,ref) in fails if te - t <= window]
            if is_fail:
                fails.append((te, safe_str(ip), f"{file_id}:{rownum}"))
                continue
            if is_succ and len(fails) >= min_fails:
                # evidence summary
                ip_counts = Counter(i for _,i,_ in fails if i)
                sha = file_sha_map.get(int(file_id), "")
                fid = f"SAF-{user}-{file_id}-{rownum}-{te}"
                details = f"{len(fails)} failures then success within {max_minutes}m; success_ip={ip} app={app} client={client_app}"
                if safe_str(ec) in AADSTS_HINTS:
                    details += f" ({AADSTS_HINTS[safe_str(ec)]})"
                findings.append(Finding(
                    finding_id=fid,
                    severity="high",
                    category="success_after_failures",
                    title="Success after multiple failures (possible compromise)",
                    timestamp=safe_str(ts_iso),
                    user=safe_str(user),
                    ip=safe_str(ip),
                    country=safe_str(country),
                    file=str(file_id),
                    rownum=str(rownum),
                    sha256=sha,
                    details=details,
                    evidence={
                        "fail_count": len(fails),
                        "fail_ips_top": ip_counts.most_common(10),
                        "fail_refs": fails[:50],
                        "success": {"file_id": file_id, "rownum": rownum, "ip": ip, "app": app, "client_app": client_app},
                        "window_minutes": max_minutes,
                    }
                ))
                # reset to avoid duplicate findings for next successes
                fails.clear()

    return findings


def detect_impossible_travel(conn: sqlite3.Connection, file_sha_map: Dict[int, str], max_minutes: int = 60) -> List[Finding]:
    """
    If country changes between successful sign-ins within max_minutes.
    Needs country field present; otherwise no findings.
    """
    findings: List[Finding] = []
    window = max_minutes * 60
    users = [r[0] for r in conn.execute("""
        SELECT user FROM signin
        WHERE user != '' AND ts_epoch IS NOT NULL AND country != ''
        GROUP BY user
        HAVING COUNT(*) >= 2
        LIMIT 5000
    """)]
    for user in users:
        cur = conn.execute("""
            SELECT file_id,rownum,ts_epoch,ts_iso,ip,country,app,client_app,result_type,status
            FROM signin
            WHERE user=? AND ts_epoch IS NOT NULL AND country != ''
            ORDER BY ts_epoch ASC
        """, (user,))
        prev = None
        for file_id,rownum,ts_epoch,ts_iso,ip,country,app,client_app,rt,st in cur:
            if not _is_success_signin(rt, st):
                continue
            now = (int(ts_epoch), safe_str(country), safe_str(ip), str(file_id), str(rownum), safe_str(ts_iso))
            if prev:
                dt = now[0] - prev[0]
                if dt >= 0 and dt <= window and now[1] and prev[1] and now[1] != prev[1]:
                    sha = file_sha_map.get(int(file_id), "")
                    fid = f"IMPTRAVEL-{user}-{file_id}-{rownum}-{ts_epoch}"
                    findings.append(Finding(
                        finding_id=fid,
                        severity="high",
                        category="impossible_travel",
                        title="Impossible travel / rapid country change",
                        timestamp=safe_str(ts_iso),
                        user=safe_str(user),
                        ip=safe_str(ip),
                        country=safe_str(country),
                        file=str(file_id),
                        rownum=str(rownum),
                        sha256=sha,
                        details=f"Successful sign-in from {prev[1]} -> {now[1]} in {dt//60}m",
                        evidence={
                            "prev": {"ts": prev[5], "country": prev[1], "ip": prev[2], "ref": f"{prev[3]}:{prev[4]}"},
                            "now": {"ts": now[5], "country": now[1], "ip": now[2], "ref": f"{now[3]}:{now[4]}"},
                            "delta_seconds": dt,
                        }
                    ))
            prev = now
    return findings


def classify_ual_operation(op: str) -> str:
    op_l = safe_str(op).lower()
    for pat in UAL_SUSPICIOUS_PATTERNS["high"]:
        if re.search(pat, op_l):
            return "high"
    for pat in UAL_SUSPICIOUS_PATTERNS["medium"]:
        if re.search(pat, op_l):
            return "medium"
    return ""


def extract_oauth_scopes_from_auditdata(auditdata: str) -> List[str]:
    ad = _try_json(auditdata)
    scopes: List[str] = []
    if not ad or not isinstance(ad, dict):
        return scopes
    # Common places: ModifiedProperties / Parameters / ConsentContext / OAuth2PermissionGrant
    txt = json.dumps(ad, ensure_ascii=False).lower()
    # quick regex for scopes-like strings
    for m in re.finditer(r"scope[s]?[\"']?\s*[:=]\s*[\"']([^\"']+)[\"']", txt):
        raw = m.group(1)
        for s in re.split(r"[ ,]+", raw):
            s = s.strip()
            if s and len(s) <= 60:
                scopes.append(s)
    # also look for "mail.readwrite" etc anywhere
    for s in DANGEROUS_OAUTH_SCOPES:
        if s in txt and s not in scopes:
            scopes.append(s)
    return sorted(set(scopes))


def detect_ual_suspicious(conn: sqlite3.Connection, file_sha_map: Dict[int, str]) -> List[Finding]:
    findings: List[Finding] = []
    cur = conn.execute("""
        SELECT file_id,rownum,ts_iso,ts_epoch,user,ip,operation,workload,record_type,object_id,auditdata
        FROM ual
    """)
    for file_id,rownum,ts_iso,ts_epoch,user,ip,op,workload,record_type,obj,auditdata in cur:
        sev = classify_ual_operation(op)

        # Performance: only scan heavy AuditData blobs when the operation looks interesting.
        # If the operation is unknown but contains strong hints, treat as medium.
        if not sev:
            op_l = safe_str(op).lower()
            if any(t in op_l for t in ("mailbox", "inbox", "transport", "role", "permission", "delegate", "consent", "oauth", "forward", "redirect")):
                sev = "medium"
            else:
                continue

        audit = safe_str(auditdata)

        # Boost if forwarding / inbox-rule traits exist in AuditData (high signal of BEC / exfil)
        forwarding = bool(FORWARD_RE.search(audit))
        inboxrule = bool(INBOX_RULE_RE.search(audit)) or "inboxrule" in safe_str(op).lower()
        if forwarding:
            sev = "high"
        if sev:

            sha = file_sha_map.get(int(file_id), "")
            fid = f"UAL-{file_id}-{rownum}"
            details = f"operation={op} workload={workload} record_type={record_type}"
            if forwarding:
                details += " forwarding_indicator=true"
            if inboxrule:
                details += " inbox_rule_indicator=true"
            scopes = extract_oauth_scopes_from_auditdata(auditdata) if auditdata else []
            if scopes:
                dangerous = [s for s in scopes if s in DANGEROUS_OAUTH_SCOPES]
                if dangerous:
                    sev = "high"
                    details += f" dangerous_scopes={dangerous}"
            findings.append(Finding(
                finding_id=fid,
                severity=sev,
                category="ual_suspicious_operation",
                title="Suspicious Unified Audit Log operation",
                timestamp=safe_str(ts_iso),
                user=safe_str(user),
                ip=safe_str(ip),
                country="",
                file=str(file_id),
                rownum=str(rownum),
                sha256=sha,
                details=details,
                evidence={"operation": op, "workload": workload, "record_type": record_type, "object_id": obj,
                          "forwarding": forwarding, "inboxrule": inboxrule, "scopes": scopes}
            ))
    return findings


def detect_mailitems_spike(conn: sqlite3.Connection, file_sha_map: Dict[int, str], window_minutes: int = 60, threshold: int = 500) -> List[Finding]:
    """
    Exfil / mailbox hunting indicator: MailItemsAccessed spikes per user per window.
    Uses ual.operation matching MailItemsAccessed variants or auditdata contains.
    """
    findings: List[Finding] = []
    win = int(window_minutes) * 60
    # operation matching
    cur = conn.execute("""
        SELECT user, (ts_epoch / ?) as bucket, COUNT(*) as cnt, MIN(ts_epoch) as min_ts, MAX(ts_epoch) as max_ts
        FROM ual
        WHERE ts_epoch IS NOT NULL AND user != ''
          AND (
                lower(operation) LIKE '%mailbox%'
             OR lower(operation) LIKE '%inbox%'
             OR lower(operation) LIKE '%transport%'
             OR lower(operation) LIKE '%role%'
             OR lower(operation) LIKE '%permission%'
             OR lower(operation) LIKE '%delegate%'
             OR lower(operation) LIKE '%consent%'
             OR lower(operation) LIKE '%oauth%'
             OR lower(operation) LIKE '%forward%'
             OR lower(operation) LIKE '%redirect%'
             OR auditdata LIKE '%Forward%'
             OR auditdata LIKE '%Redirect%'
             OR auditdata LIKE '%DeliverToMailboxAndForward%'
             OR auditdata LIKE '%ForwardingSmtpAddress%'
          )
          AND (
              lower(operation) LIKE '%mailitemsaccessed%' OR lower(operation) LIKE '%mailread%'
              OR lower(auditdata) LIKE '%mailitemsaccessed%'
          )
        GROUP BY user, bucket
        HAVING cnt >= ?
        ORDER BY cnt DESC
        LIMIT 200
    """, (win, threshold))
    for user,bucket,cnt,min_ts,max_ts in cur:
        fid = f"MAILSPIKE-{user}-{bucket}"
        findings.append(Finding(
            finding_id=fid,
            severity="high",
            category="mailitems_access_spike",
            title="MailItemsAccessed spike (possible mailbox hunting / exfil)",
            timestamp=iso_from_epoch(int(min_ts)) if min_ts else "",
            user=safe_str(user),
            ip="",
            country="",
            file="multiple",
            rownum="",
            sha256="",
            details=f"count={cnt} in {window_minutes}m window start={iso_from_epoch(int(min_ts))} end={iso_from_epoch(int(max_ts))}",
            evidence={"user": user, "count": int(cnt), "window_minutes": window_minutes,
                      "start": iso_from_epoch(int(min_ts)), "end": iso_from_epoch(int(max_ts))}
        ))
    return findings


def correlate_ual_with_signin(conn: sqlite3.Connection, file_sha_map: Dict[int, str], max_minutes: int = 60) -> List[Finding]:
    """
    For each UAL suspicious op, find last successful sign-in within max_minutes for same user.
    Escalate severity if sign-in was legacy/risky or country mismatch.
    """
    findings: List[Finding] = []
    window = max_minutes * 60

    # Pull UAL suspicious subset first (we use the same patterns as detect_ual_suspicious)
    cur = conn.execute("""
        SELECT file_id,rownum,ts_epoch,ts_iso,user,ip,operation,workload,auditdata
        FROM ual
        WHERE ts_epoch IS NOT NULL AND user != ''
    """)
    for file_id,rownum,ts_epoch,ts_iso,user,ip,op,workload,auditdata in cur:
        sev0 = classify_ual_operation(op)
        if not sev0:
            # allow forwarding/inboxrule triggers even if op is bland
            audit = safe_str(auditdata)
            if not (FORWARD_RE.search(audit) or INBOX_RULE_RE.search(audit)):
                continue
            sev0 = "high"

        te = int(ts_epoch)
        # find last success sign-in
        s = conn.execute("""
            SELECT ts_epoch,ts_iso,ip,country,app,client_app,risk_level,risk_state,risk_detail,result_type,status
            FROM signin
            WHERE user=? AND ts_epoch IS NOT NULL AND ts_epoch <= ?
            ORDER BY ts_epoch DESC
            LIMIT 5
        """, (user, te)).fetchall()

        best = None
        for r in s:
            if _is_success_signin(r[9], r[10]):
                best = r
                break

        if not best:
            continue

        dt = te - int(best[0])
        if dt < 0 or dt > window:
            continue

        signin_ip = safe_str(best[2])
        signin_country = safe_str(best[3])
        signin_client = safe_str(best[5])
        rl = safe_str(best[6]).lower()
        rs = safe_str(best[7]).lower()
        rd = safe_str(best[8]).lower()

        riskish = any(x and x not in {"none","low"} for x in [rl,rs,rd])
        legacyish = any(p in (signin_client.lower() + " " + safe_str(best[4]).lower()) for p in LEGACY_CLIENT_PATTERNS)

        sev = "high" if sev0 == "high" else "medium"
        notes = []
        if riskish:
            sev = "high"
            notes.append("prior_signin_risky=true")
        if legacyish:
            sev = "high"
            notes.append("prior_signin_legacy=true")
        if signin_ip and ip and signin_ip != ip:
            notes.append("ip_mismatch=true")
        if signin_country and signin_country.strip() and signin_country != "" and signin_country != " ":
            # some ual rows don't have country; ignore
            pass

        sha = file_sha_map.get(int(file_id), "")
        fid = f"CORR-UAL-SIGNIN-{file_id}-{rownum}"
        findings.append(Finding(
            finding_id=fid,
            severity=sev,
            category="correlation_signin_ual",
            title="UAL sensitive action correlated to prior successful sign-in",
            timestamp=safe_str(ts_iso),
            user=safe_str(user),
            ip=safe_str(ip),
            country="",
            file=str(file_id),
            rownum=str(rownum),
            sha256=sha,
            details=f"UAL op '{op}' within {dt//60}m of successful sign-in (client={signin_client}). " + " ".join(notes),
            evidence={
                "ual": {"operation": op, "workload": workload, "ip": ip, "ref": f"{file_id}:{rownum}"},
                "signin": {"ts": best[1], "ip": signin_ip, "country": signin_country, "app": best[4], "client": signin_client,
                           "risk_level": best[6], "risk_state": best[7], "risk_detail": best[8]},
                "delta_seconds": dt,
                "notes": notes,
            }
        ))

    return findings


def detect_bec_checklist(conn: sqlite3.Connection) -> Dict[str, Any]:
    """
    BEC indicators summary:
    - forwarding/redirect to external domains
    - inbox rules hiding/deleting/moving
    - mailbox permissions / delegations changes
    Returns an aggregated dictionary for reporting.
    """
    out: Dict[str, Any] = {
        "forwarding_events": [],
        "inbox_rule_events": [],
        "delegation_events": [],
        "external_forward_domains_top": [],
    }
    domains = Counter()

    cur = conn.execute("""
        SELECT ts_iso,user,ip,operation,auditdata,file_id,rownum
        FROM ual
        WHERE lower(auditdata) LIKE '%forward%' OR lower(operation) LIKE '%inboxrule%' OR lower(auditdata) LIKE '%inboxrule%'
        LIMIT 50000
    """)
    for ts_iso,user,ip,op,auditdata,file_id,rownum in cur:
        ad_l = safe_str(auditdata).lower()
        op_l = safe_str(op).lower()
        ref = f"{file_id}:{rownum}"

        # forwarding
        if any(k in ad_l for k in FORWARDING_KEYWORDS):
            # crude extraction of external domains from auditdata text
            for m in re.finditer(r"([a-z0-9._%+\-]+)@([a-z0-9.\-]+\.[a-z]{2,})", ad_l, flags=re.I):
                domains[m.group(2).lower()] += 1
            out["forwarding_events"].append({"ts": ts_iso, "user": user, "ip": ip, "operation": op, "ref": ref})

        # inbox rule suspicious actions
        if "inbox" in op_l or any(k in ad_l for k in INBOX_RULE_KEYWORDS):
            out["inbox_rule_events"].append({"ts": ts_iso, "user": user, "ip": ip, "operation": op, "ref": ref})

        # delegation / permissions
        if re.search(r"add-mailboxpermission|add-mailboxfolderpermission|set-mailboxfolderpermission|delegate", op_l):
            out["delegation_events"].append({"ts": ts_iso, "user": user, "ip": ip, "operation": op, "ref": ref})

    out["external_forward_domains_top"] = domains.most_common(25)
    return out


# -----------------------------
# Timeline & case views
# -----------------------------

def export_timeline(conn: sqlite3.Connection, outdir: Path, mode: str = "deep") -> Tuple[Path, Path]:
    """
    Exports normalized timeline of key events.
    In quick mode: only findings-level / suspicious events.
    In deep mode: include successes & failures (bounded).
    """
    timeline_rows: List[Dict[str, Any]] = []

    # UAL: always include suspicious-looking ops
    cur = conn.execute("""
        SELECT ts_epoch,ts_iso,user,ip,operation,workload,file_id,rownum,auditdata
        FROM ual
        WHERE ts_epoch IS NOT NULL
        ORDER BY ts_epoch ASC
        LIMIT 200000
    """)
    for ts_epoch,ts_iso,user,ip,op,workload,file_id,rownum,auditdata in cur:
        op_l = safe_str(op).lower()
        ad_l = safe_str(auditdata).lower()
        suspicious = bool(classify_ual_operation(op) or any(k in ad_l for k in FORWARDING_KEYWORDS + INBOX_RULE_KEYWORDS) or "mailitemsaccessed" in op_l)
        if mode == "quick" and not suspicious:
            continue
        timeline_rows.append({
            "ts": safe_str(ts_iso),
            "epoch": ts_epoch,
            "source": "ual",
            "user": safe_str(user),
            "ip": safe_str(ip),
            "action": safe_str(op),
            "detail": safe_str(workload),
            "ref": f"{file_id}:{rownum}",
        })

    # Sign-ins: in deep mode include both fails and successes (bounded)
    if mode != "quick":
        cur = conn.execute("""
            SELECT ts_epoch,ts_iso,user,ip,app,client_app,result_type,status,error_code,failure_reason,file_id,rownum,country
            FROM signin
            WHERE ts_epoch IS NOT NULL
            ORDER BY ts_epoch ASC
            LIMIT 300000
        """)
        for ts_epoch,ts_iso,user,ip,app,client_app,rt,st,ec,fr,file_id,rownum,country in cur:
            is_fail = _is_failure_signin(rt, st)
            is_succ = _is_success_signin(rt, st)
            action = "signin_failure" if is_fail else "signin_success" if is_succ else "signin_event"
            detail = f"app={app} client={client_app} status={st} result={rt}"
            if safe_str(ec):
                detail += f" error_code={ec}"
            if safe_str(fr):
                detail += f" reason={fr}"
            if safe_str(country):
                detail += f" country={country}"
            timeline_rows.append({
                "ts": safe_str(ts_iso),
                "epoch": ts_epoch,
                "source": "signin",
                "user": safe_str(user),
                "ip": safe_str(ip),
                "action": action,
                "detail": detail,
                "ref": f"{file_id}:{rownum}",
            })

    timeline_rows.sort(key=lambda r: (r.get("epoch") or 0, r.get("source","")))

    csv_path = outdir / "timeline.csv"
    jsonl_path = outdir / "timeline.jsonl"

    pd.DataFrame(timeline_rows).to_csv(csv_path, index=False)
    with jsonl_path.open("w", encoding="utf-8") as f:
        for r in timeline_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    return csv_path, jsonl_path


def export_case_views(conn: sqlite3.Connection, outdir: Path, max_users: int = 50) -> None:
    """
    Generate per-user case markdown views:
    - summary of sign-in patterns
    - suspicious UAL actions
    - compact timeline
    """
    cases_dir = outdir / "cases"
    ensure_dir(cases_dir)

    # Users with most UAL events + sign-in failures
    users = [r[0] for r in conn.execute("""
        SELECT user FROM (
            SELECT user, COUNT(*) as c FROM ual WHERE user != '' GROUP BY user
            UNION ALL
            SELECT user, COUNT(*) as c FROM signin WHERE user != '' GROUP BY user
        )
        GROUP BY user
        ORDER BY SUM(c) DESC
        LIMIT ?
    """, (max_users,))]

    for user in users:
        # Pull sign-in summary
        sign_summary = conn.execute("""
            SELECT
              SUM(CASE WHEN (CASE WHEN result_type GLOB '[0-9]*' THEN CAST(result_type as INTEGER) = 0
                                 ELSE lower(status) LIKE '%success%' END) THEN 1 ELSE 0 END) as success,
              SUM(CASE WHEN (CASE WHEN result_type GLOB '[0-9]*' THEN CAST(result_type as INTEGER) != 0
                                 ELSE lower(status) LIKE '%fail%' OR lower(status) LIKE '%error%' OR lower(status) LIKE '%denied%' OR lower(status) LIKE '%blocked%' END) THEN 1 ELSE 0 END) as fail,
              COUNT(DISTINCT ip) as ips
            FROM signin WHERE user=?
        """, (user,)).fetchone()
        succ = int(sign_summary[0] or 0)
        fail = int(sign_summary[1] or 0)
        ips = int(sign_summary[2] or 0)

        # Last 200 events timeline for user (both)
        ev: List[Dict[str, Any]] = []
        cur = conn.execute("""
            SELECT 'signin' as src, ts_epoch, ts_iso, ip, app, client_app, status, result_type, error_code, failure_reason, file_id, rownum
            FROM signin
            WHERE user=? AND ts_epoch IS NOT NULL
            UNION ALL
            SELECT 'ual' as src, ts_epoch, ts_iso, ip, operation, workload, '', '', '', '', file_id, rownum
            FROM ual
            WHERE user=? AND ts_epoch IS NOT NULL
            ORDER BY ts_epoch ASC
        """, (user, user))
        for row in cur:
            src, ts_epoch, ts_iso, ip, a, b, st, rt, ec, fr, file_id, rownum = row
            if src == "signin":
                action = "signin"
                detail = f"app={a} client={b} status={st} result={rt}"
                if ec:
                    detail += f" ec={ec}"
                if fr:
                    detail += f" fr={fr}"
            else:
                action = "ual"
                detail = f"op={a} workload={b}"
            ev.append({"ts": ts_iso, "src": src, "ip": ip, "action": action, "detail": detail, "ref": f"{file_id}:{rownum}"})

        ev = ev[-200:]

        md = []
        md.append(f"# Case view: {user}")
        md.append("")
        md.append("## Summary")
        md.append(f"- Sign-ins: success={succ} fail={fail} distinct_ips={ips}")
        md.append("")
        md.append("## Recent timeline (last 200 events)")
        md.append(md_table(ev, headers=["ts","src","ip","action","detail","ref"], max_rows=200))
        (cases_dir / f"{user.replace('@','_at_').replace('/','_')}.md").write_text("\n".join(md), encoding="utf-8")


# -----------------------------
# Reporting (MD + HTML + optional XLSX)
# -----------------------------

def findings_to_dataframe(findings: List[Finding]) -> pd.DataFrame:
    if not findings:
        return pd.DataFrame(columns=[
            "finding_id","severity","category","title","timestamp","user","ip","country","file","rownum","sha256","details","evidence_json"
        ])
    return pd.DataFrame([f.to_row() for f in findings])


def write_findings(findings: List[Finding], outdir: Path) -> Tuple[Path, Path]:
    ensure_dir(outdir)
    csv_path = outdir / "findings.csv"
    jsonl_path = outdir / "findings.jsonl"

    df = findings_to_dataframe(findings)
    # Severity ordering
    sev_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    if not df.empty:
        df["sev_rank"] = df["severity"].map(lambda x: sev_rank.get(str(x).lower(), 9))
        df["ts_sort"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
        df = df.sort_values(["sev_rank","ts_sort"]).drop(columns=["sev_rank","ts_sort"])
    df.to_csv(csv_path, index=False)

    with jsonl_path.open("w", encoding="utf-8") as f:
        for item in findings:
            f.write(json.dumps(item.to_json(), ensure_ascii=False) + "\n")

    return csv_path, jsonl_path


def write_file_ranges(conn: sqlite3.Connection, outdir: Path) -> Path:
    rows = []
    cur = conn.execute("SELECT file_id,name,family,rows,start_epoch,end_epoch,sha256,delimiter,skiprows,columns_json,error FROM files ORDER BY name")
    for file_id,name,family,r,start_e,end_e,sha,delim,skip,cols_json,err in cur:
        rows.append({
            "file_id": file_id,
            "name": name,
            "family": family,
            "rows": r,
            "start": iso_from_epoch(start_e),
            "end": iso_from_epoch(end_e),
            "sha256": sha,
            "delimiter": delim,
            "skiprows": skip,
            "columns": cols_json,
            "error": err or "",
        })
    df = pd.DataFrame(rows)
    p = outdir / "file_ranges.csv"
    df.to_csv(p, index=False)
    return p


def write_schema_profiles(conn: sqlite3.Connection, outdir: Path) -> Path:
    profiles = {}
    cur = conn.execute("SELECT file_id,name,profile_json FROM files")
    for file_id,name,prof_json in cur:
        try:
            profiles[str(file_id)] = json.loads(prof_json) if prof_json else {}
        except Exception:
            profiles[str(file_id)] = {}
    p = outdir / "schema_profiles.json"
    p.write_text(json.dumps(profiles, ensure_ascii=False, indent=2), encoding="utf-8")
    return p


def generate_report_md(conn: sqlite3.Connection, findings: List[Finding], bec: Dict[str, Any], outdir: Path) -> Path:
    ensure_dir(outdir)
    p = outdir / "report.md"

    # Coverage
    min_e = conn.execute("SELECT MIN(start_epoch) FROM files WHERE start_epoch IS NOT NULL").fetchone()[0]
    max_e = conn.execute("SELECT MAX(end_epoch) FROM files WHERE end_epoch IS NOT NULL").fetchone()[0]

    # Summary counts
    df = findings_to_dataframe(findings)
    sev_counts = df["severity"].value_counts().to_dict() if not df.empty else {}

    top_cats = df["category"].value_counts().head(20).to_dict() if not df.empty else {}

    # Top IPs for failures
    ip_fail = conn.execute("""
        SELECT ip, COUNT(*) as fails
        FROM signin
        WHERE ip != '' AND ts_epoch IS NOT NULL
          AND (CASE WHEN result_type GLOB '[0-9]*' THEN CAST(result_type as INTEGER) != 0
                    ELSE lower(status) LIKE '%fail%' OR lower(status) LIKE '%error%' OR lower(status) LIKE '%denied%' OR lower(status) LIKE '%blocked%' END)
        GROUP BY ip
        ORDER BY fails DESC
        LIMIT 20
    """).fetchall()

    # Top users for failures
    user_fail = conn.execute("""
        SELECT user, COUNT(*) as fails
        FROM signin
        WHERE user != '' AND ts_epoch IS NOT NULL
          AND (CASE WHEN result_type GLOB '[0-9]*' THEN CAST(result_type as INTEGER) != 0
                    ELSE lower(status) LIKE '%fail%' OR lower(status) LIKE '%error%' OR lower(status) LIKE '%denied%' OR lower(status) LIKE '%blocked%' END)
        GROUP BY user
        ORDER BY fails DESC
        LIMIT 20
    """).fetchall()

    md = []
    md.append("# M365 Offline Forensic Triage Report")
    md.append("")
    md.append("## Coverage")
    md.append(f"- Global start (UTC): {iso_from_epoch(min_e)}")
    md.append(f"- Global end (UTC): {iso_from_epoch(max_e)}")
    md.append("")
    md.append("## Findings summary")
    md.append(md_table([{"severity": k, "count": v} for k,v in sev_counts.items()], ["severity","count"], max_rows=10) if sev_counts else "_No findings._")
    md.append("")
    md.append("## Top categories")
    md.append(md_table([{"category": k, "count": v} for k,v in top_cats.items()], ["category","count"], max_rows=20) if top_cats else "_No categories._")
    md.append("")
    md.append("## High severity findings (top 50)")
    if not df.empty:
        high_df = df[df["severity"].str.lower() == "high"].head(50)
        md.append(md_table(high_df.to_dict(orient="records"), ["timestamp","category","title","user","ip","details"], max_rows=50) if not high_df.empty else "_No HIGH findings._")
    else:
        md.append("_No findings._")
    md.append("")
    md.append("## Sign-in failures: top IPs")
    md.append(md_table([{"ip": a, "fails": int(b)} for a,b in ip_fail], ["ip","fails"], max_rows=20) if ip_fail else "_No data._")
    md.append("")
    md.append("## Sign-in failures: top users")
    md.append(md_table([{"user": a, "fails": int(b)} for a,b in user_fail], ["user","fails"], max_rows=20) if user_fail else "_No data._")
    md.append("")
    md.append("## BEC indicators (summary)")
    md.append(f"- Forwarding-related events: {len(bec.get('forwarding_events', []))}")
    md.append(f"- Inbox-rule-related events: {len(bec.get('inbox_rule_events', []))}")
    md.append(f"- Delegation/permissions events: {len(bec.get('delegation_events', []))}")
    md.append("")
    md.append("### Top external domains seen in forwarding artifacts")
    md.append(md_table([{"domain": d, "count": c} for d,c in bec.get("external_forward_domains_top", [])], ["domain","count"], max_rows=25) if bec.get("external_forward_domains_top") else "_None detected._")
    md.append("")
    md.append("## Notes / Next steps")
    md.append("- Review HIGH findings first, then correlate with mailbox content checks, inbox rules, and suspicious OAuth consents.")
    md.append("- If you have additional logs (Defender for Office 365, Mailflow, EDR), ingest them for better correlation.")
    md.append("")
    p.write_text("\n".join(md), encoding="utf-8")
    return p



def _compress_text(s: Any, max_len: int = 800) -> str:
    """Limit long strings so the HTML payload stays manageable."""
    s2 = safe_str(s)
    if len(s2) <= max_len:
        return s2
    return s2[:max_len] + f"… (+{len(s2)-max_len} chars)"


def _compress_evidence(e: Dict[str, Any], max_len: int = 800) -> Dict[str, Any]:
    """Trim very large evidence blobs (auditdata/raw_json) for embedding in HTML."""
    out: Dict[str, Any] = {}
    for k, v in (e or {}).items():
        if isinstance(v, str):
            out[k] = _compress_text(v, max_len=max_len)
        else:
            # keep small primitives/dicts
            try:
                js = json.dumps(v, ensure_ascii=False)
                out[k] = v if len(js) <= max_len else _compress_text(js, max_len=max_len)
            except Exception:
                out[k] = _compress_text(v, max_len=max_len)
    return out


def build_report_data(conn: sqlite3.Connection,
                      findings: List[Finding],
                      bec: Dict[str, Any],
                      outdir: Path,
                      *,
                      logdir: Optional[Path] = None,
                      mode: str = "quick",
                      case_meta: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Build a JSON-serializable structure used by the visual HTML report.
    Keep it reasonably small and self-contained (offline-friendly).
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    cm = case_meta or {}
    case = {
        "report_title": cm.get("report_title") or "Microsoft 365 Forensic Triage Report",
        "case_id": cm.get("case_id") or "",
        "client": cm.get("client") or "",
        "analyst": cm.get("analyst") or "",
        "classification": cm.get("classification") or "CONFIDENTIAL",
    }

    # Coverage
    cur = conn.execute("SELECT MIN(start_epoch), MAX(end_epoch) FROM files WHERE start_epoch IS NOT NULL AND end_epoch IS NOT NULL")
    mn, mx = cur.fetchone() if cur else (None, None)
    cov = {
        "start": epoch_to_iso(mn) if mn else "",
        "end": epoch_to_iso(mx) if mx else "",
    }

    # File inventory
    files = []
    for row in conn.execute("""
        SELECT name,family,rows,sha256,delimiter,skiprows,start_epoch,end_epoch,path
        FROM files
        ORDER BY family,name
    """):
        name,fam,rows_n,sha,delim,skiprows,st,ed,path = row
        files.append({
            "name": name,
            "family": fam,
            "rows": int(rows_n or 0),
            "sha256": sha or "",
            "delimiter": delim or "",
            "skiprows": int(skiprows or 0),
            "start": epoch_to_iso(st) if st else "",
            "end": epoch_to_iso(ed) if ed else "",
            "path": path or "",
        })

    # Counts per family
    fam_counts = []
    for fam, total_rows in conn.execute("SELECT family, SUM(rows) FROM files GROUP BY family ORDER BY SUM(rows) DESC"):
        fam_counts.append({"family": fam, "rows": int(total_rows or 0)})

    # Findings summary
    sev_counts = Counter([f.severity.lower() for f in findings])
    cat_counts = Counter([f.category for f in findings])
    total_findings = len(findings)

    # Risk score (simple, explainable)
    score = 0
    score += 35 * sev_counts.get("critical", 0)
    score += 20 * sev_counts.get("high", 0)
    score += 8 * sev_counts.get("medium", 0)
    score += 2 * sev_counts.get("low", 0)
    score = min(100, score)

    # Impacted entities
    impacted_users = sorted({f.user for f in findings if f.user})
    impacted_ips = sorted({f.ip for f in findings if f.ip})
    impacted_countries = Counter([f.country for f in findings if f.country]).most_common(25)

    # Top sign-in failures by IP/user (fast SQL)
    top_fail_ips = []
    for ip, fails, users in conn.execute("""
        SELECT ip,
               SUM(CASE WHEN (result_type IS NOT NULL AND result_type != '0') OR (status LIKE '%fail%' OR status LIKE '%error%') THEN 1 ELSE 0 END) AS fails,
               COUNT(DISTINCT user) AS users
        FROM signin
        WHERE ip IS NOT NULL AND ip != ''
        GROUP BY ip
        ORDER BY fails DESC, users DESC
        LIMIT 25
    """):
        top_fail_ips.append({"ip": ip or "", "fails": int(fails or 0), "users": int(users or 0)})

    top_fail_users = []
    for user, fails, ips in conn.execute("""
        SELECT user,
               SUM(CASE WHEN (result_type IS NOT NULL AND result_type != '0') OR (status LIKE '%fail%' OR status LIKE '%error%') THEN 1 ELSE 0 END) AS fails,
               COUNT(DISTINCT ip) AS ips
        FROM signin
        WHERE user IS NOT NULL AND user != ''
        GROUP BY user
        ORDER BY fails DESC, ips DESC
        LIMIT 25
    """):
        top_fail_users.append({"user": user or "", "fails": int(fails or 0), "ips": int(ips or 0)})

    # Timeseries (by day) for sign-ins / UAL / findings
    def ts_by_day(table: str) -> List[Dict[str, Any]]:
        out = []
        try:
            for d, c in conn.execute(f"""
                SELECT DATE(ts_epoch, 'unixepoch') AS d, COUNT(*) AS c
                FROM {table}
                WHERE ts_epoch IS NOT NULL
                GROUP BY d
                ORDER BY d
            """):
                out.append({"date": d, "count": int(c or 0)})
        except Exception:
            pass
        return out

    signin_by_day = ts_by_day("signin")
    ual_by_day = ts_by_day("ual")

    # Findings by day (from list; cheap)
    f_by_day = Counter()
    for f in findings:
        if f.timestamp:
            try:
                # timestamp might be ISO already
                d = str(pd.to_datetime([f.timestamp], utc=True, errors="coerce")[0].date())
                if d != "NaT":
                    f_by_day[d] += 1
            except Exception:
                pass
    findings_by_day = [{"date": d, "count": c} for d, c in sorted(f_by_day.items())]

    # Heatmap: day-of-week x hour
    heat = [[0 for _ in range(24)] for _ in range(7)]
    try:
        for dow, hour, c in conn.execute("""
            SELECT CAST(STRFTIME('%w', ts_epoch, 'unixepoch') AS INTEGER) AS dow,
                   CAST(STRFTIME('%H', ts_epoch, 'unixepoch') AS INTEGER) AS hour,
                   COUNT(*) AS c
            FROM signin
            WHERE ts_epoch IS NOT NULL
            GROUP BY dow, hour
        """):
            if dow is None or hour is None:
                continue
            heat[int(dow)][int(hour)] = int(c or 0)
    except Exception:
        pass

    # Findings to embed in HTML: prioritize high/medium, cap to keep report snappy
    def sev_rank(s: str) -> int:
        s = (s or "").lower()
        return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(s, 9)

    sorted_findings = sorted(findings, key=lambda f: (sev_rank(f.severity), f.timestamp or ""))
    embed_findings = []
    for f in sorted_findings[:1500]:
        r = f.to_row()
        # compress evidence fields
        r["evidence"] = _compress_evidence(r.get("evidence", {}), max_len=800)
        r["details"] = _compress_text(r.get("details", ""), max_len=800)
        embed_findings.append(r)

    # Timeline (only from findings for readability)
    timeline = []
    for f in sorted_findings[:800]:
        if not f.timestamp:
            continue
        timeline.append({
            "ts": f.timestamp,
            "severity": f.severity,
            "title": f.title,
            "category": f.category,
            "user": f.user,
            "ip": f.ip,
            "ref": f"{f.file}:{f.rownum}" if (f.file and f.rownum) else "",
            "finding_id": f.finding_id
        })
    # sort timeline chronologically
    try:
        timeline.sort(key=lambda x: pd.to_datetime(x["ts"], utc=True, errors="coerce"))
    except Exception:
        pass

    # Helpful links (relative paths in outdir)
    links = {
        "report_md": "report.md",
        "report_data_json": "report_data.json",
        "findings_csv": "findings.csv",
        "findings_jsonl": "findings.jsonl",
        "timeline_csv": "timeline.csv",
        "timeline_jsonl": "timeline.jsonl",
        "file_ranges_csv": "file_ranges.csv",
        "schema_profiles_json": "schema_profiles.json",
        "db": "triage.sqlite",
        "cases_dir": "cases" if (outdir / "cases").exists() else "",
    }

    return {
        "meta": {
            "tool": "m365_triage",
            "version": TOOL_VERSION,
            "generated_at": now_iso,
            "mode": mode,
            "logdir": str(logdir) if logdir else "",
        },
    "case": case,
        "coverage": cov,
        "kpis": {
            "risk_score": score,
            "total_files": len(files),
            "total_findings": total_findings,
            "impacted_users": len(impacted_users),
            "impacted_ips": len(impacted_ips),
            "signin_rows": int(conn.execute("SELECT COUNT(*) FROM signin").fetchone()[0]),
            "ual_rows": int(conn.execute("SELECT COUNT(*) FROM ual").fetchone()[0]),
        },
        "counts": {
            "severity": dict(sev_counts),
            "category_top": cat_counts.most_common(20),
            "families": fam_counts,
        },
        "entities": {
            "impacted_users": impacted_users[:2000],
            "impacted_ips": impacted_ips[:2000],
            "impacted_countries_top": impacted_countries,
            "top_signin_fail_ips": top_fail_ips,
            "top_signin_fail_users": top_fail_users,
        },
        "timeseries": {
            "signin_by_day": signin_by_day,
            "ual_by_day": ual_by_day,
            "findings_by_day": findings_by_day,
            "signin_heatmap_dow_hour": heat,
        },
        "bec": bec,
        "files": files,
        "findings": embed_findings,
        "timeline": timeline,
        "links": links,
    }


def generate_report_html(conn: sqlite3.Connection,
                        findings: List[Finding],
                        bec: Dict[str, Any],
                        outdir: Path,
                        *,
                        logdir: Optional[Path] = None,
                        mode: str = "quick",
                        md_path: Optional[Path] = None,
                        case_meta: Optional[Dict[str, Any]] = None) -> Path:
    """
    Generate a single-file, offline-friendly HTML report (dashboard style).
    Also writes report_data.json next to it.
    """
    outdir.mkdir(parents=True, exist_ok=True)

    report_data = build_report_data(conn, findings, bec, outdir, logdir=logdir, mode=mode, case_meta=case_meta)
    now_iso = report_data.get("meta", {}).get("generated_at") or datetime.now(timezone.utc).isoformat()
    json_text = json.dumps(report_data, ensure_ascii=False, indent=2)
    (outdir / "report_data.json").write_text(json_text, encoding="utf-8")

    md_text = ""
    if md_path and Path(md_path).exists():
        try:
            md_text = Path(md_path).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            md_text = ""

    # Embed JSON safely: avoid closing <script> injection via </
    json_for_html = json_text.replace("</", "<\\/")

    
    HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>M365 Triage Report</title>
<style>
:root{
  color-scheme: light;
  --bg:#f5f7fb;
  --panel:#ffffff;
  --panel2:#f2f4f8;
  --text:#111827;
  --muted:#4b5563;
  --accent:#2563eb;
  --accent2:#1e40af;
  --danger:#dc2626;
  --warning:#d97706;
  --ok:#16a34a;
  --border:#e5e7eb;
  --shadow:rgba(17,24,39,0.10);
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0; background:var(--bg); color:var(--text);
  font-family:var(--sans); line-height:1.35;
}
a{color:inherit}
.container{display:flex; min-height:100vh}
.sidebar{
  width:280px; padding:22px 16px 18px; border-right:1px solid var(--border);
  position:sticky; top:0; height:100vh; background:linear-gradient(180deg,var(--panel),transparent);
}
.brand{display:flex; gap:12px; align-items:center; margin-bottom:18px}
.logo{
  width:42px; height:42px; border-radius:14px;
  background:radial-gradient(circle at 30% 30%, #7dd3fc, #60a5fa 35%, #3b82f6 60%, #1d4ed8);
  box-shadow: var(--shadow);
}
.brand h1{font-size:14px; margin:0}
.brand .sub{color:var(--muted); font-size:12px; margin-top:2px}
.nav{display:flex; flex-direction:column; gap:6px; margin-top:10px}
.nav a{
  text-decoration:none; padding:10px 12px; border-radius:12px;
  color:var(--muted); border:1px solid transparent;
}
.nav a:hover{background:var(--chip); color:var(--text)}
.nav a.active{background:var(--chip); color:var(--text); border:1px solid var(--border)}
.main{flex:1; padding:22px 26px 80px}
.topbar{
  display:flex; gap:14px; align-items:flex-start; justify-content:space-between; flex-wrap:wrap;
  margin-bottom:14px;
}
.title h2{margin:0; font-size:20px}
.meta{color:var(--muted); font-size:12px; margin-top:6px}
.actions{display:flex; gap:10px; align-items:center}
.btn{
  cursor:pointer; border:1px solid var(--border); background:var(--panel);
  color:var(--text); padding:10px 12px; border-radius:12px; box-shadow: var(--shadow);
  font-size:12px; text-decoration:none; display:inline-block;
}
.btn:hover{filter:brightness(1.05)}
.grid{display:grid; grid-template-columns:repeat(12, 1fr); gap:14px; margin-top:14px}
.card{
  background:var(--panel); border:1px solid var(--border); border-radius: var(--radius);
  box-shadow: var(--shadow); padding:14px;
}
.card h3{margin:0 0 8px; font-size:13px; color:var(--muted); font-weight:600; letter-spacing:.2px}
.kpi{display:flex; align-items:flex-end; justify-content:space-between; gap:10px}
.kpi .value{font-size:28px; font-weight:800; letter-spacing:-.6px}
.kpi .hint{color:var(--muted); font-size:12px}
.badge{display:inline-flex; align-items:center; gap:6px; padding:6px 10px; border-radius:999px; background:var(--chip); border:1px solid var(--border); font-size:12px; color:var(--muted)}
.badge b{color:var(--text)}
.badge.crit b{color:var(--crit)}
.badge.high b{color:var(--bad)}
.badge.med b{color:var(--warn)}
.badge.low b{color:var(--good)}
.section{margin-top:18px}
.section h2{margin:22px 0 10px; font-size:16px}
.two{display:grid; grid-template-columns:1fr 1fr; gap:14px}
@media (max-width: 1120px) {
  .sidebar{display:none}
  .main{padding:18px}
  .two{grid-template-columns:1fr}
}
.table-wrap{overflow:auto; border-radius: 12px; border:1px solid var(--border)}
table{width:100%; border-collapse:collapse; font-size:12px}
th,td{padding:10px 10px; border-bottom:1px solid var(--border); vertical-align:top}
th{text-align:left; color:var(--muted); font-weight:700; position:sticky; top:0; background:var(--panel2); cursor:pointer; user-select:none}
tr:hover td{background:rgba(0,0,0,.03)}
.mono{font-family:var(--mono)}
.small{font-size:12px; color:var(--muted)}
.searchbar{display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:10px}
.searchbar input{
  flex:1; min-width:240px; padding:10px 12px; border-radius:12px; border:1px solid var(--border);
  background:var(--panel2); color:var(--text); outline:none;
}
.pill{
  display:inline-flex; gap:6px; align-items:center; padding:8px 10px; border-radius:999px;
  border:1px solid var(--border); background:var(--chip); font-size:12px; color:var(--muted);
}
.pill select{
  background:transparent; color:var(--text); border:none; outline:none; font-size:12px;
}
.hr{height:1px; background:var(--border); margin:14px 0}
.accordion-item{border:1px solid var(--border); border-radius:14px; overflow:hidden; margin-bottom:10px; background:var(--panel)}
.accordion-head{display:flex; gap:10px; align-items:center; justify-content:space-between; padding:12px 12px; cursor:pointer}
.accordion-head:hover{background:rgba(0,0,0,.03)}
.accordion-title{display:flex; gap:10px; align-items:center; min-width:0}
.tag{padding:4px 8px; border-radius:999px; font-size:11px; border:1px solid var(--border); background:var(--chip); color:var(--muted)}
.tag.critical{color:var(--crit); border-color:rgba(255,59,48,.35)}
.tag.high{color:var(--bad); border-color:rgba(255,107,107,.35)}
.tag.medium{color:var(--warn); border-color:rgba(255,204,102,.35)}
.tag.low{color:var(--good); border-color:rgba(56,211,159,.35)}
.accordion-title .txt{white-space:nowrap; overflow:hidden; text-overflow:ellipsis}
.accordion-body{display:none; padding:12px 12px; border-top:1px solid var(--border)}
.kv{display:grid; grid-template-columns:170px 1fr; gap:8px 12px; font-size:12px}
.kv div:nth-child(odd){color:var(--muted)}
pre{margin:0; padding:12px; border-radius:12px; background:var(--panel2); border:1px solid var(--border); overflow:auto; font-family:var(--mono); font-size:11px; line-height:1.35}
footer{margin-top:28px; color:var(--muted); font-size:12px}
.print-note{display:none}
@media print {
  .sidebar,.actions,.searchbar,.btn{display:none !important}
  body{background:#fff; color:#000}
  .card{box-shadow:none}
  .print-note{display:block; margin:10px 0; color:#222}
}
</style>
</head>
<body>
<div class="container" id="app">
  <aside class="sidebar">
    <div class="brand">
      <div class="logo"></div>
      <div>
        <h1 id="brandTitle">M365 Forensic Triage</h1>
        <div class="sub" id="sideMeta">Offline • __TOOL_VERSION__</div>
      </div>
    </div>

    <div class="nav" id="nav">
      <a href="#overview" class="active">Overview</a>
      <a href="#findings">Findings</a>
      <a href="#timeline">Timeline</a>
      <a href="#signins">Sign-ins</a>
      <a href="#ual">Audit (UAL)</a>
      <a href="#evidence">Evidence</a>
      <a href="#exports">Exports</a>
      <a href="#raw">Raw</a>
    </div>

    <div class="hr"></div>
    <div class="small" id="coverageChip"></div>
  </aside>

  <main class="main">
    <div class="topbar">
      <div class="title">
        <h2 id="rTitle">Microsoft 365 — Forensic Triage Report</h2>
        <div class="meta" id="rMeta"></div>
      </div>
      <div class="actions">
        <button class="btn" onclick="window.print()">Print / PDF</button>
        <a class="btn" id="openOut" href="report_data.json" download>Download report_data.json</a>
      </div>
    </div>

    <div class="print-note">This report is <strong>read-only</strong> and intended for <strong>forensic preservation</strong>. See the <strong>Evidence</strong> section for provenance, parameters, and export artifacts.</div>

    <section id="overview" class="section">
      <div class="grid">
        <div class="card" style="grid-column: span 3;">
          <h3>Overall risk</h3>
          <div class="kpi">
            <div>
              <div class="value" id="riskScore">0</div>
              <div class="hint">Score (0–100)</div>
            </div>
            <div id="riskBadge" class="badge"><b>LOW</b></div>
          </div>
          <div style="margin-top:10px;">
            <div class="small">Severity → weighting (Critical/High/Medium/Low)</div>
            <div style="margin-top:10px; height:10px; border-radius:999px; background:var(--chip); border:1px solid var(--border); overflow:hidden;">
              <div id="riskBar" style="height:100%; width:0%; background:linear-gradient(90deg,var(--good),var(--warn),var(--bad),var(--crit));"></div>
            </div>
          </div>
        </div>

        <div class="card" style="grid-column: span 3;">
          <h3>Findings</h3>
          <div class="kpi">
            <div>
              <div class="value" id="kTotalFindings">0</div>
              <div class="hint">Total</div>
            </div>
            <div class="badge crit">Critical: <b id="sevCritical">0</b></div>
          </div>
          <div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap;">
            <span class="badge high">High: <b id="sevHigh">0</b></span>
            <span class="badge med">Medium: <b id="sevMedium">0</b></span>
            <span class="badge low">Low: <b id="sevLow">0</b></span>
          </div>
        </div>

        <div class="card" style="grid-column: span 3;">
          <h3>Impacto</h3>
          <div class="kpi">
            <div>
              <div class="value" id="kUsers">0</div>
              <div class="hint">Usuarios afectados</div>
            </div>
            <div>
              <div class="value" id="kIps">0</div>
              <div class="hint">IPs involucradas</div>
            </div>
          </div>
        </div>

        <div class="card" style="grid-column: span 3;">
          <h3>Dataset</h3>
          <div class="kpi">
            <div>
              <div class="value" id="kFiles">0</div>
              <div class="hint">Archivos</div>
            </div>
            <div>
              <div class="value" id="kEvents">0</div>
              <div class="hint">Events (UAL + Sign-in)</div>
            </div>
          </div>
        </div>

        <div class="card" style="grid-column: span 7;">
          <h3>Volume per day (eventos)</h3>
          <div id="chartDaily" style="height:160px;"></div>
          <div class="small" style="margin-top:8px;">Sign-ins, UAL and aggregated findings per day (when timestamps are available).</div>
        </div>

        <div class="card" style="grid-column: span 5;">
          <h3>Severity distribution</h3>
          <div id="chartSev" style="height:160px;"></div>
          <div class="small" style="margin-top:8px;">Note: Only embedded findings are included (top severities + sample)..</div>
        </div>
      </div>
    </section>

    <section id="findings" class="section">
      <h2>Findings (priority & evidence)</h2>
      <div class="searchbar">
        <input id="findSearch" placeholder="Search by user, IP, category, title, ref…" />
        <span class="pill">Severity:
          <select id="findSev">
            <option value="">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </span>
        <span class="pill">Category:
          <select id="findCat"><option value="">All</option></select>
        </span>
        <span class="pill">Vista:
          <select id="findView">
            <option value="accordion">Case file</option>
            <option value="table">Table</option>
          </select>
        </span>
      </div>

      <div id="findingsAccordion"></div>

      <div id="findingsTable" class="table-wrap" style="display:none;">
        <table id="tblFindings">
          <thead>
            <tr>
              <th data-k="severity">Sev</th>
              <th data-k="timestamp">Timestamp</th>
              <th data-k="user">User</th>
              <th data-k="ip">IP</th>
              <th data-k="category">Category</th>
              <th data-k="title">Title</th>
              <th data-k="file">File</th>
              <th data-k="rownum">Row</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <div class="small" style="margin-top:10px;">
        Note: This report embeds a subset (up to ~1500) to stay lightweight. Full datasets remain in <span class="mono">findings.csv</span> / <span class="mono">triage.sqlite</span>.
      </div>
    </section>

    <section id="timeline" class="section">
      <h2>Timeline (hallazgos)</h2>
      <div class="two">
        <div class="card">
          <h3>Events (chronological)</h3>
          <div class="table-wrap" style="max-height:420px;">
            <table id="tblTimeline">
              <thead>
                <tr>
                  <th data-k="ts">Time</th>
                  <th data-k="severity">Sev</th>
                  <th data-k="title">Title</th>
                  <th data-k="user">User</th>
                  <th data-k="ip">IP</th>
                </tr>
              </thead>
              <tbody></tbody>
            </table>
          </div>
        </div>
        <div class="card">
          <h3>Heatmap (Sign-ins)</h3>
          <div class="small">Day of week × hour (0–23). Useful to spot anomalous spikes.</div>
          <div id="heatmap" style="margin-top:10px;"></div>
        </div>
      </div>
    </section>

    <section id="signins" class="section">
      <h2>Sign-ins</h2>
      <div class="two">
        <div class="card">
          <h3>Top IPs con fallos</h3>
          <div class="table-wrap" style="max-height:380px;">
            <table id="tblFailIPs">
              <thead><tr><th data-k="ip">IP</th><th data-k="fails">Fails</th><th data-k="users">Users</th></tr></thead>
              <tbody></tbody>
            </table>
          </div>
          <div class="small" style="margin-top:8px;">Typical password-spray indicator: one IP → many users.</div>
        </div>
        <div class="card">
          <h3>Top users with failures</h3>
          <div class="table-wrap" style="max-height:380px;">
            <table id="tblFailUsers">
              <thead><tr><th data-k="user">User</th><th data-k="fails">Fails</th><th data-k="ips">IPs</th></tr></thead>
              <tbody></tbody>
            </table>
          </div>
          <div class="small" style="margin-top:8px;">Typical brute-force indicator: one user → many IPs.</div>
        </div>
      </div>
    </section>

    <section id="ual" class="section">
      <h2>Audit (UAL) — BEC checklist</h2>
      <div class="grid">
        <div class="card" style="grid-column: span 4;">
          <h3>Forwarding / Redirect</h3>
          <div class="kpi">
            <div>
              <div class="value" id="becForward">0</div>
              <div class="hint">Eventos</div>
            </div>
            <div class="badge">Top external domains</div>
          </div>
          <div id="becDomains" class="small" style="margin-top:10px;"></div>
        </div>
        <div class="card" style="grid-column: span 4;">
          <h3>Inbox Rules sospechosas</h3>
          <div class="kpi">
            <div>
              <div class="value" id="becRules">0</div>
              <div class="hint">Eventos</div>
            </div>
          </div>
          <div class="small" style="margin-top:10px;">Revisa reglas de delete/hide/redirect/move.</div>
        </div>
        <div class="card" style="grid-column: span 4;">
          <h3>Delegaciones / permisos</h3>
          <div class="kpi">
            <div>
              <div class="value" id="becDeleg">0</div>
              <div class="hint">Eventos</div>
            </div>
          </div>
          <div class="small" style="margin-top:10px;">Cambios de permisos y delegaciones son muy indicativos.</div>
        </div>

        <div class="card" style="grid-column: span 12;">
          <h3>BEC events (sample)</h3>
          <div class="table-wrap" style="max-height:420px;">
            <table id="tblBec">
              <thead><tr><th data-k="ts">Time</th><th data-k="user">User</th><th data-k="ip">IP</th><th data-k="operation">Operation</th><th data-k="ref">Ref</th><th data-k="kind">Type</th></tr></thead>
              <tbody></tbody>
            </table>
          </div>
        </div>
      </div>
    </section>

    <section id="evidence" class="section">
      <h2>Evidence / Integridad</h2>
      <div class="card">
        <h3>Inventario de archivos (hashes)</h3>
        <div class="small">Conserva estos archivos en modo solo lectura. Verifica SHA-256 si haces copia/traslado.</div>
        <div class="table-wrap" style="margin-top:10px;">
          <table id="tblFiles">
            <thead>
              <tr>
                <th data-k="family">Family</th>
                <th data-k="name">File</th>
                <th data-k="rows">Rows</th>
                <th data-k="start">Start</th>
                <th data-k="end">End</th>
                <th data-k="sha256">SHA-256</th>
              </tr>
            </thead>
            <tbody></tbody>
          </table>
        </div>
        <div class="small" style="margin-top:10px;">Note: Raw identifiers may be partially redacted in the embedded dataset to reduce inadvertent disclosure. Full values are available in report_data.json if required.</div>
      </div>
    </section>

    <section id="exports" class="section">
      <h2>Exports (para SOC / IR)</h2>
      <div class="grid">
        <div class="card" style="grid-column: span 4;">
          <h3>Archivos clave</h3>
          <div id="links"></div>
        </div>
        <div class="card" style="grid-column: span 8;">
          <h3>Top categorías</h3>
          <div id="chartCat" style="height:180px;"></div>
        </div>
      </div>
    </section>

    <section id="raw" class="section">
      <h2>Raw (Markdown)</h2>
      <div class="small" style="margin-bottom:10px;">Para copiado rápido, envío o anexado a ticket. También disponible como <span class="mono">report.md</span>.</div>
      <pre id="rawMd"></pre>
      <footer>Generated by <span class="mono">m365_triage</span> v__TOOL_VERSION__ • __NOW_ISO__</footer>
    </section>

  </main>
</div>

<script id="report-data" type="application/json">__REPORT_JSON__</script>
<script>
const DATA = JSON.parse(document.getElementById('report-data').textContent);

function $(id){ return document.getElementById(id); }
function fmt(n){
  if (n === null || n === undefined) return "";
  const x = Number(n);
  if (Number.isNaN(x)) return String(n);
  return x.toLocaleString('es-ES');
}
function sevTag(sev){
  const s = (sev||"").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "low";
}
function riskLabel(score){
  if (score >= 85) return ["CRITICAL", "crit"];
  if (score >= 60) return ["HIGH", "high"];
  if (score >= 30) return ["MEDIUM", "med"];
  return ["LOW", "low"];
}
function setActiveNav() {
  const links = Array.from(document.querySelectorAll('#nav a'));
  const ids = links.map(a => a.getAttribute('href').slice(1));
  const onScroll = () => {
    let best = ids[0];
    for (const id of ids) {
      const el = document.getElementById(id);
      if (!el) continue;
      const r = el.getBoundingClientRect();
      if (r.top <= 110) best = id;
    }
    links.forEach(a => a.classList.toggle('active', a.getAttribute('href') === '#' + best));
  };
  window.addEventListener('scroll', onScroll, {passive:true});
  onScroll();
}

function svgBarChart(el, series, opts={}){
  const w = opts.w || 900, h = opts.h || 160, pad = 36, barGap = 6;
  const maxV = Math.max(1, ...series.map(x => x.v));
  const n = series.length;
  const barW = Math.max(8, (w - pad*2 - barGap*(n-1)) / n);
  const x0 = pad, y0 = h - pad;

  const bars = series.map((p, i) => {
    const bh = Math.round((p.v / maxV) * (h - pad*2));
    const x = x0 + i*(barW+barGap);
    const y = y0 - bh;
    return `<rect x="${x}" y="${y}" width="${barW}" height="${bh}" rx="6" opacity="0.95"></rect>`;
  }).join("");

  const labels = series.map((p, i) => {
    const x = x0 + i*(barW+barGap) + barW/2;
    return `<text x="${x}" y="${h-12}" text-anchor="middle" font-size="10" opacity="0.75">${p.k}</text>`;
  }).join("");

  const yLabel = `<text x="${pad}" y="16" font-size="10" opacity="0.75">max ${fmt(maxV)}</text>`;

  el.innerHTML = `
  <svg viewBox="0 0 ${w} ${h}" width="100%" height="100%" role="img" aria-label="bar chart">
    <g fill="currentColor">${bars}</g>
    <g fill="currentColor">${labels}</g>
    <g fill="currentColor">${yLabel}</g>
  </svg>`;
}

function svgDonut(el, parts){
  const cx = 78, cy = 78, r = 54, sw = 12;
  const total = parts.reduce((a,b)=>a+b.v,0) || 1;

  let acc = 0;
  const circles = parts.map(p => {
    const frac = p.v/total;
    const dash = (2*Math.PI*r) * frac;
    const gap = (2*Math.PI*r) - dash;
    const rot = (acc/total) * 360 - 90;
    acc += p.v;
    return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${p.color}" stroke-width="${sw}"
      stroke-dasharray="${dash} ${gap}" transform="rotate(${rot} ${cx} ${cy})" stroke-linecap="round"></circle>`;
  }).join("");

  const legend = parts.map(p => `<div class="badge" style="margin:6px 8px 0 0; display:inline-flex;">
    <span style="width:10px;height:10px;border-radius:3px;background:${p.color};display:inline-block;"></span>
    <span style="margin-left:8px">${p.k}: <b>${fmt(p.v)}</b></span>
  </div>`).join("");

  el.innerHTML = `
  <div style="display:flex; gap:14px; align-items:center; flex-wrap:wrap;">
    <svg viewBox="0 0 160 160" width="160" height="160" aria-label="donut">
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="rgba(255,255,255,.12)" stroke-width="${sw}"></circle>
      ${circles}
      <text x="${cx}" y="${cy}" text-anchor="middle" font-size="18" font-weight="800" fill="currentColor">${fmt(total)}</text>
      <text x="${cx}" y="${cy+18}" text-anchor="middle" font-size="10" opacity="0.75" fill="currentColor">findings</text>
    </svg>
    <div>${legend}</div>
  </div>`;
}

function renderTable(tableId, rows, columns){
  const tbody = document.querySelector(`#${tableId} tbody`);
  tbody.innerHTML = rows.map(r => {
    const tds = columns.map(c => {
      const v = (r[c] === null || r[c] === undefined) ? "" : r[c];
      const cls = (c === "sha256" || c === "ip" || c === "user" || c === "ref") ? "mono" : "";
      const safe = String(v).replace(/</g,"&lt;").replace(/>/g,"&gt;");
      return `<td class="${cls}">${safe}</td>`;
    }).join("");
    return `<tr>${tds}</tr>`;
  }).join("");
}

function enableSort(tableId, rows, columns){
  const ths = Array.from(document.querySelectorAll(`#${tableId} thead th`));
  let sortKey = null, sortAsc = true;

  ths.forEach(th => {
    th.addEventListener('click', () => {
      const k = th.dataset.k;
      if (!k) return;
      if (sortKey === k) sortAsc = !sortAsc;
      else { sortKey = k; sortAsc = true; }

      const sorted = [...rows].sort((a,b) => {
        const av = a[k] ?? "";
        const bv = b[k] ?? "";
        const an = Number(av), bn = Number(bv);
        const isNum = !Number.isNaN(an) && !Number.isNaN(bn);
        if (isNum) return sortAsc ? (an-bn) : (bn-an);
        return sortAsc ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
      });
      renderTable(tableId, sorted, columns);
    });
  });
}

function renderHeatmap(el, heat){
  const dow = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
  let maxV = 1;
  for (const row of heat) for (const c of row) maxV = Math.max(maxV, c||0);
  const cell = (v) => {
    const t = (v||0) / maxV; // 0..1
    const a = 0.08 + 0.55*t;
    return `rgba(110,168,254,${a.toFixed(3)})`;
  };

  let html = `<div class="table-wrap"><table><thead><tr><th></th>`;
  for (let h=0; h<24; h++) html += `<th class="mono">${h}</th>`;
  html += `</tr></thead><tbody>`;
  for (let d=0; d<7; d++) {
    html += `<tr><td><b>${dow[d]}</b></td>`;
    for (let h=0; h<24; h++) {
      const v = heat[d][h] || 0;
      html += `<td title="${dow[d]} ${h}:00 → ${fmt(v)}" style="background:${cell(v)}; text-align:right" class="mono">${v ? fmt(v) : ""}</td>`;
    }
    html += `</tr>`;
  }
  html += `</tbody></table></div>`;
  el.innerHTML = html;
}

function renderFindingsAccordion(container, list){
  container.innerHTML = list.map(f => {
    const sev = sevTag(f.severity);
    const ref = (f.file && f.rownum) ? `${f.file}:${f.rownum}` : "";
    const head = `
      <div class="accordion-head" data-id="${f.finding_id}">
        <div class="accordion-title">
          <span class="tag ${sev}">${(f.severity||"").toUpperCase()}</span>
          <div class="txt"><b>${escapeHtml(f.title||"")}</b> <span class="small">• ${escapeHtml(f.category||"")}</span></div>
        </div>
        <div class="small mono">${escapeHtml(f.timestamp||"")}</div>
      </div>`;
    const ev = f.evidence || {};
    const kv = `
      <div class="kv">
        <div>Finding ID</div><div class="mono">${escapeHtml(f.finding_id||"")}</div>
        <div>Timestamp</div><div class="mono">${escapeHtml(f.timestamp||"")}</div>
        <div>User</div><div class="mono">${escapeHtml(f.user||"")}</div>
        <div>IP</div><div class="mono">${escapeHtml(f.ip||"")}</div>
        <div>Country</div><div>${escapeHtml(f.country||"")}</div>
        <div>Ref</div><div class="mono">${escapeHtml(ref)}</div>
        <div>Details</div><div>${escapeHtml(f.details||"")}</div>
      </div>
      <div class="hr"></div>
      <div class="small">Evidence (trimmed):</div>
      <pre>${escapeHtml(JSON.stringify(ev, null, 2))}</pre>
    `;
    return `<div class="accordion-item">${head}<div class="accordion-body">${kv}</div></div>`;
  }).join("");

  container.querySelectorAll('.accordion-head').forEach(h => {
    h.addEventListener('click', () => {
      const body = h.parentElement.querySelector('.accordion-body');
      const open = body.style.display === 'block';
      body.style.display = open ? 'none' : 'block';
    });
  });
}

function escapeHtml(s){
  return String(s ?? "")
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;").replace(/'/g,"&#039;");
}

function render(){
  // Title
  $('rTitle').textContent = ((DATA.case||{}).report_title || 'Microsoft 365 — Forensic Triage Report');

  // Meta
  const cov = DATA.coverage || {};
  $('rMeta').textContent = `Generated: ${DATA.meta.generated_at} • Coverage: ${cov.start || "?"} → ${cov.end || "?"} • Mode: ${DATA.meta.mode} • Case: ${(DATA.case||{}).case_id || "N/A"} • Client: ${(DATA.case||{}).client || "N/A"} • Analyst: ${(DATA.case||{}).analyst || "N/A"}`;
  $('sideMeta').textContent = `Offline • v${DATA.meta.version}`;
  $('coverageChip').innerHTML = `<span class="badge"><b>Inicio</b> ${escapeHtml(cov.start||"?")}</span> <span class="badge" style="margin-top:8px; display:inline-flex;"><b>Fin</b> ${escapeHtml(cov.end||"?")}</span>`;

  // KPIs
  $('riskScore').textContent = fmt(DATA.kpis.risk_score);
  $('riskBar').style.width = Math.min(100, DATA.kpis.risk_score) + '%';
  const [lbl, cls] = riskLabel(DATA.kpis.risk_score);
  $('riskBadge').className = 'badge ' + cls;
  $('riskBadge').innerHTML = `<b>${lbl}</b>`;

  $('kTotalFindings').textContent = fmt(DATA.kpis.total_findings);
  $('kUsers').textContent = fmt(DATA.kpis.impacted_users);
  $('kIps').textContent = fmt(DATA.kpis.impacted_ips);
  $('kFiles').textContent = fmt(DATA.kpis.total_files);
  $('kEvents').textContent = fmt((DATA.kpis.signin_rows||0) + (DATA.kpis.ual_rows||0));

  const sev = DATA.counts.severity || {};
  $('sevCritical').textContent = fmt(sev.critical || 0);
  $('sevHigh').textContent = fmt(sev.high || 0);
  $('sevMedium').textContent = fmt(sev.medium || 0);
  $('sevLow').textContent = fmt(sev.low || 0);

  // Charts
  const dailyMap = new Map();
  for (const p of (DATA.timeseries.signin_by_day||[])) dailyMap.set(p.date, {d:p.date, signin:p.count, ual:0, findings:0});
  for (const p of (DATA.timeseries.ual_by_day||[])) {
    const o = dailyMap.get(p.date) || {d:p.date, signin:0, ual:0, findings:0};
    o.ual = p.count; dailyMap.set(p.date, o);
  }
  for (const p of (DATA.timeseries.findings_by_day||[])) {
    const o = dailyMap.get(p.date) || {d:p.date, signin:0, ual:0, findings:0};
    o.findings = p.count; dailyMap.set(p.date, o);
  }
  const daily = Array.from(dailyMap.values()).sort((a,b)=>String(a.d).localeCompare(String(b.d)));
  const compact = daily.slice(Math.max(0, daily.length-30)); // last 30
  const bars = compact.map(p => ({k: p.d.slice(5), v: p.signin + p.ual}));
  svgBarChart($('chartDaily'), bars, {h:160});

  const css = getComputedStyle(document.documentElement);
  svgDonut($('chartSev'), [
    {k:"Critical", v:(sev.critical||0), color:css.getPropertyValue('--crit').trim() || "#ff3b30"},
    {k:"High", v:(sev.high||0), color:css.getPropertyValue('--bad').trim() || "#ff6b6b"},
    {k:"Medium", v:(sev.medium||0), color:css.getPropertyValue('--warn').trim() || "#ffcc66"},
    {k:"Low", v:(sev.low||0), color:css.getPropertyValue('--good').trim() || "#38d39f"},
  ]);

  const cats = (DATA.counts.category_top||[]).slice(0, 10).map(([k,v]) => ({k, v}));
  svgBarChart($('chartCat'), cats.map(p => ({k: p.k.length>12? p.k.slice(0,11)+'…':p.k, v:p.v})), {h:180});

  // Heatmap
  renderHeatmap($('heatmap'), DATA.timeseries.signin_heatmap_dow_hour || [[0]]);

  // Tables
  renderTable('tblFailIPs', DATA.entities.top_signin_fail_ips||[], ['ip','fails','users']);
  enableSort('tblFailIPs', DATA.entities.top_signin_fail_ips||[], ['ip','fails','users']);

  renderTable('tblFailUsers', DATA.entities.top_signin_fail_users||[], ['user','fails','ips']);
  enableSort('tblFailUsers', DATA.entities.top_signin_fail_users||[], ['user','fails','ips']);

  renderTable('tblFiles', DATA.files||[], ['family','name','rows','start','end','sha256']);
  enableSort('tblFiles', DATA.files||[], ['family','name','rows','start','end','sha256']);

  renderTable('tblTimeline', (DATA.timeline||[]).slice(0, 800), ['ts','severity','title','user','ip']);
  enableSort('tblTimeline', (DATA.timeline||[]).slice(0, 800), ['ts','severity','title','user','ip']);

  // BEC
  const bec = DATA.bec || {};
  $('becForward').textContent = fmt((bec.forwarding_events||[]).length);
  $('becRules').textContent = fmt((bec.inbox_rule_events||[]).length);
  $('becDeleg').textContent = fmt((bec.delegation_events||[]).length);

  const doms = (bec.external_forward_domains_top||[]).slice(0, 10);
  $('becDomains').innerHTML = doms.length
    ? doms.map(([d,c]) => `<span class="badge" style="margin:6px 6px 0 0;"><b>${escapeHtml(d)}</b> ${fmt(c)}</span>`).join("")
    : `<span class="small">No external domains detected in the sample.</span>`;

  const becRows = [];
  for (const e of (bec.forwarding_events||[]).slice(0,250)) becRows.push({...e, kind:"forwarding"});
  for (const e of (bec.inbox_rule_events||[]).slice(0,250)) becRows.push({...e, kind:"inboxrule"});
  for (const e of (bec.delegation_events||[]).slice(0,250)) becRows.push({...e, kind:"delegation"});
  becRows.sort((a,b)=>String(a.ts).localeCompare(String(b.ts)));
  renderTable('tblBec', becRows.slice(0, 800), ['ts','user','ip','operation','ref','kind']);
  enableSort('tblBec', becRows.slice(0, 800), ['ts','user','ip','operation','ref','kind']);

  // Findings: category filter
  const catSel = $('findCat');
  const catsAll = Array.from(new Set((DATA.findings||[]).map(f => f.category).filter(Boolean))).sort();
  catSel.innerHTML = `<option value="">All</option>` + catsAll.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join("");

  function applyFindFilters(){
    const q = ($('findSearch').value || "").toLowerCase().trim();
    const sevF = ($('findSev').value || "").toLowerCase();
    const catF = ($('findCat').value || "");
    const list = (DATA.findings||[]).filter(f => {
      if (sevF && (f.severity||"").toLowerCase() !== sevF) return false;
      if (catF && f.category !== catF) return false;
      if (!q) return true;
      const blob = `${f.finding_id} ${f.severity} ${f.category} ${f.title} ${f.timestamp} ${f.user} ${f.ip} ${f.file} ${f.rownum} ${f.details}`.toLowerCase();
      return blob.includes(q);
    });
    return list;
  }

  function refreshFindings(){
    const view = $('findView').value;
    const list = applyFindFilters();
    if (view === "table") {
      $('findingsTable').style.display = "block";
      $('findingsAccordion').style.display = "none";
      const rows = list.map(f => ({severity:f.severity, timestamp:f.timestamp, user:f.user, ip:f.ip, category:f.category, title:f.title, file:f.file, rownum:f.rownum}));
      renderTable('tblFindings', rows, ['severity','timestamp','user','ip','category','title','file','rownum']);
      enableSort('tblFindings', rows, ['severity','timestamp','user','ip','category','title','file','rownum']);
    } else {
      $('findingsTable').style.display = "none";
      $('findingsAccordion').style.display = "block";
      renderFindingsAccordion($('findingsAccordion'), list.slice(0, 400));
    }
  }

  ['findSearch','findSev','findCat','findView'].forEach(id => {
    $(id).addEventListener('input', refreshFindings);
    $(id).addEventListener('change', refreshFindings);
  });
  refreshFindings();

  // Exports links
  const links = DATA.links || {};
  const entries = Object.entries(links).filter(([k,v]) => v);
  $('links').innerHTML = entries.map(([k,v]) => {
    const label = k.replace(/_/g," ");
    return `<div style="margin-top:8px;"><a class="btn" href="${escapeHtml(v)}" target="_blank" rel="noopener">${escapeHtml(label)}</a></div>`;
  }).join("");

  // Raw MD
  $('rawMd').textContent = __MD_JSON__;
  // Theme toggle removed (single-theme report)

  setActiveNav();
}

render();
</script>
</body>
</html>
"""
    html = (HTML_TEMPLATE
            .replace("__REPORT_JSON__", json_for_html)
            .replace("__TOOL_VERSION__", TOOL_VERSION)
            .replace("__NOW_ISO__", now_iso)
            .replace("__MD_JSON__", json.dumps(md_text, ensure_ascii=False)))


    out_path = outdir / "report.html"
    out_path.write_text(html, encoding="utf-8")
    return out_path


def write_xlsx_optional(findings: List[Finding], outdir: Path) -> Optional[Path]:
    try:
        import openpyxl  # noqa: F401
    except Exception:
        return None

    p = outdir / "report.xlsx"
    df = findings_to_dataframe(findings)
    with pd.ExcelWriter(p, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="findings")
    return p


# -----------------------------
# Main pipeline
# -----------------------------

def ingest_all(logdir: Path, outdir: Path, mode: str, chunk_rows: int, verbosity: int, rules_path: Optional[Path], case_meta: Optional[Dict[str, Any]] = None) -> None:
    ensure_dir(outdir)
    db_path = outdir / "triage.sqlite"
    if db_path.exists():
        db_path.unlink()  # fresh run
    conn = db_connect(db_path)

    csv_files = sorted([p for p in logdir.rglob("*.csv") if p.is_file()])
    if not csv_files:
        print(f"[!] No CSV files found under: {logdir}")
        return

    file_sha_map: Dict[int, str] = {}

    for f in csv_files:
        if f.stat().st_size < 5:
            logging.warning(f"[skip] empty file: {f.name}")
            meta = {
                "path": str(f.resolve()),
                "name": f.name,
                "family": "empty",
                "sha256": sha256_file(f) if f.exists() else "",
                "rows": 0,
                "delimiter": "",
                "skiprows": 0,
                "start_epoch": None,
                "end_epoch": None,
                "columns_json": "[]",
                "profile_json": "{}",
                "error": "empty file",
            }
            fid = db_insert_file(conn, meta)
            file_sha_map[fid] = meta["sha256"]
            conn.commit()
            continue

        delimiter = sniff_delimiter(f)
        skiprows = detect_skiprows_for_excel_sep(f)
        try:
            head = read_csv_any(f, delimiter, nrows=0)
        except EmptyDataError:
            logging.warning(f"[skip] EmptyDataError: {f.name}")
            meta = {
                "path": str(f.resolve()),
                "name": f.name,
                "family": "empty",
                "sha256": sha256_file(f),
                "rows": 0,
                "delimiter": delimiter,
                "skiprows": skiprows,
                "start_epoch": None,
                "end_epoch": None,
                "columns_json": "[]",
                "profile_json": "{}",
                "error": "EmptyDataError",
            }
            fid = db_insert_file(conn, meta)
            file_sha_map[fid] = meta["sha256"]
            conn.commit()
            continue

        cols = [c.strip() for c in head.columns]
        family = detect_family(f, cols)
        sha = sha256_file(f)

        # profile sample
        profile_json = "{}"
        try:
            sample = read_csv_any(f, delimiter, nrows=2000, dtype=str, keep_default_na=False)
            prof = schema_profile_from_sample(sample)
            profile_json = json.dumps(prof, ensure_ascii=False)
        except Exception:
            profile_json = "{}"

        meta = {
            "path": str(f.resolve()),
            "name": f.name,
            "family": family,
            "sha256": sha,
            "rows": 0,
            "delimiter": delimiter,
            "skiprows": skiprows,
            "start_epoch": None,
            "end_epoch": None,
            "columns_json": json.dumps(cols, ensure_ascii=False),
            "profile_json": profile_json,
            "error": "",
        }

        file_id = db_insert_file(conn, meta)
        file_sha_map[file_id] = sha
        conn.commit()

        try:
            if family == "signin":
                logging.info(f"[signin] {f.name} (delim='{delimiter}')")
                rows, min_e, max_e = ingest_signin_file(conn, f, file_id, delimiter, chunk_rows, verbosity)
            elif family == "ual":
                logging.info(f"[ual] {f.name} (delim='{delimiter}')")
                rows, min_e, max_e = ingest_ual_file(conn, f, file_id, delimiter, chunk_rows, verbosity)
            else:
                logging.info(f"[skip] unknown family: {f.name}")
                rows, min_e, max_e = 0, None, None

            conn.execute("UPDATE files SET rows=?, start_epoch=?, end_epoch=? WHERE file_id=?", (rows, min_e, max_e, file_id))
            conn.commit()

        except Exception as e:
            logging.error(f"[error] processing {f.name}: {e}", exc_info=(verbosity >= 2))
            conn.execute("UPDATE files SET error=? WHERE file_id=?", (str(e), file_id))
            conn.commit()

    # Run detections
    findings: List[Finding] = []
    findings.extend(detect_risky_signins(conn, file_sha_map))
    findings.extend(detect_legacy_auth(conn, file_sha_map))

    # campaign detections (tune defaults for IR)
    findings.extend(detect_password_spray(conn, file_sha_map, window_minutes=15, min_failures=20, min_users=5))
    findings.extend(detect_bruteforce(conn, file_sha_map, window_minutes=15, min_failures=25, min_ips=5))

    findings.extend(detect_success_after_failures(conn, file_sha_map, max_minutes=30, min_fails=5))
    findings.extend(detect_impossible_travel(conn, file_sha_map, max_minutes=60))

    findings.extend(detect_ual_suspicious(conn, file_sha_map))

    if mode != "quick":
        findings.extend(detect_mailitems_spike(conn, file_sha_map, window_minutes=60, threshold=500))
        findings.extend(correlate_ual_with_signin(conn, file_sha_map, max_minutes=60))

    # YAML rules
    rules = load_yaml_rules(rules_path)
    if rules:
        findings.extend(apply_rules(conn, rules, file_sha_map))

    # Outputs
    write_findings(findings, outdir)
    write_file_ranges(conn, outdir)
    write_schema_profiles(conn, outdir)

    bec = detect_bec_checklist(conn)

    # timeline and cases
    export_timeline(conn, outdir, mode=mode)
    if mode != "quick":
        export_case_views(conn, outdir, max_users=50)

    md_path = generate_report_md(conn, findings, bec, outdir)
    html_path = generate_report_html(conn, findings, bec, outdir, logdir=logdir, mode=mode, md_path=md_path, case_meta=case_meta)

    xlsx_path = write_xlsx_optional(findings, outdir)

    print(f"[OK] Analysis completed.")
    print(f" - DB:        {db_path}")
    print(f" - Report MD:  {md_path}")
    print(f" - Report HTML:{html_path}")
    print(f" - Findings:  {outdir/'findings.csv'}  (and findings.jsonl)")
    print(f" - Timeline:  {outdir/'timeline.csv'} (and timeline.jsonl)")
    print(f" - Files:     {outdir/'file_ranges.csv'}")
    print(f" - Profiles:  {outdir/'schema_profiles.json'}")
    if xlsx_path:
        print(f" - XLSX:      {xlsx_path}")
    if mode != "quick":
        print(f" - Cases:     {outdir/'cases'}")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Offline forensic triage for Microsoft 365 exported CSV logs (Sign-ins + UAL).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--logdir", required=True, help="Folder with CSV logs (recursive).")
    p.add_argument("--outdir", default="./out", help="Output folder.")
    p.add_argument("--mode", choices=["quick","deep"], default="deep", help="quick = lighter + faster, deep = more correlation & case views")
    p.add_argument("--chunk-rows", type=int, default=20000, help="CSV chunk rows for streaming ingestion.")
    p.add_argument("--rules", default="", help="Optional rules.yml (custom detections).")
    p.add_argument("--case-id", default="", help="Case identifier (e.g., INC-2026-001).")
    p.add_argument("--client", default="", help="Client / organization name.")
    p.add_argument("--analyst", default="", help="Analyst / examiner name.")
    p.add_argument("--report-title", default="Microsoft 365 Forensic Triage Report", help="Title shown in the HTML report.")
    p.add_argument("--classification", default="CONFIDENTIAL", help="Report classification label (e.g., CONFIDENTIAL / RESTRICTED / PUBLIC).")
    p.add_argument("-v", "--verbose", action="count", default=0, help="Verbose logs (-v info, -vv debug).")
    return p


def main() -> None:
    args = build_arg_parser().parse_args()
    setup_logging(args.verbose)

    logdir = Path(args.logdir).expanduser().resolve()
    outdir = Path(args.outdir).expanduser().resolve()
    rules_path = Path(args.rules).expanduser().resolve() if args.rules else None

    case_meta = {
        "case_id": getattr(args, "case_id", "") or "",
        "client": getattr(args, "client", "") or "",
        "analyst": getattr(args, "analyst", "") or "",
        "report_title": getattr(args, "report_title", "") or "Microsoft 365 Forensic Triage Report",
        "classification": getattr(args, "classification", "") or "CONFIDENTIAL",
    }

    if not logdir.exists():
        print(f"[!] logdir does not exist: {logdir}")
        sys.exit(2)

    ingest_all(logdir, outdir, mode=args.mode, chunk_rows=args.chunk_rows, verbosity=args.verbose, rules_path=rules_path, case_meta=case_meta)


if __name__ == "__main__":
    main()