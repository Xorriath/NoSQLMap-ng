"""Session/resume (SQLite) and structured output (NDJSON/CSV + run log) for the
modern NoSQL engine (nsmwebng).

The Store is keyed by a normalized target.  It persists extracted values and
per-character partial progress so an interrupted or repeated run resumes instead
of re-walking values blind-byte-by-byte (the expensive, especially time-based,
part).  It also streams findings and recovered data to files under an output dir.
"""
import csv
import hashlib
import json
import os
import sqlite3
import threading
import time
import urllib.parse


def _slug(url):
    p = urllib.parse.urlsplit(url)
    host = (p.netloc or "target").replace(":", "_")
    path = (p.path or "/").strip("/").replace("/", "_") or "root"
    return "%s_%s" % (host, path)


def context_key(parts):
    # Stable hash of the dict describing one extraction unit (vector, field,
    # method, pin, exclude, where) so the same logical value maps to one row.
    blob = json.dumps(parts, sort_keys=True, default=str)
    return hashlib.sha1(blob.encode()).hexdigest()


class Store:
    def __init__(self, target_url, output_dir=None, session_file=None,
                 no_resume=False, flush=False):
        self.target = target_url
        self.no_resume = no_resume
        self._lock = threading.Lock()

        self.output_dir = output_dir or os.path.join("nosqlmap-out", _slug(target_url))
        os.makedirs(self.output_dir, exist_ok=True)

        self.session_file = session_file or os.path.join(self.output_dir, "session.sqlite")
        self.db = sqlite3.connect(self.session_file, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(
            "CREATE TABLE IF NOT EXISTS values_ ("
            "  target TEXT, ctx TEXT, field TEXT, value TEXT, complete INTEGER,"
            "  length INTEGER, updated REAL, PRIMARY KEY(target, ctx));"
            "CREATE TABLE IF NOT EXISTS findings ("
            "  target TEXT, label TEXT, vector TEXT, payload TEXT, blob TEXT,"
            "  updated REAL, PRIMARY KEY(target, vector, label));"
        )
        self.db.commit()

        self.log_path = os.path.join(self.output_dir, "run.log")
        self.findings_path = os.path.join(self.output_dir, "findings.ndjson")
        self.data_path = os.path.join(self.output_dir, "data.ndjson")
        self.csv_path = os.path.join(self.output_dir, "data.csv")
        if flush:                     # after paths exist, so flush() can clear the data files too
            self.flush()
        self._logf = open(self.log_path, "a", encoding="utf-8")
        self.log("=== run start: %s ===" % self.target)

    # --- run log ---------------------------------------------------------
    def log(self, msg):
        with self._lock:
            self._logf.write("%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
            self._logf.flush()

    # --- findings --------------------------------------------------------
    def save_finding(self, finding, payload_repr):
        rec = {
            "target": self.target, "label": finding.get("label"),
            "vector": finding.get("vector"), "payload": payload_repr,
            "reasons": finding.get("reasons"), "strong": finding.get("strong"),
            "error": finding.get("error", False),
            "where": finding.get("where") if isinstance(finding.get("where"), dict) else None,
        }
        with self._lock:
            self.db.execute(
                "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?)",
                (self.target, rec["label"], rec["vector"], payload_repr,
                 json.dumps(rec, default=str), time.time()))
            self.db.commit()
            with open(self.findings_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, default=str) + "\n")

    # --- extracted values + partial progress -----------------------------
    def get_value(self, ctx):
        if self.no_resume:
            return None
        with self._lock:        # one sqlite3.Connection shared across worker threads:
            cur = self.db.execute(   # ALL access (reads included) must be serialized.
                "SELECT value, complete, length FROM values_ WHERE target=? AND ctx=?",
                (self.target, ctx))
            row = cur.fetchone()
        if not row:
            return None
        return {"value": row[0], "complete": bool(row[1]), "length": row[2]}

    def set_partial(self, ctx, field, value, complete, length=None):
        with self._lock:
            self.db.execute(
                "INSERT OR REPLACE INTO values_ VALUES (?,?,?,?,?,?,?)",
                (self.target, ctx, field, value, 1 if complete else 0, length, time.time()))
            self.db.commit()

    def record_value(self, field, value, context=None):
        # Stream a recovered value to data.ndjson (and CSV) for the report.
        rec = {"field": field, "value": value, "context": context}
        with self._lock:
            with open(self.data_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, default=str) + "\n")

    def write_records(self, field_list, records):
        # Tabular dump (one row per record) -> data.csv.  Always (re)write so a
        # run that recovers nothing cannot leave a previous run's rows behind.
        if not field_list:
            return
        with self._lock:
            with open(self.csv_path, "w", newline="", encoding="utf-8") as f:
                wr = csv.DictWriter(f, fieldnames=field_list, extrasaction="ignore")
                wr.writeheader()
                for r in records:
                    wr.writerow({k: r.get(k) for k in field_list})

    # --- maintenance -----------------------------------------------------
    def flush(self):
        with self._lock:
            self.db.execute("DELETE FROM values_ WHERE target=?", (self.target,))
            self.db.execute("DELETE FROM findings WHERE target=?", (self.target,))
            self.db.commit()
        # Clear the streamed output files too, so --flushSession really resets
        # this target instead of leaving stale findings/data alongside an empty db.
        for p in (self.findings_path, self.data_path, self.csv_path):
            try:
                os.remove(p)
            except OSError:
                pass

    def close(self):
        try:
            self.log("=== run end ===")
            self._logf.close()
            self.db.close()
        except Exception:
            pass
