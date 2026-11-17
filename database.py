import sqlite3
import json
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import Any, Dict, List, Optional
from config import Config


class DatabaseManager:
    def __init__(self, db_path: str = str(Config.DATABASE_PATH)):
        Config.ensure_directories()
        self.db_path = db_path
        self.init_db()

    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self):
        with self.get_connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    scan_mode TEXT NOT NULL,
                    asset_criticality TEXT NOT NULL DEFAULT 'Medium',
                    authorization_confirmed INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'queued',
                    progress INTEGER NOT NULL DEFAULT 0,
                    status_message TEXT DEFAULT 'Initializing...',
                    os_detected TEXT DEFAULT 'Unknown',
                    os_accuracy INTEGER DEFAULT 0,
                    overall_risk_score REAL DEFAULT 0.0,
                    risk_grade TEXT DEFAULT 'Informational',
                    attack_surface_summary TEXT DEFAULT '{}',
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    error_message TEXT
                );

                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    port_number INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    state TEXT NOT NULL,
                    service_name TEXT,
                    product TEXT,
                    version TEXT,
                    extrainfo TEXT,
                    cpe TEXT,
                    exposure_level TEXT DEFAULT 'Moderate',
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    port_number INTEGER,
                    protocol TEXT,
                    service_name TEXT,
                    affected_software TEXT,
                    cve_id TEXT,
                    title TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    cvss_score REAL NOT NULL DEFAULT 0.0,
                    cvss_vector TEXT DEFAULT 'N/A',
                    severity TEXT NOT NULL,
                    priority_score REAL NOT NULL DEFAULT 0.0,
                    priority_rank INTEGER DEFAULT 0,
                    business_impact TEXT,
                    evidence TEXT,
                    remediation TEXT NOT NULL,
                    references_json TEXT DEFAULT '[]',
                    source TEXT DEFAULT 'NVD/Nmap',
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS nvd_cache (
                    cache_key TEXT PRIMARY KEY,
                    response_json TEXT NOT NULL,
                    fetched_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT,
                    operator_ip TEXT,
                    details TEXT
                );
                """
            )

    def log_audit(self, action: str, target: str = "", operator_ip: str = "127.0.0.1", details: str = ""):
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                "INSERT INTO audit_logs (timestamp, action, target, operator_ip, details) VALUES (?, ?, ?, ?, ?)",
                (now, action, target, operator_ip, details),
            )

    def create_scan(self, target: str, scan_mode: str, asset_criticality: str) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO scans (target, scan_mode, asset_criticality, status, progress, status_message, started_at)
                VALUES (?, ?, ?, 'running', 5, 'Validating target authorization scope...', ?)
                """,
                (target, scan_mode, asset_criticality, now),
            )
            return cur.lastrowid

    def update_scan_progress(self, scan_id: int, progress: int, message: str, status: str = "running"):
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE scans SET progress = ?, status_message = ?, status = ? WHERE id = ?",
                (progress, message, status, scan_id),
            )

    def complete_scan(
        self,
        scan_id: int,
        os_detected: str,
        os_accuracy: int,
        overall_risk_score: float,
        risk_grade: str,
        attack_surface_summary: Dict[str, Any],
    ):
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                """
                UPDATE scans
                SET status = 'completed',
                    progress = 100,
                    status_message = 'Assessment completed successfully.',
                    os_detected = ?,
                    os_accuracy = ?,
                    overall_risk_score = ?,
                    risk_grade = ?,
                    attack_surface_summary = ?,
                    completed_at = ?
                WHERE id = ?
                """,
                (
                    os_detected,
                    os_accuracy,
                    overall_risk_score,
                    risk_grade,
                    json.dumps(attack_surface_summary),
                    now,
                    scan_id,
                ),
            )

    def fail_scan(self, scan_id: int, error_message: str):
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                """
                UPDATE scans
                SET status = 'failed',
                    status_message = 'Assessment halted due to error.',
                    error_message = ?,
                    completed_at = ?
                WHERE id = ?
                """,
                (error_message, now, scan_id),
            )

    def save_ports(self, scan_id: int, ports: List[Dict[str, Any]]):
        with self.get_connection() as conn:
            conn.executemany(
                """
                INSERT INTO ports (
                    scan_id, port_number, protocol, state, service_name,
                    product, version, extrainfo, cpe, exposure_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        p["port_number"],
                        p["protocol"],
                        p["state"],
                        p.get("service_name", "unknown"),
                        p.get("product", ""),
                        p.get("version", ""),
                        p.get("extrainfo", ""),
                        p.get("cpe", ""),
                        p.get("exposure_level", "Moderate"),
                    )
                    for p in ports
                ],
            )

    def save_vulnerabilities(self, scan_id: int, vulns: List[Dict[str, Any]]):
        with self.get_connection() as conn:
            conn.executemany(
                """
                INSERT INTO vulnerabilities (
                    scan_id, port_number, protocol, service_name, affected_software,
                    cve_id, title, finding_type, description, cvss_score, cvss_vector,
                    severity, priority_score, priority_rank, business_impact,
                    evidence, remediation, references_json, source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        v.get("port_number"),
                        v.get("protocol", "tcp"),
                        v.get("service_name", "general"),
                        v.get("affected_software", "Unknown"),
                        v.get("cve_id", "N/A"),
                        v["title"],
                        v["finding_type"],
                        v["description"],
                        v.get("cvss_score", 0.0),
                        v.get("cvss_vector", "N/A"),
                        v["severity"],
                        v.get("priority_score", 0.0),
                        v.get("priority_rank", 0),
                        v.get("business_impact", ""),
                        v.get("evidence", ""),
                        v["remediation"],
                        json.dumps(v.get("references", [])),
                        v.get("source", "NVD/Nmap"),
                    )
                    for v in vulns
                ],
            )

    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if not row:
                return None
            scan = dict(row)
            scan["attack_surface_summary"] = json.loads(scan["attack_surface_summary"] or "{}")

            ports = conn.execute(
                "SELECT * FROM ports WHERE scan_id = ? ORDER BY port_number ASC", (scan_id,)
            ).fetchall()
            scan["ports"] = [dict(p) for p in ports]

            vulns = conn.execute(
                "SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY priority_rank ASC, priority_score DESC",
                (scan_id,),
            ).fetchall()
            parsed_vulns = []
            for v in vulns:
                item = dict(v)
                item["references"] = json.loads(item["references_json"] or "[]")
                parsed_vulns.append(item)
            scan["vulnerabilities"] = parsed_vulns
            return scan

    def get_all_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT s.*,
                       (SELECT COUNT(*) FROM ports p WHERE p.scan_id = s.id AND p.state = 'open') AS open_ports_count,
                       (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id) AS vuln_count,
                       (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id AND v.severity = 'Critical') AS critical_count,
                       (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id AND v.severity = 'High') AS high_count
                FROM scans s
                ORDER BY s.id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_vulnerability_by_id(self, vuln_id: int) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            row = conn.execute(
                """
                SELECT v.*, s.target, s.os_detected, s.asset_criticality, s.started_at
                FROM vulnerabilities v
                JOIN scans s ON v.scan_id = s.id
                WHERE v.id = ?
                """,
                (vuln_id,),
            ).fetchone()
            if not row:
                return None
            data = dict(row)
            data["references"] = json.loads(data["references_json"] or "[]")
            return data

    def compare_scans(self, baseline_scan_id: int, current_scan_id: int) -> Dict[str, Any]:
        base = self.get_scan(baseline_scan_id)
        curr = self.get_scan(current_scan_id)
        if not base or not curr:
            raise ValueError("One or both scan IDs do not exist.")

        def fingerprint(v: Dict[str, Any]) -> str:
            key = v["cve_id"] if v["cve_id"] and v["cve_id"] != "N/A" else v["title"]
            return f"{v.get('port_number')}:{v.get('service_name')}:{key}"

        base_map = {fingerprint(v): v for v in base["vulnerabilities"]}
        curr_map = {fingerprint(v): v for v in curr["vulnerabilities"]}

        new_vulns = [curr_map[k] for k in curr_map if k not in base_map]
        resolved_vulns = [base_map[k] for k in base_map if k not in curr_map]
        persistent_vulns = [curr_map[k] for k in curr_map if k in base_map]

        base_ports = {f"{p['port_number']}/{p['protocol']}" for p in base["ports"] if p["state"] == "open"}
        curr_ports = {f"{p['port_number']}/{p['protocol']}" for p in curr["ports"] if p["state"] == "open"}

        return {
            "baseline_scan_id": baseline_scan_id,
            "current_scan_id": current_scan_id,
            "baseline_target": base["target"],
            "current_target": curr["target"],
            "risk_delta": round(curr["overall_risk_score"] - base["overall_risk_score"], 2),
            "new_vulnerabilities": new_vulns,
            "resolved_vulnerabilities": resolved_vulns,
            "persistent_vulnerabilities": persistent_vulns,
            "newly_opened_ports": sorted(list(curr_ports - base_ports)),
            "closed_ports": sorted(list(base_ports - curr_ports)),
        }

    def get_cached_nvd(self, cache_key: str, max_age_hours: int) -> Optional[List[Dict[str, Any]]]:
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT response_json, fetched_at FROM nvd_cache WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
            if not row:
                return None
            fetched_at = datetime.fromisoformat(row["fetched_at"])
            age_hours = (datetime.now(timezone.utc) - fetched_at).total_seconds() / 3600.0
            if age_hours > max_age_hours:
                return None
            return json.loads(row["response_json"])

    def set_cached_nvd(self, cache_key: str, data: List[Dict[str, Any]]):
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO nvd_cache (cache_key, response_json, fetched_at)
                VALUES (?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    response_json = excluded.response_json,
                    fetched_at = excluded.fetched_at
                """,
                (cache_key, json.dumps(data), now),
            )
