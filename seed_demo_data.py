"""
Seeds an initial baseline scan in SQLite so the Scan Comparison (New vs. Resolved)
and Historical Trend views work immediately on first launch.
"""
from database import DatabaseManager
from risk_scorer import RiskScoringEngine


def seed():
    db = DatabaseManager()
    if db.get_all_scans(limit=1):
        print("Database already contains scan history. Skipping seed.")
        return

    scorer = RiskScoringEngine()
    scan_id = db.create_scan("127.0.0.1", "demo", "High")

    baseline_ports = [
        {
            "port_number": 21,
            "protocol": "tcp",
            "state": "open",
            "service_name": "ftp",
            "product": "vsftpd",
            "version": "3.0.3",
            "extrainfo": "Cleartext FTP",
            "cpe": "cpe:/a:vsftpd_project:vsftpd:3.0.3",
            "exposure_level": "High",
        },
        {
            "port_number": 23,
            "protocol": "tcp",
            "state": "open",
            "service_name": "telnet",
            "product": "Linux telnetd",
            "version": "",
            "extrainfo": "Legacy remote shell",
            "cpe": "",
            "exposure_level": "High",
        },
        {
            "port_number": 80,
            "protocol": "tcp",
            "state": "open",
            "service_name": "http",
            "product": "Apache httpd",
            "version": "2.4.49",
            "extrainfo": "Unix",
            "cpe": "cpe:/a:apache:http_server:2.4.49",
            "exposure_level": "Elevated",
        },
    ]

    baseline_findings = [
        {
            "port_number": 80,
            "protocol": "tcp",
            "service_name": "http",
            "affected_software": "Apache httpd 2.4.49",
            "cve_id": "CVE-2021-41773",
            "title": "Apache HTTP Server Path Traversal and Remote Code Execution",
            "finding_type": "Confirmed CVE",
            "description": "Path normalization flaw in Apache HTTP Server 2.4.49 allows path traversal and RCE.",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "evidence": "Port 80/tcp banner identified Apache httpd 2.4.49",
            "remediation": "Upgrade Apache HTTP Server to 2.4.51 or later.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
            "source": "Verified CVE Advisory / NVD",
        },
        {
            "port_number": 23,
            "protocol": "tcp",
            "service_name": "telnet",
            "affected_software": "Linux telnetd",
            "cve_id": "N/A",
            "title": "Unencrypted Telnet Remote Administration Service Exposed",
            "finding_type": "Potential Security Risk",
            "description": "Telnet transmits credentials in cleartext over the network.",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "evidence": "Port 23/tcp open (telnet)",
            "remediation": "Disable Telnet and migrate to OpenSSH.",
            "references": [],
            "source": "Configuration & Attack Surface Analyzer",
        },
    ]

    db.save_ports(scan_id, baseline_ports)
    scored, overall, grade, surface = scorer.score_and_prioritize(baseline_findings, baseline_ports, "High")
    db.save_vulnerabilities(scan_id, scored)
    db.complete_scan(scan_id, "Linux 5.4 (Ubuntu 20.04 LTS Baseline)", 95, overall, grade, surface)
    print(f"Seeded Baseline Scan #{scan_id} successfully.")


if __name__ == "__main__":
    seed()
