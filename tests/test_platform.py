import pytest
from scanner import NmapScannerEngine, TargetValidationError
from vuln_correlator import VulnerabilityCorrelator
from risk_scorer import RiskScoringEngine
from database import DatabaseManager
from report_generator import PDFReportGenerator


def test_target_validation_enforces_authorization():
    engine = NmapScannerEngine()
    with pytest.raises(TargetValidationError):
        engine.validate_target("127.0.0.1", authorization_confirmed=False)


def test_target_validation_blocks_unauthorized_public_ip():
    engine = NmapScannerEngine()
    with pytest.raises(TargetValidationError):
        engine.validate_target("8.8.8.8", authorization_confirmed=True)


def test_target_validation_blocks_command_injection():
    engine = NmapScannerEngine()
    with pytest.raises(TargetValidationError):
        engine.validate_target("127.0.0.1; rm -rf /", authorization_confirmed=True)


def test_demo_scan_correlates_confirmed_cves_and_potential_risks(tmp_path):
    db = DatabaseManager(str(tmp_path / "test.db"))
    scanner = NmapScannerEngine()
    correlator = VulnerabilityCorrelator(db)
    scorer = RiskScoringEngine()

    scan_out = scanner.run_scan("127.0.0.1", scan_mode="demo", authorization_confirmed=True)
    findings = correlator.analyze_ports(scan_out["ports"], use_live_nvd=False)
    scored, overall, grade, summary = scorer.score_and_prioritize(findings, scan_out["ports"], "Mission-Critical")

    assert len(scan_out["ports"]) == 6
    assert summary["confirmed_cves_count"] >= 4
    assert summary["potential_risks_count"] >= 3
    assert grade == "Critical"
    assert scored[0]["priority_rank"] == 1


def test_scan_comparison_identifies_new_and_resolved(tmp_path):
    db = DatabaseManager(str(tmp_path / "diff.db"))
    s1 = db.create_scan("127.0.0.1", "demo", "High")
    db.save_vulnerabilities(
        s1,
        [
            {
                "port_number": 23,
                "service_name": "telnet",
                "cve_id": "N/A",
                "title": "Telnet Exposed",
                "finding_type": "Potential Security Risk",
                "description": "Cleartext telnet",
                "cvss_score": 7.5,
                "severity": "High",
                "priority_score": 8.0,
                "priority_rank": 1,
                "remediation": "Disable telnet",
            }
        ],
    )
    db.complete_scan(s1, "Linux", 90, 8.0, "High", {})

    s2 = db.create_scan("127.0.0.1", "demo", "High")
    db.save_vulnerabilities(
        s2,
        [
            {
                "port_number": 80,
                "service_name": "http",
                "cve_id": "CVE-2021-41773",
                "title": "Apache Path Traversal",
                "finding_type": "Confirmed CVE",
                "description": "Path traversal",
                "cvss_score": 9.8,
                "severity": "Critical",
                "priority_score": 10.0,
                "priority_rank": 1,
                "remediation": "Upgrade Apache",
            }
        ],
    )
    db.complete_scan(s2, "Linux", 90, 9.5, "Critical", {})

    diff = db.compare_scans(s1, s2)
    assert len(diff["resolved_vulnerabilities"]) == 1
    assert len(diff["new_vulnerabilities"]) == 1


def test_pdf_report_generation(tmp_path):
    db = DatabaseManager(str(tmp_path / "pdf.db"))
    scanner = NmapScannerEngine()
    correlator = VulnerabilityCorrelator(db)
    scorer = RiskScoringEngine()
    pdf_gen = PDFReportGenerator()

    scan_id = db.create_scan("127.0.0.1", "demo", "High")
    out = scanner.run_scan("127.0.0.1", "demo", True)
    db.save_ports(scan_id, out["ports"])
    findings = correlator.analyze_ports(out["ports"], use_live_nvd=False)
    scored, overall, grade, summary = scorer.score_and_prioritize(findings, out["ports"], "High")
    db.save_vulnerabilities(scan_id, scored)
    db.complete_scan(scan_id, out["os_detected"], out["os_accuracy"], overall, grade, summary)

    scan = db.get_scan(scan_id)
    pdf_path = pdf_gen.generate_report(scan)
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 2000
