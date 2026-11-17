import threading
from flask import Flask, jsonify, render_template, request, send_file, abort
from config import Config, setup_logging
from database import DatabaseManager
from scanner import NmapScannerEngine, TargetValidationError
from vuln_correlator import VulnerabilityCorrelator
from risk_scorer import RiskScoringEngine
from nessus_integrator import NessusIntegrator
from report_generator import PDFReportGenerator

logger = setup_logging()
Config.ensure_directories()

app = Flask(__name__)
app.config["SECRET_KEY"] = Config.SECRET_KEY

db = DatabaseManager()
scanner = NmapScannerEngine()
correlator = VulnerabilityCorrelator(db)
scorer = RiskScoringEngine()
nessus = NessusIntegrator()
pdf_gen = PDFReportGenerator()


def _execute_scan_pipeline(scan_id: int, target: str, scan_mode: str, asset_criticality: str, use_live_nvd: bool):
    try:
        db.update_scan_progress(scan_id, 20, f"Enumerating open ports and service banners on {target}...")
        scan_result = scanner.run_scan(target=target, scan_mode=scan_mode, authorization_confirmed=True)
        ports = scan_result["ports"]
        db.save_ports(scan_id, ports)

        db.update_scan_progress(scan_id, 55, f"Discovered {len(ports)} open ports. Correlating with NIST NVD CVE database...")
        raw_findings = correlator.analyze_ports(ports, use_live_nvd=use_live_nvd)

        db.update_scan_progress(scan_id, 85, "Calculating contextual risk scores and business impact rankings...")
        scored_findings, overall_score, risk_grade, attack_surface = scorer.score_and_prioritize(
            raw_findings, ports, asset_criticality=asset_criticality
        )
        db.save_vulnerabilities(scan_id, scored_findings)

        db.complete_scan(
            scan_id=scan_id,
            os_detected=scan_result["os_detected"],
            os_accuracy=scan_result["os_accuracy"],
            overall_risk_score=overall_score,
            risk_grade=risk_grade,
            attack_surface_summary=attack_surface,
        )
        logger.info("Scan #%s completed for %s | Risk=%s (%s)", scan_id, target, overall_score, risk_grade)
    except Exception as exc:
        logger.exception("Scan #%s failed: %s", scan_id, exc)
        db.fail_scan(scan_id, str(exc))


@app.route("/")
def index():
    return render_template("index.html", nessus_configured=nessus.is_configured())


@app.route("/vulnerability/<int:vuln_id>")
def vulnerability_detail_page(vuln_id: int):
    vuln = db.get_vulnerability_by_id(vuln_id)
    if not vuln:
        abort(404)
    return render_template("vulnerability_detail.html", vuln=vuln)


@app.route("/api/validate-target", methods=["POST"])
def api_validate_target():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    auth_confirmed = bool(data.get("authorization_confirmed", False))
    try:
        _, normalized = scanner.validate_target(target, auth_confirmed)
        return jsonify({"valid": True, "normalized_target": normalized, "message": f"Target {normalized} is authorized within configured scope."})
    except TargetValidationError as exc:
        return jsonify({"valid": False, "message": str(exc)}), 400


@app.route("/api/scans", methods=["GET"])
def api_list_scans():
    scans = db.get_all_scans(limit=50)
    return jsonify({"scans": scans})


@app.route("/api/scans", methods=["POST"])
def api_start_scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    scan_mode = data.get("scan_mode", "demo")
    asset_criticality = data.get("asset_criticality", "Medium")
    auth_confirmed = bool(data.get("authorization_confirmed", False))
    use_live_nvd = bool(data.get("use_live_nvd", True))

    if scan_mode not in ("demo", "quick", "standard", "deep"):
        return jsonify({"error": "Invalid scan_mode. Choose demo, quick, standard, or deep."}), 400

    try:
        _, normalized_target = scanner.validate_target(target, auth_confirmed)
    except TargetValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    scan_id = db.create_scan(normalized_target, scan_mode, asset_criticality)
    db.log_audit(
        action="SCAN_INITIATED",
        target=normalized_target,
        operator_ip=request.remote_addr or "127.0.0.1",
        details=f"scan_id={scan_id}, mode={scan_mode}, criticality={asset_criticality}",
    )

    worker = threading.Thread(
        target=_execute_scan_pipeline,
        args=(scan_id, normalized_target, scan_mode, asset_criticality, use_live_nvd),
        daemon=True,
    )
    worker.start()

    return jsonify({"scan_id": scan_id, "status": "running", "target": normalized_target}), 202


@app.route("/api/scans/<int:scan_id>", methods=["GET"])
def api_get_scan(scan_id: int):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan)


@app.route("/api/scans/compare", methods=["GET"])
def api_compare_scans():
    try:
        baseline_id = int(request.args.get("baseline", 0))
        current_id = int(request.args.get("current", 0))
        diff = db.compare_scans(baseline_id, current_id)
        return jsonify(diff)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/scans/<int:scan_id>/report", methods=["GET"])
def api_download_report(scan_id: int):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    if scan["status"] != "completed":
        return jsonify({"error": "Report generation requires a completed scan."}), 400

    pdf_path = pdf_gen.generate_report(scan)
    db.log_audit("PDF_REPORT_EXPORTED", target=scan["target"], details=f"scan_id={scan_id}, file={pdf_path.name}")
    return send_file(pdf_path, as_attachment=True, download_name=pdf_path.name)


@app.route("/api/nessus/import-xml", methods=["POST"])
def api_import_nessus_xml():
    if "file" not in request.files:
        return jsonify({"error": "No .nessus XML file uploaded."}), 400
    uploaded = request.files["file"]
    xml_text = uploaded.read().decode("utf-8", errors="replace")
    asset_criticality = request.form.get("asset_criticality", "High")

    try:
        parsed = nessus.parse_nessus_xml(xml_text)
        scan_id = db.create_scan(parsed["target"], "nessus-import", asset_criticality)
        db.save_ports(scan_id, parsed["ports"])
        scored_findings, overall_score, risk_grade, attack_surface = scorer.score_and_prioritize(
            parsed["findings"], parsed["ports"], asset_criticality=asset_criticality
        )
        db.save_vulnerabilities(scan_id, scored_findings)
        db.complete_scan(
            scan_id=scan_id,
            os_detected=parsed["os_detected"],
            os_accuracy=parsed["os_accuracy"],
            overall_risk_score=overall_score,
            risk_grade=risk_grade,
            attack_surface_summary=attack_surface,
        )
        return jsonify({"scan_id": scan_id, "message": "Nessus report imported successfully."}), 201
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


if __name__ == "__main__":
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
