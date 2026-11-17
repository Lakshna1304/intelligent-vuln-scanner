from typing import Any, Dict, List, Tuple

CRITICALITY_MULTIPLIERS = {
    "Low": 0.85,
    "Medium": 1.00,
    "High": 1.15,
    "Mission-Critical": 1.30,
}

SENSITIVE_SERVICES = {
    "microsoft-ds": 1.2,
    "smb": 1.2,
    "rdp": 1.2,
    "ms-wbt-server": 1.2,
    "mysql": 1.0,
    "postgresql": 1.0,
    "redis": 1.1,
    "mongodb": 1.1,
    "ssh": 0.8,
    "http": 0.9,
    "https": 0.9,
    "ftp": 0.9,
}


class RiskScoringEngine:
    @staticmethod
    def classify_severity(score: float) -> str:
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        if score > 0.0:
            return "Low"
        return "Informational"

    def score_and_prioritize(
        self,
        findings: List[Dict[str, Any]],
        ports: List[Dict[str, Any]],
        asset_criticality: str = "Medium",
    ) -> Tuple[List[Dict[str, Any]], float, str, Dict[str, Any]]:
        crit_mult = CRITICALITY_MULTIPLIERS.get(asset_criticality, 1.0)
        scored_findings: List[Dict[str, Any]] = []

        for item in findings:
            base_cvss = float(item.get("cvss_score", 0.0))
            severity = self.classify_severity(base_cvss)
            service = (item.get("service_name") or "").lower()
            finding_type = item.get("finding_type", "Potential Security Risk")

            service_bonus = SENSITIVE_SERVICES.get(service, 0.4) if base_cvss > 0 else 0.0
            confirmed_bonus = 0.6 if finding_type == "Confirmed CVE" else 0.0

            raw_priority = (base_cvss + service_bonus + confirmed_bonus) * crit_mult
            priority_score = round(min(10.0, raw_priority), 2)

            business_impact = self._generate_business_impact(severity, service, asset_criticality, finding_type)

            enriched = dict(item)
            enriched["severity"] = severity
            enriched["priority_score"] = priority_score
            enriched["business_impact"] = business_impact
            scored_findings.append(enriched)

        scored_findings.sort(key=lambda x: (x["priority_score"], x["cvss_score"]), reverse=True)
        for idx, item in enumerate(scored_findings, start=1):
            item["priority_rank"] = idx

        if not scored_findings:
            overall_score = 0.0
        else:
            top_scores = [f["priority_score"] for f in scored_findings[:5]]
            peak = top_scores[0]
            avg_top = sum(top_scores) / len(top_scores)
            overall_score = round(min(10.0, (peak * 0.65) + (avg_top * 0.35)), 2)

        risk_grade = self.classify_severity(overall_score)
        attack_surface = self._build_attack_surface_summary(ports, scored_findings)

        return scored_findings, overall_score, risk_grade, attack_surface

    def _generate_business_impact(self, severity: str, service: str, criticality: str, finding_type: str) -> str:
        if severity == "Critical":
            return (
                f"[{criticality} Asset] Immediate risk of remote code execution, full host compromise, "
                f"or lateral movement via {service.upper()}."
            )
        if severity == "High":
            return (
                f"[{criticality} Asset] High likelihood of unauthorized data access, privilege escalation, "
                f"or service disruption on {service.upper()}."
            )
        if severity == "Medium":
            return (
                f"[{criticality} Asset] Moderate risk of information disclosure or configuration abuse "
                f"({finding_type})."
            )
        if severity == "Low":
            return f"[{criticality} Asset] Minor hardening gap with limited standalone exploitability."
        return f"[{criticality} Asset] Informational visibility finding for attack surface inventory."

    def _build_attack_surface_summary(
        self, ports: List[Dict[str, Any]], findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        open_ports = [p for p in ports if p.get("state") == "open"]
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        confirmed_cves = 0
        potential_risks = 0

        for f in findings:
            sev = f.get("severity", "Informational")
            if sev in severity_counts:
                severity_counts[sev] += 1
            if f.get("finding_type") == "Confirmed CVE":
                confirmed_cves += 1
            else:
                potential_risks += 1

        high_exposure_services = [
            f"{p['port_number']}/{p['protocol']} ({p.get('service_name', 'unknown')})"
            for p in open_ports
            if p.get("exposure_level") == "High"
        ]

        return {
            "total_open_ports": len(open_ports),
            "high_exposure_ports_count": len(high_exposure_services),
            "high_exposure_services": high_exposure_services,
            "confirmed_cves_count": confirmed_cves,
            "potential_risks_count": potential_risks,
            "severity_distribution": severity_counts,
        }
