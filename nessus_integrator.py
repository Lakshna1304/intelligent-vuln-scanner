import xml.etree.ElementTree as ET
import requests
import urllib3
from typing import Any, Dict, List
from config import Config, setup_logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = setup_logging()

NESSUS_SEVERITY_MAP = {
    "4": ("Critical", 9.5),
    "3": ("High", 7.8),
    "2": ("Medium", 5.3),
    "1": ("Low", 3.1),
    "0": ("Informational", 0.0),
}


class NessusIntegrator:
    def is_configured(self) -> bool:
        return bool(Config.NESSUS_URL and Config.NESSUS_ACCESS_KEY and Config.NESSUS_SECRET_KEY)

    def _headers(self) -> Dict[str, str]:
        return {
            "X-ApiKeys": f"accessKey={Config.NESSUS_ACCESS_KEY}; secretKey={Config.NESSUS_SECRET_KEY}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def list_nessus_scans(self) -> List[Dict[str, Any]]:
        if not self.is_configured():
            raise RuntimeError("Nessus API credentials are not configured in .env.")
        url = f"{Config.NESSUS_URL.rstrip('/')}/scans"
        resp = requests.get(url, headers=self._headers(), verify=Config.NESSUS_VERIFY_SSL, timeout=10)
        resp.raise_for_status()
        return resp.json().get("scans", [])

    def parse_nessus_xml(self, xml_content: str) -> Dict[str, Any]:
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid .nessus XML file: {exc}") from exc

        report_host = root.find(".//ReportHost")
        if report_host is None:
            raise ValueError("No ReportHost entries found inside .nessus XML.")

        target = report_host.attrib.get("name", "imported-nessus-host")
        os_detected = "Unknown (Nessus Import)"
        for tag in report_host.findall(".//HostProperties/tag"):
            if tag.attrib.get("name") == "operating-system" and tag.text:
                os_detected = tag.text.strip()

        ports_map: Dict[int, Dict[str, Any]] = {}
        findings: List[Dict[str, Any]] = []

        for item in report_host.findall("ReportItem"):
            port_num = int(item.attrib.get("port", 0))
            protocol = item.attrib.get("protocol", "tcp")
            svc_name = item.attrib.get("svc_name", "general")
            plugin_name = item.attrib.get("pluginName", "Nessus Finding")
            sev_code = item.attrib.get("severity", "0")

            if port_num > 0 and port_num not in ports_map:
                ports_map[port_num] = {
                    "port_number": port_num,
                    "protocol": protocol,
                    "state": "open",
                    "service_name": svc_name,
                    "product": svc_name,
                    "version": "",
                    "extrainfo": "Imported via Nessus",
                    "cpe": "",
                    "exposure_level": "High" if port_num in {21, 22, 445, 3306, 3389} else "Elevated",
                }

            default_sev, default_cvss = NESSUS_SEVERITY_MAP.get(sev_code, ("Informational", 0.0))
            cvss3_el = item.find("cvss3_base_score")
            cvss_score = float(cvss3_el.text) if (cvss3_el is not None and cvss3_el.text) else default_cvss
            cvss_vec_el = item.find("cvss3_vector")
            cvss_vector = cvss_vec_el.text if (cvss_vec_el is not None and cvss_vec_el.text) else "N/A"

            cve_el = item.find("cve")
            cve_id = cve_el.text.strip() if (cve_el is not None and cve_el.text) else "N/A"
            desc_el = item.find("description")
            sol_el = item.find("solution")
            out_el = item.find("plugin_output")

            findings.append(
                {
                    "port_number": port_num if port_num > 0 else None,
                    "protocol": protocol,
                    "service_name": svc_name,
                    "affected_software": svc_name,
                    "cve_id": cve_id,
                    "title": plugin_name,
                    "finding_type": "Confirmed CVE" if cve_id != "N/A" else "Potential Security Risk",
                    "description": (desc_el.text or "").strip() if desc_el is not None else plugin_name,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "evidence": (out_el.text or "Imported from Nessus ReportItem").strip()[:600] if out_el is not None else "Nessus plugin detection",
                    "remediation": (sol_el.text or "Apply vendor security patch.").strip() if sol_el is not None else "Apply vendor patch.",
                    "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"] if cve_id != "N/A" else [],
                    "source": "Tenable Nessus Import",
                }
            )

        return {
            "target": target,
            "os_detected": os_detected,
            "os_accuracy": 95,
            "ports": list(ports_map.values()),
            "findings": findings,
        }
