import time
import re
import requests
from typing import Any, Dict, List, Optional
from packaging import version as pkg_version
from config import Config, setup_logging
from database import DatabaseManager

logger = setup_logging()

VERIFIED_ADVISORY_KNOWLEDGE_BASE: List[Dict[str, Any]] = [
    {
        "product_pattern": r"apache\s*httpd",
        "affected_versions": ["2.4.49", "2.4.50"],
        "cve_id": "CVE-2021-41773",
        "title": "Apache HTTP Server Path Traversal and Remote Code Execution",
        "description": "A flaw in path normalization in Apache HTTP Server 2.4.49 allows an attacker to map URLs to files outside the expected document root and execute arbitrary scripts if CGI is enabled.",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "remediation": "Upgrade Apache HTTP Server immediately to version 2.4.51 or later. Ensure 'Require all denied' is enforced on filesystem root directories.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773", "https://httpd.apache.org/security/vulnerabilities_24.html"],
    },
    {
        "product_pattern": r"openssh",
        "max_vulnerable_version": "9.7",
        "min_vulnerable_version": "8.5",
        "cve_id": "CVE-2024-6387",
        "title": "OpenSSH Server RegreSSHion Signal Handler Race Condition",
        "description": "A signal handler race condition in OpenSSH's server (sshd) on glibc-based Linux systems allows unauthenticated remote code execution as root under specific timing conditions.",
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "remediation": "Upgrade OpenSSH to 9.8p1 or apply vendor backported security patches. Set LoginGraceTime to 0 as a temporary mitigation if patching is delayed.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
    },
    {
        "product_pattern": r"openssh",
        "max_vulnerable_version": "8.4",
        "min_vulnerable_version": "7.0",
        "cve_id": "CVE-2021-41617",
        "title": "OpenSSH Privilege Escalation via AuthorizedKeysCommand",
        "description": "sshd in OpenSSH 6.2 through 8.x before 8.8 fails to initialize supplemental groups when executing AuthorizedKeysCommand or AuthorizedPrincipalsCommand.",
        "cvss_score": 7.0,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "remediation": "Upgrade OpenSSH to version 8.8p1 or newer and restrict SSH access using key-based authentication and firewall allowlists.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41617"],
    },
    {
        "product_pattern": r"samba",
        "max_vulnerable_version": "4.13.16",
        "min_vulnerable_version": "4.13.0",
        "cve_id": "CVE-2021-44142",
        "title": "Samba Out-of-Bounds Heap Read/Write in vfs_fruit Module",
        "description": "An out-of-bounds heap read/write vulnerability in Samba's vfs_fruit module allows remote attackers with write access to extended file attributes to execute arbitrary code as root.",
        "cvss_score": 9.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "remediation": "Upgrade Samba to 4.13.17, 4.14.12, or 4.15.5+ and remove 'fruit' from 'vfs objects' in smb.conf if macOS compatibility is not required.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44142"],
    },
    {
        "product_pattern": r"mysql",
        "max_vulnerable_version": "8.0.27",
        "min_vulnerable_version": "8.0.0",
        "cve_id": "CVE-2022-21245",
        "title": "Oracle MySQL Server Optimizer Denial of Service Vulnerability",
        "description": "Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer) allows high-privileged network attackers to cause a repeatable crash (DoS).",
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H",
        "remediation": "Apply the Oracle Critical Patch Update (upgrade MySQL to 8.0.28 or latest 8.0/8.4 LTS release) and bind MySQL to 127.0.0.1.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-21245"],
    },
    {
        "product_pattern": r"redis",
        "max_vulnerable_version": "6.0.15",
        "min_vulnerable_version": "6.0.0",
        "cve_id": "CVE-2021-32762",
        "title": "Redis Integer Overflow in redis-cli / Bulk Protocol Handling",
        "description": "An integer overflow vulnerability in Redis allows specially crafted multi-bulk protocol commands to trigger heap corruption.",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "remediation": "Upgrade Redis to 6.0.16+ or 6.2.6+, enable requirepass/ACL authentication, and disable protected-mode bypasses.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-32762"],
    },
]

CONFIGURATION_RISK_RULES = [
    {
        "port": 21,
        "service": "ftp",
        "title": "Unencrypted Cleartext File Transfer Protocol (FTP) Exposed",
        "description": "FTP transmits authentication credentials and data in plaintext, exposing sessions to passive network interception.",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "remediation": "Decommission cleartext FTP (port 21) and migrate file transfers to SFTP (SSH File Transfer Protocol) or FTPS with TLS 1.3.",
    },
    {
        "port": 23,
        "service": "telnet",
        "title": "Unencrypted Telnet Remote Administration Service Exposed",
        "description": "Telnet lacks encryption and cryptographic authentication, allowing credential sniffing and session hijacking.",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "remediation": "Disable the Telnet daemon immediately and replace remote management with hardened OpenSSH.",
    },
    {
        "port": 3306,
        "service": "mysql",
        "title": "Database Service (MySQL) Exposed Over Network Interface",
        "description": "Direct network exposure of database ports increases brute-force, credential stuffing, and protocol-level exploitation attack surface.",
        "cvss_score": 5.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "remediation": "Configure 'bind-address = 127.0.0.1' in my.cnf or restrict TCP/3306 strictly to application server IPs via host firewall rules.",
    },
    {
        "port": 6379,
        "service": "redis",
        "title": "In-Memory Datastore (Redis) Exposed Without Network Segmentation",
        "description": "Exposed Redis instances frequently lack authentication by default, enabling unauthenticated data exfiltration or SSH key injection.",
        "cvss_score": 7.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "remediation": "Bind Redis to localhost (127.0.0.1), enforce strong ACL passwords, and rename dangerous commands (FLUSHALL, CONFIG).",
    },
]


class VulnerabilityCorrelator:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self._last_nvd_call = 0.0

    def _normalize_version(self, raw_ver: str) -> Optional[str]:
        if not raw_ver:
            return None
        match = re.search(r"(\d+\.\d+(?:\.\d+)?)", raw_ver)
        return match.group(1) if match else None

    def _is_version_affected(self, detected_ver: Optional[str], rule: Dict[str, Any]) -> bool:
        if not detected_ver:
            return False
        if "affected_versions" in rule:
            return detected_ver in rule["affected_versions"]
        try:
            v = pkg_version.parse(detected_ver)
            min_v = pkg_version.parse(rule.get("min_vulnerable_version", "0.0.0"))
            max_v = pkg_version.parse(rule["max_vulnerable_version"])
            return min_v <= v <= max_v
        except Exception:
            return False

    def _respect_nvd_rate_limit(self):
        min_interval = 0.7 if Config.NVD_API_KEY else 6.2
        elapsed = time.time() - self._last_nvd_call
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_nvd_call = time.time()

    def query_nvd_api(self, product: str, version: str) -> List[Dict[str, Any]]:
        if not product or not version:
            return []

        cache_key = f"nvd:{product.lower().strip()}:{version.strip()}"
        cached = self.db.get_cached_nvd(cache_key, Config.NVD_CACHE_TTL_HOURS)
        if cached is not None:
            return cached

        self._respect_nvd_rate_limit()
        headers = {"User-Agent": "AegisVuln-SecurityScanner/1.0"}
        if Config.NVD_API_KEY:
            headers["apiKey"] = Config.NVD_API_KEY

        params = {
            "keywordSearch": f"{product} {version}",
            "resultsPerPage": 5,
            "noRejected": "",
        }

        results: List[Dict[str, Any]] = []
        try:
            resp = requests.get(Config.NVD_API_URL, params=params, headers=headers, timeout=12)
            if resp.status_code == 200:
                payload = resp.json()
                for item in payload.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "N/A")
                    descriptions = cve.get("descriptions", [])
                    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description available.")

                    if version not in desc_en and product.lower() not in desc_en.lower():
                        continue

                    metrics = cve.get("metrics", {})
                    cvss_score = 0.0
                    cvss_vector = "N/A"
                    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
                        if metric_key in metrics and metrics[metric_key]:
                            cvss_data = metrics[metric_key][0].get("cvssData", {})
                            cvss_score = float(cvss_data.get("baseScore", 0.0))
                            cvss_vector = cvss_data.get("vectorString", "N/A")
                            break

                    refs = [r.get("url") for r in cve.get("references", [])[:3] if r.get("url")]
                    results.append(
                        {
                            "cve_id": cve_id,
                            "title": f"{product} {version} — {cve_id}",
                            "description": desc_en,
                            "cvss_score": cvss_score,
                            "cvss_vector": cvss_vector,
                            "remediation": f"Review vendor advisory for {cve_id} and upgrade {product} beyond version {version}.",
                            "references": refs or [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                        }
                    )
                self.db.set_cached_nvd(cache_key, results)
            else:
                logger.warning("NVD API returned HTTP %s for '%s %s'", resp.status_code, product, version)
        except requests.RequestException as exc:
            logger.warning("NVD API unreachable (%s); relying on local verified advisory database.", exc)

        return results

    def analyze_ports(self, ports: List[Dict[str, Any]], use_live_nvd: bool = True) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        seen_keys = set()

        for port in ports:
            if port.get("state") != "open":
                continue

            port_num = port["port_number"]
            protocol = port.get("protocol", "tcp")
            service_name = port.get("service_name", "unknown")
            product = port.get("product", "")
            raw_version = port.get("version", "")
            norm_ver = self._normalize_version(raw_version)
            software_label = f"{product} {raw_version}".strip() or service_name

            for rule in VERIFIED_ADVISORY_KNOWLEDGE_BASE:
                if product and re.search(rule["product_pattern"], product, re.IGNORECASE):
                    if self._is_version_affected(norm_ver, rule):
                        dedup = (port_num, rule["cve_id"])
                        if dedup not in seen_keys:
                            seen_keys.add(dedup)
                            findings.append(
                                {
                                    "port_number": port_num,
                                    "protocol": protocol,
                                    "service_name": service_name,
                                    "affected_software": software_label,
                                    "cve_id": rule["cve_id"],
                                    "title": rule["title"],
                                    "finding_type": "Confirmed CVE",
                                    "description": rule["description"],
                                    "cvss_score": rule["cvss_score"],
                                    "cvss_vector": rule["cvss_vector"],
                                    "evidence": f"Port {port_num}/{protocol} banner identified '{software_label}' (CPE: {port.get('cpe') or 'N/A'}), matching vulnerable version criteria for {rule['cve_id']}.",
                                    "remediation": rule["remediation"],
                                    "references": rule["references"],
                                    "source": "Verified CVE Advisory / NVD",
                                }
                            )

            if use_live_nvd and product and norm_ver:
                nvd_hits = self.query_nvd_api(product, norm_ver)
                for hit in nvd_hits:
                    dedup = (port_num, hit["cve_id"])
                    if dedup not in seen_keys:
                        seen_keys.add(dedup)
                        findings.append(
                            {
                                "port_number": port_num,
                                "protocol": protocol,
                                "service_name": service_name,
                                "affected_software": software_label,
                                "cve_id": hit["cve_id"],
                                "title": hit["title"],
                                "finding_type": "Confirmed CVE",
                                "description": hit["description"],
                                "cvss_score": hit["cvss_score"],
                                "cvss_vector": hit["cvss_vector"],
                                "evidence": f"Service fingerprint '{software_label}' on {port_num}/{protocol} correlated with NIST NVD v2.0 record {hit['cve_id']}.",
                                "remediation": hit["remediation"],
                                "references": hit["references"],
                                "source": "NIST NVD API v2.0",
                            }
                        )

            for cfg_rule in CONFIGURATION_RISK_RULES:
                if port_num == cfg_rule["port"] or service_name.lower() == cfg_rule["service"]:
                    dedup = (port_num, cfg_rule["title"])
                    if dedup not in seen_keys:
                        seen_keys.add(dedup)
                        findings.append(
                            {
                                "port_number": port_num,
                                "protocol": protocol,
                                "service_name": service_name,
                                "affected_software": software_label,
                                "cve_id": "N/A",
                                "title": cfg_rule["title"],
                                "finding_type": "Potential Security Risk",
                                "description": cfg_rule["description"],
                                "cvss_score": cfg_rule["cvss_score"],
                                "cvss_vector": cfg_rule["cvss_vector"],
                                "evidence": f"Open port {port_num}/{protocol} ({service_name}) detected with banner '{software_label}'.",
                                "remediation": cfg_rule["remediation"],
                                "references": ["https://owasp.org/www-project-top-ten/"],
                                "source": "Configuration & Attack Surface Analyzer",
                            }
                        )

            if not product and not raw_version:
                dedup = (port_num, "Unidentified Service Banner")
                if dedup not in seen_keys:
                    seen_keys.add(dedup)
                    findings.append(
                        {
                            "port_number": port_num,
                            "protocol": protocol,
                            "service_name": service_name,
                            "affected_software": f"Unknown ({service_name})",
                            "cve_id": "N/A",
                            "title": f"Unidentified Service Version on Port {port_num}/{protocol}",
                            "finding_type": "Potential Security Risk",
                            "description": "The service responded on an open port without revealing a standard software version banner, requiring manual configuration verification.",
                            "cvss_score": 0.0,
                            "cvss_vector": "N/A",
                            "evidence": f"Port {port_num}/{protocol} reported state 'open' for service '{service_name}' with empty version metadata.",
                            "remediation": "Verify business necessity of this listener; close unused ports or restrict access via host firewall.",
                            "references": [],
                            "source": "Attack Surface Analyzer",
                        }
                    )

        return findings
