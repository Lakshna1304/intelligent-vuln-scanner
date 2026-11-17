import ipaddress
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Tuple
from config import Config, setup_logging

logger = setup_logging()

HIGH_EXPOSURE_PORTS = {21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}


class TargetValidationError(Exception):
    pass


class NmapScannerEngine:
    def __init__(self):
        self.allowed_networks = [
            ipaddress.ip_network(cidr, strict=False) for cidr in Config.ALLOWED_TARGET_CIDRS
        ]

    def validate_target(self, target: str, authorization_confirmed: bool) -> Tuple[bool, str]:
        if not authorization_confirmed:
            raise TargetValidationError(
                "Explicit authorization confirmation is required prior to initiating any network scan."
            )

        cleaned = target.strip()
        if not cleaned or len(cleaned) > 64:
            raise TargetValidationError("Target cannot be empty or exceed 64 characters.")

        if not re.match(r"^[a-zA-Z0-9\.\-:/]+$", cleaned):
            raise TargetValidationError("Invalid characters detected in target specification.")

        if cleaned.lower() == "localhost":
            cleaned = "127.0.0.1"

        try:
            if "/" in cleaned:
                net = ipaddress.ip_network(cleaned, strict=False)
                if net.prefixlen < 28:
                    raise TargetValidationError(
                        "CIDR prefix must be /28 or smaller (max 16 hosts) to prevent broad network sweeps."
                    )
                if not any(net.subnet_of(allowed) for allowed in self.allowed_networks if net.version == allowed.version):
                    raise TargetValidationError(
                        f"Target network {cleaned} is outside ALLOWED_TARGET_CIDRS scope."
                    )
            else:
                ip_obj = ipaddress.ip_address(cleaned)
                if not any(ip_obj in allowed for allowed in self.allowed_networks):
                    raise TargetValidationError(
                        f"Target IP {cleaned} is outside authorized RFC1918/localhost scope. Update ALLOWED_TARGET_CIDRS if explicitly authorized."
                    )
        except ValueError as exc:
            raise TargetValidationError(f"Invalid IPv4/IPv6 address format: {exc}") from exc

        return True, cleaned

    def classify_port_exposure(self, port_num: int, service_name: str) -> str:
        svc = (service_name or "").lower()
        if port_num in HIGH_EXPOSURE_PORTS or any(
            k in svc for k in ("smb", "rdp", "telnet", "ftp", "mysql", "postgres", "redis", "mongo", "ssh")
        ):
            return "High"
        if port_num in {80, 443, 8080, 8443} or "http" in svc:
            return "Elevated"
        return "Moderate"

    def run_scan(self, target: str, scan_mode: str = "standard", authorization_confirmed: bool = False) -> Dict[str, Any]:
        _, validated_target = self.validate_target(target, authorization_confirmed)

        if scan_mode == "demo":
            logger.info("Executing Localhost Safe Demo Mode simulation for target=%s", validated_target)
            return self._run_localhost_demo_profile(validated_target)

        nmap_bin = shutil.which(Config.NMAP_BINARY_PATH)
        if not nmap_bin:
            raise RuntimeError(
                f"Nmap executable '{Config.NMAP_BINARY_PATH}' was not found in PATH. Install Nmap or use 'Localhost Demo Mode'."
            )

        if scan_mode == "quick":
            cmd = [nmap_bin, "-sT", "-sV", "--version-intensity", "5", "--top-ports", "100", "-T4", "-oX", "-", validated_target]
        elif scan_mode == "deep":
            cmd = [nmap_bin, "-sT", "-sV", "-O", "--osscan-guess", "--version-intensity", "7", "--top-ports", "1000", "-T4", "-oX", "-", validated_target]
        else:
            cmd = [nmap_bin, "-sT", "-sV", "--version-intensity", "6", "--top-ports", "300", "-T4", "-oX", "-", validated_target]

        logger.info("Executing safe Nmap command: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=Config.NMAP_TIMEOUT_SECONDS,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Nmap scan timed out after {Config.NMAP_TIMEOUT_SECONDS}s.") from exc

        if proc.returncode != 0 and not proc.stdout.strip():
            raise RuntimeError(f"Nmap failed (code {proc.returncode}): {proc.stderr.strip()}")

        return self.parse_nmap_xml(proc.stdout, validated_target)

    def parse_nmap_xml(self, xml_output: str, target: str) -> Dict[str, Any]:
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as exc:
            raise RuntimeError(f"Failed to parse Nmap XML output: {exc}") from exc

        ports: List[Dict[str, Any]] = []
        os_detected = "Unknown / Filtered"
        os_accuracy = 0

        host_elem = root.find("host")
        if host_elem is not None:
            os_elem = host_elem.find("os")
            if os_elem is not None:
                osmatch = os_elem.find("osmatch")
                if osmatch is not None:
                    os_detected = osmatch.attrib.get("name", "Unknown")
                    os_accuracy = int(osmatch.attrib.get("accuracy", "0"))

            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_el in ports_elem.findall("port"):
                    state_el = port_el.find("state")
                    state = state_el.attrib.get("state", "closed") if state_el is not None else "closed"
                    if state not in ("open", "open|filtered"):
                        continue

                    port_num = int(port_el.attrib.get("portid", 0))
                    protocol = port_el.attrib.get("protocol", "tcp")
                    service_el = port_el.find("service")

                    service_name = "unknown"
                    product = ""
                    version = ""
                    extrainfo = ""
                    cpe = ""

                    if service_el is not None:
                        service_name = service_el.attrib.get("name", "unknown")
                        product = service_el.attrib.get("product", "")
                        version = service_el.attrib.get("version", "")
                        extrainfo = service_el.attrib.get("extrainfo", "")
                        cpe_el = service_el.find("cpe")
                        if cpe_el is not None and cpe_el.text:
                            cpe = cpe_el.text.strip()

                    ports.append(
                        {
                            "port_number": port_num,
                            "protocol": protocol,
                            "state": state,
                            "service_name": service_name,
                            "product": product,
                            "version": version,
                            "extrainfo": extrainfo,
                            "cpe": cpe,
                            "exposure_level": self.classify_port_exposure(port_num, service_name),
                        }
                    )

        return {
            "target": target,
            "os_detected": os_detected,
            "os_accuracy": os_accuracy,
            "ports": ports,
        }

    def _run_localhost_demo_profile(self, target: str) -> Dict[str, Any]:
        demo_ports = [
            {
                "port_number": 21,
                "protocol": "tcp",
                "state": "open",
                "service_name": "ftp",
                "product": "vsftpd",
                "version": "3.0.3",
                "extrainfo": "Cleartext FTP control channel",
                "cpe": "cpe:/a:vsftpd_project:vsftpd:3.0.3",
                "exposure_level": "High",
            },
            {
                "port_number": 22,
                "protocol": "tcp",
                "state": "open",
                "service_name": "ssh",
                "product": "OpenSSH",
                "version": "8.2p1",
                "extrainfo": "Ubuntu Linux; protocol 2.0",
                "cpe": "cpe:/a:openbsd:openssh:8.2p1",
                "exposure_level": "High",
            },
            {
                "port_number": 80,
                "protocol": "tcp",
                "state": "open",
                "service_name": "http",
                "product": "Apache httpd",
                "version": "2.4.49",
                "extrainfo": "Unix; mod_ssl/2.4.49",
                "cpe": "cpe:/a:apache:http_server:2.4.49",
                "exposure_level": "Elevated",
            },
            {
                "port_number": 445,
                "protocol": "tcp",
                "state": "open",
                "service_name": "microsoft-ds",
                "product": "Samba smbd",
                "version": "4.13.2",
                "extrainfo": "Workgroup: LABNET",
                "cpe": "cpe:/a:samba:samba:4.13.2",
                "exposure_level": "High",
            },
            {
                "port_number": 3306,
                "protocol": "tcp",
                "state": "open",
                "service_name": "mysql",
                "product": "MySQL",
                "version": "8.0.26",
                "extrainfo": "Unauthorized network bind 0.0.0.0",
                "cpe": "cpe:/a:oracle:mysql:8.0.26",
                "exposure_level": "High",
            },
            {
                "port_number": 6379,
                "protocol": "tcp",
                "state": "open",
                "service_name": "redis",
                "product": "Redis key-value store",
                "version": "6.0.9",
                "extrainfo": "Protected-mode disabled",
                "cpe": "cpe:/a:redislabs:redis:6.0.9",
                "exposure_level": "High",
            },
        ]
        return {
            "target": target,
            "os_detected": "Linux 5.4 - 5.15 (Ubuntu 20.04 LTS Lab Profile)",
            "os_accuracy": 96,
            "ports": demo_ports,
        }
