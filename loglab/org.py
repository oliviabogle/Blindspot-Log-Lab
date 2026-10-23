"""Builds the fictional organization: people, systems, and policy facts.

All names, domains, and IP addresses are fictional. External addresses come
from the RFC 5737 documentation ranges and domains use the reserved .example
TLD, so nothing in a generated case points at a real organization.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

from .model import Asset, User

COMPANY = "Ironvale Precision Systems"
DOMAIN = "ironvale.example"
PRIME_DOMAIN = "primedefense.example"          # approved partner for CUI exchange
PRIME_SFTP = "sftp.primedefense.example"
HQ_CITY = "Dayton, OH"

FIRST = ["Avery", "Jordan", "Morgan", "Taylor", "Casey", "Riley", "Quinn", "Reese", "Hayden",
         "Parker", "Rowan", "Emerson", "Logan", "Dakota", "Skyler", "Jamie", "Cameron",
         "Drew", "Sage", "Blake", "Marisol", "Tomas", "Priya", "Kenji", "Lena", "Omar",
         "Grace", "Victor", "Nadia", "Elliot", "Beatriz", "Samuel", "Ines", "Darius",
         "Hana", "Malik", "Colette", "Rafael", "Yusuf", "Mei"]
LAST = ["Okafor", "Lindqvist", "Ramirez", "Chen", "Patel", "Novak", "Haddad", "Brennan",
        "Kowalski", "Nguyen", "Ferreira", "Albright", "Mbeki", "Sorensen", "Castillo",
        "Whitfield", "Yamada", "Delacroix", "Abernathy", "Osei", "Varga", "Holloway",
        "Rasmussen", "Iqbal", "Duarte", "Kincaid", "Moreau", "Tanaka", "Petrov", "Quintero"]

DEPARTMENTS = {
    # dept: (titles, headcount weight, workstation tag)
    "Engineering": (["Mechanical Engineer", "Design Engineer", "Systems Engineer",
                     "Engineering Manager", "CAD Technician"], 9, "ENG"),
    "Manufacturing": (["Machinist", "Production Supervisor", "CNC Programmer"], 5, "MFG"),
    "Program Management": (["Program Manager", "Project Coordinator"], 3, "PM"),
    "Quality": (["Quality Engineer", "Inspector"], 3, "QA"),
    "Contracts": (["Contracts Administrator", "Export Compliance Specialist"], 2, "CON"),
    "Finance": (["Accountant", "Controller"], 2, "FIN"),
    "HR": (["HR Generalist", "HR Manager"], 2, "HR"),
    "IT": (["Systems Administrator", "Network Engineer", "IT Manager"], 3, "IT"),
}

HOME_CITIES = ["Dayton, OH", "Kettering, OH", "Beavercreek, OH", "Springfield, OH",
               "Cincinnati, OH", "Columbus, OH", "Fairborn, OH"]
US_TRAVEL_CITIES = ["Dallas, TX", "San Diego, CA", "Denver, CO", "Arlington, VA",
                    "Phoenix, AZ", "Seattle, WA"]
FOREIGN_HOSTILE = [("Bucharest", "RO"), ("Shenzhen", "CN"), ("Lagos", "NG"),
                   ("Minsk", "BY"), ("Tehran", "IR"), ("Hanoi", "VN"), ("Sao Paulo", "BR")]
FOREIGN_TRAVEL = [("London", "GB"), ("Paris", "FR"), ("Munich", "DE"), ("Rome", "IT")]

PROGRAMS = {
    "AX17": "AX-17 Guidance Housing",
    "TALON": "Talon Actuator Assembly",
    "RG4": "RG-4 Sensor Mount",
}
CUI_SHARES = [r"\\FS01\CUI-Programs", r"\\FS01\CUI-Drawings", r"\\PLM01\Vault"]
NON_CUI_SHARES = [r"\\FS02\Public", r"\\FS02\Facilities", r"\\FS02\Marketing"]

APPROVED_SOFTWARE = ["chrome.exe", "msedge.exe", "outlook.exe", "excel.exe", "winword.exe",
                     "powerpnt.exe", "teams.exe", "acad.exe", "SolidWorks.exe",
                     "mastercam.exe", "AcroRd32.exe", "notepad.exe", "explorer.exe",
                     "mmc.exe", "powershell.exe", "putty.exe", "WinSCP.exe"]
NORMAL_WEB = ["login.microsoftonline.example", "outlook.office.example", "github.example",
              "solidworks.example", "weather.example", "news.example", "mcmaster.example",
              "dla.mil.example", "sam.gov.example", "update.windows.example"]
PERSONAL_CLOUD = ["mega.example", "dropbox.example", "wetransfer.example", "anonfiles.example"]
PERSONAL_EMAIL = ["gmail.example", "yahoo.example", "proton.example", "outlook-personal.example"]


class IPPool:
    """Hands out fictional addresses from the RFC 5737 documentation ranges.

    external() -> a fresh, never-reused address (people, attackers, C2 servers)
    host(name) -> the same address every time for a given internet hostname
    noise()    -> one of a fixed set of internet scanners that keep coming back
    """

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.used: set[str] = set()
        self.nets = ["192.0.2", "198.51.100", "203.0.113"]
        self._hosts: dict[str, str] = {}
        self._noise: list[str] = []

    def external(self) -> str:
        if len(self.used) >= 3 * 253:
            raise RuntimeError("Fictional IP pool exhausted")
        while True:
            ip = f"{self.rng.choice(self.nets)}.{self.rng.randint(2, 254)}"
            if ip not in self.used:
                self.used.add(ip)
                return ip

    def host(self, name: str) -> str:
        if name not in self._hosts:
            self._hosts[name] = self.external()
        return self._hosts[name]

    def noise(self) -> str:
        if not self._noise:
            self._noise = [self.external() for _ in range(60)]
        return self.rng.choice(self._noise)


def _username(first: str, last: str, taken: set[str]) -> str:
    base = (first[0] + last).lower()
    name, n = base, 2
    while name in taken:
        name, n = f"{base}{n}", n + 1
    taken.add(name)
    return name


def build_org(rng: random.Random, start: datetime, size: str = "medium"):
    scale = {"small": 0.7, "medium": 1.0, "large": 1.5}[size]
    users: list[User] = []
    taken: set[str] = set()
    names_used: set[tuple[str, str]] = set()
    n = 1
    ws_counter: dict[str, int] = {}

    for dept, (titles, weight, tag) in DEPARTMENTS.items():
        count = max(1, round(weight * scale + rng.uniform(-0.4, 0.4)))
        for _ in range(count):
            while True:
                first, last = rng.choice(FIRST), rng.choice(LAST)
                if (first, last) not in names_used:
                    names_used.add((first, last))
                    break
            uname = _username(first, last, taken)
            ws_counter[tag] = ws_counter.get(tag, 0) + 1
            hire = start - timedelta(days=rng.randint(200, 3600))
            users.append(User(
                user_id=f"USR-{n:04d}", username=uname, full_name=f"{first} {last}",
                department=dept, title=rng.choice(titles),
                workstation=f"WS-{tag}-{ws_counter[tag]:03d}",
                privileged=False, mfa_enrolled=True,
                hire_date=hire.date().isoformat(),
                last_login=(start - timedelta(days=rng.randint(0, 2))).date().isoformat(),
                owner=uname, home_city=rng.choice(HOME_CITIES),
            ))
            n += 1

    # IT staff get separate privileged admin accounts (good practice for 3.1.6)
    for u in [u for u in users if u.department == "IT"]:
        users.append(User(
            user_id=f"USR-{n:04d}", username=f"adm-{u.username}", full_name=f"{u.full_name} (admin)",
            department="IT", title="Privileged account", workstation=u.workstation,
            privileged=True, mfa_enrolled=True, hire_date=u.hire_date,
            last_login=u.last_login, account_type="admin", owner=u.username,
            home_city=u.home_city, baseline=True,
        ))
        n += 1

    # Service accounts (no interactive baseline)
    for svc, purpose in [("svc-backup", "Backup job runner"), ("svc-scan", "Vulnerability scanner"),
                         ("svc-plm", "PLM application service")]:
        users.append(User(
            user_id=f"USR-{n:04d}", username=svc, full_name=purpose, department="IT",
            title="Service account", workstation="", privileged=svc != "svc-plm",
            mfa_enrolled=False, hire_date=(start - timedelta(days=900)).date().isoformat(),
            last_login=start.date().isoformat(), account_type="service", owner="IT Manager",
            notes="Non-interactive; logon type 5/4 only", baseline=False,
        ))
        n += 1

    # Former employees, correctly disabled (realistic noise)
    for _ in range(rng.randint(2, 4)):
        first, last = rng.choice(FIRST), rng.choice(LAST)
        uname = _username(first, last, taken)
        term = start - timedelta(days=rng.randint(20, 300))
        users.append(User(
            user_id=f"USR-{n:04d}", username=uname, full_name=f"{first} {last}",
            department=rng.choice(list(DEPARTMENTS)), title="(former employee)",
            workstation="", status="terminated", account_enabled=False,
            hire_date=(term - timedelta(days=rng.randint(300, 2000))).date().isoformat(),
            term_date=term.date().isoformat(), last_login=(term - timedelta(days=1)).date().isoformat(),
            owner=uname, notes="Account disabled at offboarding", baseline=False,
        ))
        n += 1

    # ---- assets ----------------------------------------------------------
    def patched(max_days: int = 18) -> str:
        return (start - timedelta(days=rng.randint(3, max_days))).date().isoformat()

    servers = [
        ("DC01", "10.10.0.10", "Windows Server 2022", "Domain Controller", False),
        ("DC02", "10.10.0.11", "Windows Server 2022", "Domain Controller", False),
        ("FS01", "10.10.0.20", "Windows Server 2022", "CUI File Server", True),
        ("FS02", "10.10.0.21", "Windows Server 2019", "General File Server", False),
        ("PLM01", "10.10.0.30", "Windows Server 2022", "PLM / CAD Vault", True),
        ("BACKUP01", "10.10.0.40", "Windows Server 2022", "Backup Server", True),
        ("SIEM01", "10.10.0.50", "Ubuntu 22.04 LTS", "Log Collector", False),
        ("VULNSCAN01", "10.10.0.60", "Ubuntu 22.04 LTS", "Vulnerability Scanner", False),
        ("VPN-GW", "10.10.1.1", "Vendor Appliance 9.4", "Remote Access Gateway", False),
        ("MAIL-GW", "10.10.1.5", "Vendor Appliance 5.2", "Email Security Gateway", False),
        ("CNC-HMI-01", "10.30.0.11", "Windows 10 IoT LTSC 2019", "Shop-floor HMI", True),
        ("CNC-HMI-02", "10.30.0.12", "Windows 10 IoT LTSC 2019", "Shop-floor HMI", True),
        ("PRINT01", "10.10.0.70", "Windows Server 2019", "Print Server", False),
    ]
    assets: list[Asset] = []
    a = 1
    for host, ip, os_, role, cui in servers:
        assets.append(Asset(f"AST-{a:04d}", host, ip, os_, role, cui, patched(),
                            edr_installed=not os_.startswith(("Vendor", "Ubuntu"))))
        a += 1
    subnet = {"ENG": 21, "MFG": 22, "PM": 23, "QA": 24, "CON": 25, "FIN": 26, "HR": 27, "IT": 28}
    for u in users:
        if u.account_type == "named" and u.workstation and u.status == "active":
            tag = u.workstation.split("-")[1]
            num = int(u.workstation.split("-")[2])
            assets.append(Asset(f"AST-{a:04d}", u.workstation, f"10.{subnet[tag]}.0.{100 + num}",
                                "Windows 11 Enterprise 23H2", "Workstation",
                                tag in ("ENG", "MFG", "PM", "QA", "CON"), patched(22),
                                owner=u.username))
            a += 1
    return users, assets


def ip_of(assets: list[Asset], hostname: str) -> str:
    for a in assets:
        if a.hostname == hostname:
            return a.ip
    return "0.0.0.0"


def cui_filename(rng: random.Random) -> tuple[str, str]:
    """Return (share-relative path, file name) for a CUI document."""
    code = rng.choice(list(PROGRAMS))
    kind = rng.choice([
        f"{code}_drawing_{rng.randint(100, 999)}_rev{rng.choice('ABCDE')}.pdf",
        f"{code}_assembly_{rng.randint(10, 99)}.step",
        f"{code}_test_report_{rng.randint(1, 40):02d}.docx",
        f"{code}_tech_data_package.zip",
        f"{code}_tolerance_stackup.xlsx",
        f"{code}_SOW_CUI.pdf",
    ])
    share = rng.choice(CUI_SHARES)
    return f"{share}\\{code}\\{kind}", kind
