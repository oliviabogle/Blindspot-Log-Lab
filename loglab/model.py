"""Core data structures shared by the generator, scenarios, and grader."""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Union

# Log sources and the ID prefix used for their events
LOG_PREFIX = {
    "windows": "WIN",
    "vpn": "VPN",
    "fileshare": "FS",
    "firewall": "FW",
    "email": "EML",
    "endpoint": "EDR",
}


@dataclass
class Event:
    ts: datetime
    log: str
    data: dict[str, Any]
    eid: str | None = None  # assigned after all events are sorted


@dataclass
class User:
    user_id: str
    username: str
    full_name: str
    department: str
    title: str
    workstation: str
    privileged: bool = False
    mfa_enrolled: bool = True
    status: str = "active"           # employment status: active | terminated
    account_enabled: bool = True     # directory account state
    hire_date: str = ""
    term_date: str = ""
    last_login: str = ""
    account_type: str = "named"      # named | shared | service | admin
    owner: str = ""                  # who is accountable for the account
    notes: str = ""
    baseline: bool = True            # generate normal background activity?
    home_city: str = ""


@dataclass
class Asset:
    asset_id: str
    hostname: str
    ip: str
    os: str
    role: str
    stores_cui: bool
    last_patched: str
    edr_installed: bool = True
    audit_logging: str = "enabled"
    owner: str = "IT"


# Evidence can be a log Event or a static ID (roster row, asset row, config setting...)
Evidence = Union[Event, str]


@dataclass
class Issue:
    key: str
    title: str
    category: str                 # "threat" | "compliance"
    severity: str                 # low | medium | high | critical
    controls: list[str]           # accepted 800-171 ids, primary first
    evidence: list[Evidence]
    explanation: str
    remediation: str
    hint: str

    def evidence_ids(self) -> list[str]:
        return [e.eid if isinstance(e, Event) else e for e in self.evidence]


@dataclass
class Decoy:
    key: str
    evidence: list[Evidence]
    reason: str

    def evidence_ids(self) -> list[str]:
        return [e.eid if isinstance(e, Event) else e for e in self.evidence]


@dataclass
class Context:
    """Everything a scenario needs to plant its activity in the case."""
    rng: random.Random
    start: datetime               # first day of the review window (00:00)
    days: int
    users: list[User]
    assets: list[Asset]
    events: list[Event] = field(default_factory=list)
    config: dict[str, dict] = field(default_factory=dict)
    change_tickets: list[dict] = field(default_factory=list)
    usb_allowlist: list[dict] = field(default_factory=list)
    travel_exceptions: list[dict] = field(default_factory=list)
    approved_scanners: list[str] = field(default_factory=list)
    used_users: set[str] = field(default_factory=set)
    used_assets: set[str] = field(default_factory=set)
    ips: Any = None               # org.IPPool for fictional external addresses
    vpn_ips: dict[str, str] = field(default_factory=dict)  # username -> usual home IP
    state: dict[str, Any] = field(default_factory=dict)    # cross-cutting flags for baseline/filters

    def new_user_id(self) -> str:
        return f"USR-{len(self.users) + 1:04d}"

    # ---- helpers ---------------------------------------------------------
    @property
    def end(self) -> datetime:
        return self.start + timedelta(days=self.days)

    def add(self, ts: datetime, log: str, **data) -> Event:
        ev = Event(ts=ts, log=log, data=data)
        self.events.append(ev)
        return ev

    def pick_user(self, *, dept: str | None = None, privileged: bool | None = False,
                  mfa: bool | None = None) -> User:
        pool = [u for u in self.users
                if u.status == "active" and u.account_type == "named"
                and u.username not in self.used_users
                and (dept is None or u.department == dept)
                and (privileged is None or u.privileged == privileged)
                and (mfa is None or u.mfa_enrolled == mfa)]
        if not pool:  # relax department filter
            pool = [u for u in self.users if u.status == "active" and u.account_type == "named"
                    and u.username not in self.used_users]
        u = self.rng.choice(pool)
        self.used_users.add(u.username)
        return u

    def pick_asset(self, *, role: str | None = None, cui: bool | None = None) -> Asset:
        pool = [a for a in self.assets
                if a.hostname not in self.used_assets
                and (role is None or a.role == role)
                and (cui is None or a.stores_cui == cui)]
        a = self.rng.choice(pool)
        self.used_assets.add(a.hostname)
        return a

    def asset(self, hostname: str) -> Asset:
        return next(a for a in self.assets if a.hostname == hostname)

    def workday(self, earliest: int = 1) -> datetime:
        """Random weekday (midnight) inside the window, at least `earliest` days in."""
        days = [self.start + timedelta(days=d) for d in range(earliest, self.days)
                if (self.start + timedelta(days=d)).weekday() < 5]
        return self.rng.choice(days)

    def at(self, day: datetime, hour: int, minute: int | None = None) -> datetime:
        m = self.rng.randint(0, 59) if minute is None else minute
        return day.replace(hour=hour, minute=m, second=self.rng.randint(0, 59))
