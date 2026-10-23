"""
Scenario library: each function plants one threat or compliance failure in the
case and returns an Issue describing the correct answer.

To add your own scenario, write a function that takes a Context, plants events
with ctx.add(...), and returns an Issue. Decorate it with @scenario(...).
Use the @decoy(...) decorator for benign activity that *looks* suspicious.
"""

from __future__ import annotations

import base64
from datetime import timedelta
from typing import Callable

from . import org
from .model import Context, Decoy, Issue, User

SCENARIOS: dict[str, tuple[str, Callable[[Context], Issue]]] = {}
DECOYS: dict[str, Callable[[Context], Decoy]] = {}


def scenario(key: str, category: str):
    def wrap(fn):
        SCENARIOS[key] = (category, fn)
        return fn
    return wrap


def decoy(key: str):
    def wrap(fn):
        DECOYS[key] = fn
        return fn
    return wrap


def _named_active(ctx: Context) -> list[User]:
    return [u for u in ctx.users if u.account_type == "named" and u.status == "active"]


def _admins(ctx: Context) -> list[User]:
    fresh = [u for u in ctx.users if u.account_type == "admin" and u.username not in ctx.used_users]
    return fresh or [u for u in ctx.users if u.account_type == "admin"]


def _assigned_ip(ctx: Context) -> str:
    return f"10.99.0.{ctx.rng.randint(10, 250)}"


# =========================================================================
# THREATS
# =========================================================================

@scenario("password_spray", "threat")
def password_spray(ctx: Context) -> Issue:
    rng = ctx.rng
    day = ctx.workday()
    attacker = ctx.ips.external()
    city, cc = rng.choice(org.FOREIGN_HOSTILE)
    targets = rng.sample(_named_active(ctx), k=min(14, len(_named_active(ctx))))
    t = ctx.at(day, rng.choice([1, 2, 3, 4]))
    ev = []
    for u in targets[:-1]:
        t += timedelta(seconds=rng.randint(25, 95))
        ev.append(ctx.add(t, "vpn", user=u.username, action="auth_failure", src_ip=attacker,
                          geo_city=city, geo_country=cc, mfa="not_reached",
                          reason="invalid_password", client="python-requests/2.31"))
    victim = targets[-1]
    t += timedelta(seconds=rng.randint(25, 95))
    ev.append(ctx.add(t, "vpn", user=victim.username, action="mfa_denied", src_ip=attacker,
                      geo_city=city, geo_country=cc, mfa="push_denied",
                      reason="password_valid_mfa_rejected", client="python-requests/2.31"))
    return Issue(
        key="password_spray", title=f"Password spray against VPN from {city}, {cc}",
        category="threat", severity="high",
        controls=["3.14.6", "3.14.7", "3.1.12", "3.1.8"], evidence=ev,
        explanation=(f"One external IP ({attacker}, geolocated to {city}, {cc}) tried a single password "
                     f"against {len(targets)} different accounts within minutes, using a scripting client. "
                     "Low-and-slow spraying stays under the per-account lockout threshold. The final attempt "
                     f"for '{victim.username}' had a VALID password and was only stopped by MFA - that "
                     "account's password is compromised."),
        remediation=(f"Block {attacker} at the VPN edge, force a password reset for {victim.username}, "
                     "geo-restrict VPN to approved countries, alert on many-users-from-one-IP failures, "
                     "and open an incident ticket (3.6.1/3.6.2)."),
        hint="One source is failing against many different usernames. Look at the VPN log by src_ip.",
    )


@scenario("mfa_fatigue", "threat")
def mfa_fatigue(ctx: Context) -> Issue:
    rng = ctx.rng
    u = ctx.pick_user(dept="Engineering")
    day = ctx.workday()
    attacker = ctx.ips.external()
    city, cc = rng.choice(org.FOREIGN_HOSTILE)
    t = ctx.at(day, rng.choice([22, 23]))
    ev = []
    for _ in range(rng.randint(5, 9)):
        ev.append(ctx.add(t, "vpn", user=u.username, action="mfa_denied", src_ip=attacker, geo_city=city,
                          geo_country=cc, mfa="push_denied", reason="password_valid_mfa_rejected",
                          client="AnyConnect-5.1"))
        t += timedelta(seconds=rng.randint(30, 120))
    assigned = _assigned_ip(ctx)
    ev.append(ctx.add(t, "vpn", user=u.username, action="connect", src_ip=attacker, geo_city=city,
                      geo_country=cc, mfa="push_approved", assigned_ip=assigned, client="AnyConnect-5.1"))
    for _ in range(rng.randint(6, 12)):
        t += timedelta(seconds=rng.randint(20, 200))
        path, _ = org.cui_filename(rng)
        ev.append(ctx.add(t, "fileshare", user=u.username, src_ip=assigned, server=path.split("\\")[2],
                          path=path, action="read", bytes=rng.randint(200, 9000) * 1000,
                          classification="CUI"))
    return Issue(
        key="mfa_fatigue", title=f"MFA fatigue attack - {u.username} account taken over",
        category="threat", severity="critical",
        controls=["3.1.12", "3.14.7", "3.14.6", "3.5.3"], evidence=ev,
        explanation=(f"'{u.username}' normally connects from {u.home_city}. Late at night, an IP in "
                     f"{city}, {cc} supplied the correct password and spammed MFA pushes until one was "
                     "approved (push fatigue). The session then immediately read CUI from the file shares."),
        remediation=("Disable the account and revoke sessions, reset credentials, move to number-matching "
                     "or phishing-resistant MFA, geo-block VPN, scope the CUI accessed, and evaluate DFARS "
                     "252.204-7012 72-hour incident reporting."),
        hint="Count how many times one user rejected an MFA prompt before finally accepting one.",
    )


@scenario("impossible_travel", "threat")
def impossible_travel(ctx: Context) -> Issue:
    rng = ctx.rng
    u = ctx.pick_user()
    day = ctx.workday()
    home_ip = ctx.ips.external()
    ctx.vpn_ips[u.username] = home_ip
    city, cc = rng.choice(org.FOREIGN_HOSTILE)
    t1 = ctx.at(day, rng.randint(8, 13))
    a1 = _assigned_ip(ctx)
    e1 = ctx.add(t1, "vpn", user=u.username, action="connect", src_ip=home_ip, geo_city=u.home_city,
                 geo_country="US", mfa="push_approved", assigned_ip=a1, client="AnyConnect-5.1")
    t2 = t1 + timedelta(minutes=rng.randint(25, 70))
    bad_ip = ctx.ips.external()
    a2 = _assigned_ip(ctx)
    e2 = ctx.add(t2, "vpn", user=u.username, action="connect", src_ip=bad_ip, geo_city=city,
                 geo_country=cc, mfa="session_token_reuse", assigned_ip=a2, client="AnyConnect-4.10")
    ev = [e1, e2]
    t = t2
    for _ in range(rng.randint(3, 7)):
        t += timedelta(minutes=rng.randint(1, 6))
        path, _ = org.cui_filename(rng)
        ev.append(ctx.add(t, "fileshare", user=u.username, src_ip=a2, server=path.split("\\")[2],
                          path=path, action="read", bytes=rng.randint(500, 20000) * 1000,
                          classification="CUI"))
    ctx.add(t1 + timedelta(hours=rng.randint(6, 8)), "vpn", user=u.username, action="disconnect",
            src_ip=home_ip, geo_city=u.home_city, geo_country="US", assigned_ip=a1,
            bytes_in=rng.randint(100, 500) * 1_000_000, bytes_out=rng.randint(5, 40) * 1_000_000)
    return Issue(
        key="impossible_travel", title=f"Impossible travel / session hijack for {u.username}",
        category="threat", severity="critical",
        controls=["3.1.12", "3.14.7", "3.14.6"], evidence=ev,
        explanation=(f"'{u.username}' had an active session from {u.home_city} and then, "
                     f"{int((t2 - t1).total_seconds() // 60)} minutes later, a second concurrent session from "
                     f"{city}, {cc} using a reused session token and an older client. Physically impossible; "
                     "indicates a stolen session cookie/token. The foreign session pulled CUI."),
        remediation=("Terminate all sessions, reset credentials, investigate the endpoint for infostealer "
                     "malware, enforce device posture checks and single-session limits on the VPN."),
        hint="Look for one user with two simultaneous VPN sessions in two different countries.",
    )


@scenario("terminated_user_active", "threat")
def terminated_user_active(ctx: Context) -> Issue:
    rng = ctx.rng
    u = ctx.pick_user()
    term = ctx.start - timedelta(days=rng.randint(2, 12))
    u.status = "terminated"
    u.account_enabled = True          # <- the offboarding miss
    u.term_date = term.date().isoformat()
    u.notes = f"Involuntary termination; HR case HR-{rng.randint(1000, 9999)}"
    u.baseline = False
    day = ctx.workday()
    t = ctx.at(day, rng.choice([19, 20, 21, 22]))
    home_ip = ctx.ips.external()
    assigned = _assigned_ip(ctx)
    ev = [ctx.add(t, "vpn", user=u.username, action="connect", src_ip=home_ip, geo_city=u.home_city,
                  geo_country="US", mfa="push_approved", assigned_ip=assigned, client="AnyConnect-5.1")]
    for _ in range(rng.randint(5, 14)):
        t += timedelta(seconds=rng.randint(30, 240))
        path, _ = org.cui_filename(rng)
        ev.append(ctx.add(t, "fileshare", user=u.username, src_ip=assigned, server=path.split("\\")[2],
                          path=path, action="read", bytes=rng.randint(100, 9000) * 1000,
                          classification="CUI"))
    u.last_login = day.date().isoformat()
    ev.append(u.user_id)
    return Issue(
        key="terminated_user_active", title=f"Terminated employee {u.username} still has access",
        category="threat", severity="critical",
        controls=["3.9.2", "3.1.1"], evidence=ev,
        explanation=(f"The roster shows '{u.username}' was terminated on {u.term_date}, but the account "
                     "is still enabled and was used after that date to VPN in and read CUI. Offboarding "
                     "failed to revoke access."),
        remediation=("Disable the account and revoke tokens immediately, review everything accessed, "
                     "and fix the HR-to-IT offboarding workflow so access is removed on the termination date."),
        hint="Cross-reference the user roster's employment status against who is actually logging in.",
    )


@scenario("insider_exfiltration", "threat")
def insider_exfiltration(ctx: Context) -> Issue:
    rng = ctx.rng
    u = ctx.pick_user(dept="Engineering")
    day = ctx.workday(earliest=2)
    resign = day - timedelta(days=rng.randint(3, 8))
    u.notes = (f"Resignation submitted {resign.date().isoformat()}; last day "
               f"{(resign + timedelta(days=14)).date().isoformat()}")
    src = org.ip_of(ctx.assets, u.workstation)
    t = ctx.at(day, rng.choice([21, 22, 23]))
    ev = [ctx.add(t, "windows", EventID=4624, Computer=u.workstation, TargetUserName=u.username,
                  LogonType=2, IpAddress=src, AuthPackage="Kerberos")]
    total = 0
    for _ in range(rng.randint(35, 70)):
        t += timedelta(seconds=rng.randint(3, 25))
        path, _ = org.cui_filename(rng)
        size = rng.randint(1000, 60000) * 1000
        total += size
        ev.append(ctx.add(t, "fileshare", user=u.username, src_ip=src, server=path.split("\\")[2],
                          path=path, action="read", bytes=size, classification="CUI"))
    site = rng.choice(org.PERSONAL_CLOUD)
    t += timedelta(minutes=rng.randint(3, 10))
    ev.append(ctx.add(t, "firewall", action="allow", src=src, dst=ctx.ips.host(site), dport=443,
                      proto="tcp", app="https", host=site, bytes_out=int(total * 0.9),
                      bytes_in=rng.randint(50, 400) * 1000))
    return Issue(
        key="insider_exfiltration", title=f"Departing employee {u.username} exfiltrated CUI to {site}",
        category="threat", severity="critical",
        controls=["3.1.3", "3.14.7", "3.13.1", "3.14.6"], evidence=ev,
        explanation=(f"'{u.username}' has a pending resignation (see roster notes). After hours they bulk-read "
                     f"{len(ev) - 2} CUI files in minutes, then uploaded ~{total * 0.9 / 1e9:.1f} GB to the "
                     f"personal cloud service {site}. The firewall allowed it."),
        remediation=("Preserve evidence, disable the account, involve legal/HR and the FSO, block personal "
                     "cloud storage categories at the boundary, add DLP, and heighten monitoring for "
                     "departing employees."),
        hint="Check the roster notes for anyone leaving the company, then look at their after-hours activity.",
    )


@scenario("usb_cui_copy", "threat")
def usb_cui_copy(ctx: Context) -> Issue:
    rng = ctx.rng
    u = ctx.pick_user(dept=rng.choice(["Engineering", "Manufacturing", "Quality"]))
    day = ctx.workday()
    t = ctx.at(day, rng.randint(10, 16))
    serial = "".join(rng.choice("0123456789ABCDEF") for _ in range(16))
    vendor = rng.choice(["SanDisk Ultra Fit", "Kingston DataTraveler", "Generic Mass Storage"])
    ev = [ctx.add(t, "endpoint", host=u.workstation, user=u.username, type="usb", action="mount",
                  device_id=f"USBSTOR\\Disk&Ven_{vendor.split()[0]}\\{serial}", vendor=vendor,
                  serial=serial, encrypted=False, drive_letter="E:")]
    for _ in range(rng.randint(3, 9)):
        t += timedelta(seconds=rng.randint(10, 90))
        path, name = org.cui_filename(rng)
        ev.append(ctx.add(t, "endpoint", host=u.workstation, user=u.username, type="file_copy",
                          src=path, dst=f"E:\\backup\\{name}", bytes=rng.randint(300, 40000) * 1000))
    return Issue(
        key="usb_cui_copy", title=f"CUI copied to unapproved USB drive by {u.username}",
        category="threat", severity="high",
        controls=["3.8.7", "3.8.8", "3.1.3", "3.1.21"], evidence=ev,
        explanation=(f"An unencrypted '{vendor}' drive (serial {serial}) that is NOT on the USB allowlist was "
                     f"mounted on {u.workstation} and CUI files were copied to it."),
        remediation=("Recover the device, interview the user, enforce device-control policy that blocks "
                     "non-allowlisted storage, and require FIPS-validated encrypted drives for CUI."),
        hint="Compare every USB serial number in the endpoint log against the USB allowlist.",
    )


@scenario("phishing_malware", "threat")
def phishing_malware(ctx: Context) -> Issue:
    rng = ctx.rng
    u = ctx.pick_user(dept=rng.choice(["Program Management", "Contracts", "Finance"]))
    day = ctx.workday()
    t = ctx.at(day, rng.randint(9, 15))
    lookalike = rng.choice(["primedefense-portal.example", "prlmedefense.example",
                            "ironva1e.example", "primedefence.example"])
    attach = rng.choice(["Updated_SOW_Rev4.docm", "Invoice_Q3_overdue.xlsm", "CDRL_revision.docm"])
    ev = [ctx.add(t, "email", direction="inbound", sender=f"contracts@{lookalike}",
                  recipient=f"{u.username}@{org.DOMAIN}", subject="ACTION REQUIRED: updated contract docs",
                  attachment=attach, tls=True, verdict="delivered", size_kb=rng.randint(80, 400),
                  spf="softfail", dkim="none")]
    t += timedelta(minutes=rng.randint(4, 40))
    office = "winword.exe" if attach.endswith(".docm") else "excel.exe"
    blob = base64.b64encode(f"IEX (New-Object Net.WebClient).DownloadString('{rng.randint(1000,9999)}')"
                            .encode()).decode()
    ev.append(ctx.add(t, "endpoint", host=u.workstation, user=u.username, type="process",
                      image="powershell.exe", parent=office,
                      cmdline=f"powershell.exe -nop -w hidden -enc {blob}", signer="Valid"))
    c2 = ctx.ips.external()
    src = org.ip_of(ctx.assets, u.workstation)
    for _ in range(rng.randint(5, 9)):
        t += timedelta(minutes=5, seconds=rng.randint(-8, 8))
        ev.append(ctx.add(t, "firewall", action="allow", src=src, dst=c2, dport=8443, proto="tcp",
                          app="ssl", host="-", bytes_out=rng.randint(300, 900), bytes_in=rng.randint(200, 600)))
    return Issue(
        key="phishing_malware", title=f"Macro phishing led to malware beaconing on {u.workstation}",
        category="threat", severity="critical",
        controls=["3.14.2", "3.14.6", "3.14.3", "3.2.1"], evidence=ev,
        explanation=(f"A macro-enabled attachment from look-alike domain '{lookalike}' (SPF softfail, no DKIM) "
                     f"was delivered to {u.username}. Shortly after, {office} spawned an encoded, hidden "
                     f"PowerShell process, and the workstation began beaconing to {c2}:8443 every ~5 minutes."),
        remediation=("Isolate the host, collect forensics, block the domain and C2 IP, purge the email from all "
                     "mailboxes, block Office macros from the internet, and run targeted phishing training."),
        hint="An Office application should never be the parent process of PowerShell.",
    )


@scenario("privilege_escalation", "threat")
def privilege_escalation(ctx: Context) -> Issue:
    rng = ctx.rng
    admins = _admins(ctx)
    actor = rng.choice(admins)
    ctx.used_users.add(actor.username)
    member = ctx.pick_user()
    day = ctx.workday()
    t = ctx.at(day, rng.choice([20, 21, 22, 23]))
    actor_ip = org.ip_of(ctx.assets, actor.workstation)
    ev = [
        ctx.add(t, "windows", EventID=4624, Computer="DC01", TargetUserName=actor.username, LogonType=10,
                IpAddress=actor_ip, AuthPackage="Kerberos", MFA="duo_approved"),
        ctx.add(t + timedelta(minutes=rng.randint(2, 6)), "windows", EventID=4728, Computer="DC01",
                SubjectUserName=actor.username, MemberName=member.username, GroupName="Domain Admins",
                Description="A member was added to a security-enabled global group"),
    ]
    t2 = t + timedelta(minutes=rng.randint(15, 40))
    ev.append(ctx.add(t2, "windows", EventID=4624, Computer="DC01", TargetUserName=member.username,
                      LogonType=10, IpAddress=org.ip_of(ctx.assets, member.workstation),
                      AuthPackage="NTLM"))
    return Issue(
        key="privilege_escalation", title=f"{member.username} added to Domain Admins without a change ticket",
        category="threat", severity="critical",
        controls=["3.1.5", "3.4.3", "3.1.7", "3.14.7"], evidence=ev,
        explanation=(f"At night, '{actor.username}' added standard user '{member.username}' to Domain Admins. "
                     "No change ticket authorizes it, and the standard account then logged on to the domain "
                     "controller interactively. Either the admin account is compromised or this is insider "
                     "abuse; standard users should never hold Domain Admin."),
        remediation=("Remove the membership, investigate both accounts, require approved change tickets for "
                     "privileged group changes, and alert on 4728/4732/4756 for sensitive groups."),
        hint="Windows Event 4728 means someone was added to a security group. Was it approved?",
    )


@scenario("audit_log_cleared", "threat")
def audit_log_cleared(ctx: Context) -> Issue:
    rng = ctx.rng
    host = rng.choice(["FS01", "PLM01"])
    day = ctx.workday()
    t = ctx.at(day, rng.choice([1, 2, 3]))
    src_ip = org.ip_of(ctx.assets, rng.choice([u for u in _named_active(ctx)]).workstation)
    ev = [
        ctx.add(t, "windows", EventID=4624, Computer=host, TargetUserName="svc-plm", LogonType=10,
                IpAddress=src_ip, AuthPackage="NTLM"),
        ctx.add(t + timedelta(minutes=rng.randint(3, 15)), "windows", EventID=1102, Computer=host,
                SubjectUserName="svc-plm", Description="The audit log was cleared"),
    ]
    return Issue(
        key="audit_log_cleared", title=f"Security log cleared on {host} by a service account",
        category="threat", severity="critical",
        controls=["3.3.8", "3.3.9", "3.14.7"], evidence=ev,
        explanation=(f"The non-interactive service account 'svc-plm' logged on interactively over RDP "
                     f"(LogonType 10) to {host} in the middle of the night from a workstation IP, then cleared "
                     "the Security event log (Event 1102). Clearing logs is classic anti-forensics."),
        remediation=("Treat as an active intrusion: rotate the service account credential, deny it "
                     "interactive logon via GPO, forward logs to the SIEM in real time so local clearing "
                     "can't erase evidence, and restrict log management to a small admin group."),
        hint="Service accounts should never log on interactively. Also: Event ID 1102.",
    )


@scenario("av_tampering", "threat")
def av_tampering(ctx: Context) -> Issue:
    rng = ctx.rng
    u = ctx.pick_user()
    day = ctx.workday()
    t = ctx.at(day, rng.randint(9, 15))
    ev = [
        ctx.add(t, "endpoint", host=u.workstation, user=u.username, type="process", image="powershell.exe",
                parent="explorer.exe",
                cmdline="powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true", signer="Valid"),
        ctx.add(t + timedelta(seconds=rng.randint(5, 40)), "endpoint", host=u.workstation, user=u.username,
                type="av_status", realtime_protection="off", signature_age_days=0, tamper_protection="off"),
    ]
    ctx.state.setdefault("av_off", {})[u.workstation] = t
    return Issue(
        key="av_tampering", title=f"Antivirus real-time protection disabled on {u.workstation}",
        category="threat", severity="high",
        controls=["3.14.2", "3.4.2", "3.1.7"], evidence=ev,
        explanation=(f"'{u.username}' ran PowerShell to disable Defender real-time monitoring, and tamper "
                     "protection turned off. A standard user being able to do this means they hold local admin "
                     "rights, and the endpoint has no malware protection afterward."),
        remediation=("Re-enable protection, investigate why it was disabled, remove local admin rights, and "
                     "enforce tamper protection centrally so users cannot change it."),
        hint="Look at endpoint av_status events - all of them should say realtime_protection=on.",
    )


@scenario("internal_recon", "threat")
def internal_recon(ctx: Context) -> Issue:
    rng = ctx.rng
    u = ctx.pick_user()
    day = ctx.workday()
    t = ctx.at(day, rng.randint(11, 15))
    src = org.ip_of(ctx.assets, u.workstation)
    tool = rng.choice(["nmap.exe", "advanced_ip_scanner.exe", "SoftPerfectNetScan.exe"])
    ev = [ctx.add(t, "endpoint", host=u.workstation, user=u.username, type="process", image=tool,
                  parent="explorer.exe", cmdline=f"{tool} 10.10.0.0/24", signer="Valid")]
    servers = [a for a in ctx.assets if a.ip.startswith("10.10.0.")]
    for a in servers:
        for port in rng.sample([21, 22, 23, 80, 135, 139, 445, 1433, 3389, 5985], k=rng.randint(4, 7)):
            t += timedelta(milliseconds=rng.randint(50, 900))
            ev.append(ctx.add(t, "firewall", action=rng.choice(["deny", "deny", "allow"]), src=src,
                              dst=a.ip, dport=port, proto="tcp", app="-", host="-", bytes_out=60, bytes_in=0))
    return Issue(
        key="internal_recon", title=f"Internal network scan from user workstation {u.workstation}",
        category="threat", severity="high",
        controls=["3.14.6", "3.14.7", "3.13.1", "3.4.9"], evidence=ev,
        explanation=(f"{u.workstation} (user {u.username}) ran '{tool}' and hit {len(servers)} servers on many "
                     "ports within seconds. Unlike VULNSCAN01, this host is not an approved scanner - this is "
                     "reconnaissance, either by the user or by malware using their machine."),
        remediation=("Isolate and investigate the workstation, block unapproved tools with application "
                     "control, and segment user VLANs from server VLANs."),
        hint="Only one host is authorized to scan the network. Is anyone else doing it?",
    )


# =========================================================================
# COMPLIANCE FAILURES
# =========================================================================

@scenario("shared_account", "compliance")
def shared_account(ctx: Context) -> Issue:
    rng = ctx.rng
    name = rng.choice(["eng-shared", "cadstation", "shopfloor", "qa-lab"])
    acct = User(user_id=ctx.new_user_id(), username=name, full_name="Shared workstation login",
              department="Engineering", title="Shared account", workstation="", privileged=False,
              mfa_enrolled=False, hire_date=(ctx.start - timedelta(days=400)).date().isoformat(),
              last_login=(ctx.start + timedelta(days=ctx.days - 1)).date().isoformat(),
              account_type="shared", owner="", notes="Password on sticky note at CAD station",
              baseline=False)
    ctx.users.append(acct)
    hosts = rng.sample([u.workstation for u in _named_active(ctx)
                        if u.department in ("Engineering", "Manufacturing")], k=4)
    ev = [acct.user_id]
    for _ in range(rng.randint(2, 4)):
        day = ctx.workday(earliest=0)
        for h in rng.sample(hosts, k=rng.randint(2, 4)):
            ev.append(ctx.add(ctx.at(day, rng.randint(7, 16)), "windows", EventID=4624, Computer=h,
                              TargetUserName=name, LogonType=2, IpAddress=org.ip_of(ctx.assets, h),
                              AuthPackage="NTLM"))
    for _ in range(rng.randint(2, 5)):
        path, _ = org.cui_filename(rng)
        h = rng.choice(hosts)
        ev.append(ctx.add(ctx.at(ctx.workday(earliest=0), rng.randint(8, 16)), "fileshare", user=name,
                          src_ip=org.ip_of(ctx.assets, h), server=path.split("\\")[2], path=path,
                          action="write", bytes=rng.randint(100, 5000) * 1000, classification="CUI"))
    return Issue(
        key="shared_account", title=f"Shared generic account '{name}' accessing CUI",
        category="compliance", severity="high",
        controls=["3.5.1", "3.5.2", "3.3.2"], evidence=ev,
        explanation=(f"'{name}' has no named owner, no MFA, and is logged into from multiple workstations - "
                     "often at the same time. Actions on CUI cannot be traced to an individual person."),
        remediation=("Disable the shared account, issue named accounts to each user, and if a kiosk is needed, "
                     "use individual authentication with fast user switching."),
        hint="Every account should map to exactly one accountable person. Check the roster's owner column.",
    )


@scenario("no_mfa_remote", "compliance")
def no_mfa_remote(ctx: Context) -> Issue:
    rng = ctx.rng
    u = ctx.pick_user(dept=rng.choice(["Program Management", "Engineering", "Finance"]))
    u.mfa_enrolled = False
    u.notes = "Member of VPN-MFA-Exempt group (temp exception, expired)"
    ctx.config["vpn_mfa"]["value"] = "true (except VPN-MFA-Exempt)"
    ev = [u.user_id, "cfg:vpn_mfa"]
    ip = ctx.ips.external()
    ctx.vpn_ips[u.username] = ip
    for _ in range(rng.randint(2, 3)):
        day = ctx.workday(earliest=0)
        t = ctx.at(day, rng.randint(7, 9))
        a = _assigned_ip(ctx)
        ev.append(ctx.add(t, "vpn", user=u.username, action="connect", src_ip=ip, geo_city=u.home_city,
                          geo_country="US", mfa="none", assigned_ip=a, client="AnyConnect-5.1"))
        ctx.add(t + timedelta(hours=rng.randint(6, 9)), "vpn", user=u.username, action="disconnect", src_ip=ip,
                geo_city=u.home_city, geo_country="US", assigned_ip=a,
                bytes_in=rng.randint(50, 600) * 1_000_000, bytes_out=rng.randint(5, 60) * 1_000_000)
    ctx.state.setdefault("collect_vpn_no_mfa", set()).add(u.username)
    return Issue(
        key="no_mfa_remote", title=f"Remote VPN access without MFA for {u.username}",
        category="compliance", severity="high",
        controls=["3.5.3", "3.1.12"], evidence=ev,
        explanation=(f"'{u.username}' is in an expired MFA exemption group and connects to the VPN with "
                     "mfa=none. 800-171 requires MFA for all network access to non-privileged accounts."),
        remediation="Enroll the user in MFA, remove the exemption group, and alert on any mfa=none connection.",
        hint="Every VPN connect should show an MFA result. Find the ones that don't.",
    )


@scenario("cleartext_protocol", "compliance")
def cleartext_protocol(ctx: Context) -> Issue:
    rng = ctx.rng
    ev = []
    if rng.random() < 0.5:
        u = ctx.pick_user(dept="Manufacturing")
        src = org.ip_of(ctx.assets, u.workstation)
        host = "ftp.supplier-files.example"
        dst = ctx.ips.host(host)
        day = ctx.workday(earliest=0)
        for _ in range(rng.randint(2, 4)):
            ev.append(ctx.add(ctx.at(day, rng.randint(8, 16)), "firewall", action="allow", src=src, dst=dst,
                              dport=21, proto="tcp", app="ftp", host=host,
                              bytes_out=rng.randint(2000, 90000) * 1000, bytes_in=rng.randint(1, 20) * 1000,
                              note="USER/PASS sent in cleartext"))
        title = f"CUI sent to supplier over unencrypted FTP from {u.workstation}"
        expl = (f"{u.workstation} uploaded large files to {host} over FTP (port 21). FTP sends credentials "
                "and file contents in cleartext - CUI in transit is unprotected.")
        controls = ["3.13.8", "3.5.10", "3.1.3"]
        rem = "Replace FTP with SFTP/FTPS using FIPS-validated crypto and block outbound port 21."
    else:
        admin = rng.choice(_admins(ctx))
        src = org.ip_of(ctx.assets, admin.workstation)
        day = ctx.workday(earliest=0)
        for sw in rng.sample(["10.10.2.1", "10.10.2.2", "10.10.2.3"], k=2):
            ev.append(ctx.add(ctx.at(day, rng.randint(9, 16)), "firewall", action="allow", src=src, dst=sw,
                              dport=23, proto="tcp", app="telnet", host="core-switch",
                              bytes_out=rng.randint(2, 30) * 1000, bytes_in=rng.randint(5, 80) * 1000))
        title = "Network switches managed over Telnet"
        expl = ("An IT workstation is managing core switches over Telnet (port 23). Admin passwords cross "
                "the network in cleartext.")
        controls = ["3.13.8", "3.5.10"]
        rem = "Disable Telnet on network devices, use SSHv2, and restrict management to a jump host."
    return Issue(key="cleartext_protocol", title=title, category="compliance", severity="high",
                 controls=controls, evidence=ev, explanation=expl, remediation=rem,
                 hint="Some protocols send everything - passwords included - in plain text. Check dport.")


@scenario("weak_password_policy", "compliance")
def weak_password_policy(ctx: Context) -> Issue:
    ctx.config["min_password_length"]["value"] = ctx.rng.choice(["6", "7", "8"])
    ctx.config["password_complexity"]["value"] = "Disabled"
    return Issue(
        key="weak_password_policy", title="Domain password policy below organizational standard",
        category="compliance", severity="medium", controls=["3.5.7"],
        evidence=["cfg:min_password_length", "cfg:password_complexity"],
        explanation=("The domain GPO allows short passwords and complexity is disabled, contradicting the "
                     "SSP requirement of 14+ characters with complexity."),
        remediation="Update the Default Domain Policy, then force a password change at next logon.",
        hint="Compare the config snapshot against the policy table in the briefing.",
    )


@scenario("lockout_disabled", "compliance")
def lockout_disabled(ctx: Context) -> Issue:
    ctx.config["lockout_threshold"]["value"] = "0 (never lock out)"
    return Issue(
        key="lockout_disabled", title="Account lockout is disabled",
        category="compliance", severity="high", controls=["3.1.8"], evidence=["cfg:lockout_threshold"],
        explanation="Lockout threshold is 0, so attackers get unlimited password guesses.",
        remediation="Set lockout threshold to 5 invalid attempts with a 30-minute lockout duration.",
        hint="What happens after the 500th wrong password? Check the config snapshot.",
    )


@scenario("session_lock_missing", "compliance")
def session_lock_missing(ctx: Context) -> Issue:
    if ctx.rng.random() < 0.5:
        ctx.config["inactivity_limit"]["value"] = ctx.rng.choice(["0 (not configured)", "7200 seconds"])
        ev, controls = ["cfg:inactivity_limit"], ["3.1.10", "3.1.11"]
        expl = "Workstations don't lock after 15 minutes of inactivity as the SSP requires."
    else:
        ctx.config["vpn_idle_timeout"]["value"] = "Disabled"
        ev, controls = ["cfg:vpn_idle_timeout"], ["3.13.9", "3.1.11"]
        expl = "Idle VPN sessions are never terminated, leaving remote connections open indefinitely."
    return Issue(key="session_lock_missing", title="Inactivity session controls not enforced",
                 category="compliance", severity="medium", controls=controls, evidence=ev,
                 explanation=expl, remediation="Configure the idle timeout per the SSP and verify via GPO/RSoP.",
                 hint="Walk away from your desk. Does anything lock? Check the config snapshot.")


@scenario("banner_missing", "compliance")
def banner_missing(ctx: Context) -> Issue:
    ctx.config["logon_banner"]["value"] = "(not configured)"
    return Issue(key="banner_missing", title="System use / CUI notification banner missing",
                 category="compliance", severity="low", controls=["3.1.9"], evidence=["cfg:logon_banner"],
                 explanation="No logon banner is displayed, so users aren't notified of monitoring and CUI handling.",
                 remediation="Configure the legal notice caption/text via GPO with approved banner language.",
                 hint="What do users see before they log on?")


@scenario("audit_gap", "compliance")
def audit_gap(ctx: Context) -> Issue:
    if ctx.rng.random() < 0.5:
        a = ctx.pick_asset(role="Shop-floor HMI")
        a.audit_logging = "disabled"
        ctx.state.setdefault("audit_disabled_hosts", set()).add(a.hostname)
        ev, title = [a.asset_id], f"Audit logging disabled on CUI system {a.hostname}"
        expl = (f"{a.hostname} stores/processes CUI but the asset inventory shows audit logging disabled - "
                "notice it has no Windows events at all. Actions there cannot be reconstructed.")
    else:
        ctx.config["siem_retention_days"]["value"] = ctx.rng.choice(["14", "30"])
        ev, title = ["cfg:siem_retention_days"], "Audit log retention far below policy"
        expl = "SIEM retention is a few weeks, while the SSP requires 365 days - investigations will lack data."
    return Issue(key="audit_gap", title=title, category="compliance", severity="medium",
                 controls=["3.3.1", "3.3.2"], evidence=ev, explanation=expl,
                 remediation="Enable audit policy per baseline, forward to SIEM, and set retention per SSP.",
                 hint="Are all in-scope systems actually logging, and for long enough?")


@scenario("unpatched_system", "compliance")
def unpatched_system(ctx: Context) -> Issue:
    rng = ctx.rng
    a = ctx.pick_asset(cui=True)
    if a.role != "Workstation" and rng.random() < 0.5:
        a.os = "Windows Server 2012 R2"
    a.last_patched = (ctx.start - timedelta(days=rng.randint(180, 420))).date().isoformat()
    return Issue(key="unpatched_system", title=f"CUI system {a.hostname} unpatched for months",
                 category="compliance", severity="high", controls=["3.14.1", "3.11.3", "3.11.2"],
                 evidence=[a.asset_id],
                 explanation=(f"{a.hostname} ({a.os}) was last patched {a.last_patched}, far outside the "
                              "30-day patch SLA. End-of-life operating systems no longer receive fixes at all."),
                 remediation="Patch or upgrade, or isolate the system and document it in a POA&M with a due date.",
                 hint="Sort the asset inventory by last_patched.")


@scenario("missing_edr", "compliance")
def missing_edr(ctx: Context) -> Issue:
    a = ctx.pick_asset(role="Workstation", cui=True)
    a.edr_installed = False
    ctx.state.setdefault("no_edr_hosts", set()).add(a.hostname)
    return Issue(key="missing_edr", title=f"No malware protection on CUI workstation {a.hostname}",
                 category="compliance", severity="high", controls=["3.14.2", "3.4.1"], evidence=[a.asset_id],
                 explanation=(f"{a.hostname} is in CUI scope but has no EDR/antivirus agent - it never "
                              "checks in on the nightly health report."),
                 remediation="Deploy the EDR agent and add a compliance check that flags assets missing it.",
                 hint="Which in-scope assets never send a nightly av_status check-in?")


@scenario("cui_to_personal_email", "compliance")
def cui_to_personal_email(ctx: Context) -> Issue:
    rng = ctx.rng
    u = ctx.pick_user(dept=rng.choice(["Engineering", "Program Management", "Quality"]))
    day = ctx.workday(earliest=0)
    _, name = org.cui_filename(rng)
    dom = rng.choice(org.PERSONAL_EMAIL)
    first = u.full_name.split()[0].lower()
    ev = [ctx.add(ctx.at(day, rng.choice([17, 18])), "email", direction="outbound",
                  sender=f"{u.username}@{org.DOMAIN}", recipient=f"{first}.home@{dom}",
                  subject="work from home tonight", attachment=name, tls=False, verdict="delivered",
                  size_kb=rng.randint(800, 15000))]
    return Issue(key="cui_to_personal_email", title=f"{u.username} emailed CUI to a personal address",
                 category="compliance", severity="high", controls=["3.1.3", "3.13.8", "3.13.1"], evidence=ev,
                 explanation=(f"A CUI file ({name}) was sent unencrypted (tls=false) to a personal "
                              f"{dom} mailbox. CUI may only leave via approved, encrypted channels."),
                 remediation=("Recall/report the spill, retrain the user, and add DLP rules blocking CUI "
                              "markings and program codes to non-approved domains."),
                 hint="Who is CUI allowed to be emailed to? Check outbound recipients and attachments.")


@scenario("privileged_account_misuse", "compliance")
def privileged_account_misuse(ctx: Context) -> Issue:
    rng = ctx.rng
    adm = rng.choice(_admins(ctx))
    ctx.used_users.add(adm.username)
    day = ctx.workday(earliest=0)
    t = ctx.at(day, rng.randint(9, 15))
    src = org.ip_of(ctx.assets, adm.workstation)
    ev = [ctx.add(t, "endpoint", host=adm.workstation, user=adm.username, type="process", image="chrome.exe",
                  parent="explorer.exe", cmdline="chrome.exe https://news.example", signer="Valid"),
          ctx.add(t + timedelta(minutes=1), "firewall", action="allow", src=src, dst=ctx.ips.host("news.example"),
                  dport=443, proto="tcp", app="https", host="news.example",
                  bytes_out=40000, bytes_in=2400000),
          ctx.add(t + timedelta(minutes=rng.randint(10, 60)), "email", direction="outbound",
                  sender=f"{adm.username}@{org.DOMAIN}", recipient=f"sales@{rng.choice(['cdw.example', 'newegg.example'])}",
                  subject="Quote request - laptops", attachment="", tls=True, verdict="delivered", size_kb=12)]
    return Issue(key="privileged_account_misuse", title=f"Privileged account {adm.username} used for web and email",
                 category="compliance", severity="medium", controls=["3.1.6", "3.1.5"], evidence=ev,
                 explanation=(f"'{adm.username}' is a privileged admin account but was used to browse the web and "
                              "send email. If the browser or a message is malicious, the attacker gets admin."),
                 remediation="Block internet/email for admin accounts via policy; use the standard account for daily work.",
                 hint="Accounts starting with adm- should only ever do admin work.")


@scenario("unauthorized_software", "compliance")
def unauthorized_software(ctx: Context) -> Issue:
    rng = ctx.rng
    u = ctx.pick_user()
    day = ctx.workday(earliest=0)
    t = ctx.at(day, rng.randint(9, 16))
    pkg, exe, remote = rng.choice([("AnyDesk", "AnyDesk.exe", True), ("uTorrent", "uTorrent.exe", False),
                                   ("TeamViewer", "TeamViewer.exe", True), ("CCleaner Free", "CCleaner64.exe", False)])
    ev = [ctx.add(t, "endpoint", host=u.workstation, user=u.username, type="software_install",
                  package=pkg, version=f"{rng.randint(3, 9)}.{rng.randint(0, 9)}.{rng.randint(0, 9)}",
                  installer=f"C:\\Users\\{u.username}\\Downloads\\{exe.replace('.exe', '')}_setup.exe"),
          ctx.add(t + timedelta(minutes=2), "endpoint", host=u.workstation, user=u.username, type="process",
                  image=exe, parent="explorer.exe", cmdline=exe, signer="Valid")]
    controls = ["3.4.9", "3.4.8"]
    if remote:
        controls.append("3.1.12")
        ev.append(ctx.add(t + timedelta(minutes=3), "firewall", action="allow",
                          src=org.ip_of(ctx.assets, u.workstation), dst=ctx.ips.host(f"relay.{pkg.lower()}.example"),
                          dport=443, proto="tcp", app="https", host=f"relay.{pkg.lower()}.example",
                          bytes_out=rng.randint(100, 900) * 1000, bytes_in=rng.randint(100, 900) * 1000))
    return Issue(key="unauthorized_software", title=f"Unapproved software '{pkg}' installed by {u.username}",
                 category="compliance", severity="medium" if not remote else "high", controls=controls, evidence=ev,
                 explanation=(f"'{pkg}' is not on the approved software list and was installed by a standard user "
                              + ("- it is a remote-access tool that creates an unmonitored path into the network."
                                 if remote else ".")),
                 remediation="Uninstall, enforce application allowlisting (AppLocker/WDAC), and remove local install rights.",
                 hint="Compare software_install events against the approved software list in the briefing.")


@scenario("stale_account", "compliance")
def stale_account(ctx: Context) -> Issue:
    rng = ctx.rng
    u = ctx.pick_user()
    u.last_login = (ctx.start - timedelta(days=rng.randint(130, 320))).date().isoformat()
    u.baseline = False
    u.notes = rng.choice(["Extended leave", "Transferred to sister company", ""])
    return Issue(key="stale_account", title=f"Inactive account {u.username} still enabled",
                 category="compliance", severity="medium", controls=["3.5.6"], evidence=[u.user_id],
                 explanation=(f"'{u.username}' hasn't logged in since {u.last_login} but the account is still "
                              "enabled. Policy requires disabling accounts after 90 days of inactivity."),
                 remediation="Disable the account and automate a 90-day inactivity sweep.",
                 hint="Sort the roster by last_login.")


# =========================================================================
# DECOYS - suspicious-looking but legitimate. Flagging them costs points.
# =========================================================================

@decoy("after_hours_approved_change")
def d_after_hours_change(ctx: Context) -> Decoy:
    rng = ctx.rng
    admins = _admins(ctx)
    adm = rng.choice(admins)
    ctx.used_users.add(adm.username)
    day = ctx.workday(earliest=0)
    t = ctx.at(day, 21)
    ticket = f"CHG-{rng.randint(10000, 99999)}"
    ctx.change_tickets.append({"ticket": ticket, "status": "Approved", "requested_by": adm.owner,
                               "approved_by": "IT Manager", "window_start": t.replace(minute=0).isoformat(),
                               "window_end": (t.replace(minute=0) + timedelta(hours=3)).isoformat(),
                               "description": "Add CAD license group members for new hires"})
    member = rng.choice(_named_active(ctx))
    ev = [ctx.add(t, "windows", EventID=4624, Computer="DC01", TargetUserName=adm.username, LogonType=10,
                  IpAddress=org.ip_of(ctx.assets, adm.workstation), AuthPackage="Kerberos", MFA="duo_approved"),
          ctx.add(t + timedelta(minutes=4), "windows", EventID=4728, Computer="DC01", SubjectUserName=adm.username,
                  MemberName=member.username, GroupName="CAD-License-Users",
                  Description="A member was added to a security-enabled global group")]
    return Decoy("after_hours_approved_change", ev,
                 f"After-hours group change, but it matches approved change ticket {ticket}, targets a "
                 "non-privileged group, and used MFA.")


@decoy("approved_foreign_travel")
def d_foreign_travel(ctx: Context) -> Decoy:
    rng = ctx.rng
    u = ctx.pick_user()
    city, cc = rng.choice(org.FOREIGN_TRAVEL)
    day = ctx.workday(earliest=0)
    ctx.travel_exceptions.append({"username": u.username, "destination": f"{city}, {cc}",
                                  "start": (day - timedelta(days=1)).date().isoformat(),
                                  "end": (day + timedelta(days=2)).date().isoformat(),
                                  "approved_by": "FSO", "conditions": "Company laptop only; MFA required"})
    u.baseline = False
    ip = ctx.ips.external()
    a = _assigned_ip(ctx)
    t = ctx.at(day, rng.randint(2, 5))  # time-zone shifted working hours
    ev = [ctx.add(t, "vpn", user=u.username, action="connect", src_ip=ip, geo_city=city, geo_country=cc,
                  mfa="push_approved", assigned_ip=a, client="AnyConnect-5.1"),
          ctx.add(t + timedelta(hours=rng.randint(3, 6)), "vpn", user=u.username, action="disconnect", src_ip=ip,
                  geo_city=city, geo_country=cc, assigned_ip=a, bytes_in=300_000_000, bytes_out=20_000_000)]
    return Decoy("approved_foreign_travel", ev,
                 f"Foreign VPN login, but {u.username} has an approved travel exception for {city}, {cc} on "
                 "these dates and authenticated with MFA. The odd hour is the time-zone difference.")


@decoy("allowlisted_usb")
def d_allowlisted_usb(ctx: Context) -> Decoy:
    rng = ctx.rng
    u = ctx.pick_user(dept=rng.choice(["Engineering", "Quality"]))
    serial = "".join(rng.choice("0123456789ABCDEF") for _ in range(16))
    ctx.usb_allowlist.append({"serial": serial, "model": "SecureVault FIPS 140-3 encrypted drive",
                              "assigned_to": u.username, "encrypted": True})
    day = ctx.workday(earliest=0)
    t = ctx.at(day, rng.randint(9, 15))
    ev = [ctx.add(t, "endpoint", host=u.workstation, user=u.username, type="usb", action="mount",
                  device_id=f"USBSTOR\\Disk&Ven_SecureVault\\{serial}", vendor="SecureVault FIPS",
                  serial=serial, encrypted=True, drive_letter="E:")]
    path, name = org.cui_filename(rng)
    ev.append(ctx.add(t + timedelta(minutes=1), "endpoint", host=u.workstation, user=u.username, type="file_copy",
                      src=path, dst=f"E:\\{name}", bytes=rng.randint(500, 9000) * 1000))
    return Decoy("allowlisted_usb", ev,
                 "CUI copied to USB, but the device is on the allowlist, assigned to this user, and FIPS-encrypted.")


@decoy("partner_sftp_transfer")
def d_partner_sftp(ctx: Context) -> Decoy:
    rng = ctx.rng
    u = ctx.pick_user(dept="Program Management")
    day = ctx.workday(earliest=0)
    ev = [ctx.add(ctx.at(day, rng.randint(10, 15)), "firewall", action="allow",
                  src=org.ip_of(ctx.assets, u.workstation), dst=ctx.ips.host(org.PRIME_SFTP), dport=22, proto="tcp",
                  app="sftp", host=org.PRIME_SFTP, bytes_out=rng.randint(800, 2500) * 1_000_000,
                  bytes_in=rng.randint(1, 5) * 1_000_000)]
    return Decoy("partner_sftp_transfer", ev,
                 "Large outbound transfer, but it's SFTP (encrypted) to the prime contractor's approved CUI "
                 "exchange server.")


@decoy("fat_finger_logins")
def d_fat_finger(ctx: Context) -> Decoy:
    rng = ctx.rng
    u = ctx.pick_user()
    day = ctx.workday(earliest=0)
    t = ctx.at(day, 7)
    ip = org.ip_of(ctx.assets, u.workstation)
    ev = []
    for _ in range(3):
        ev.append(ctx.add(t, "windows", EventID=4625, Computer=u.workstation, TargetUserName=u.username,
                          LogonType=2, IpAddress=ip, Status="0xC000006A", FailureReason="Bad password"))
        t += timedelta(seconds=rng.randint(8, 30))
    ev.append(ctx.add(t, "windows", EventID=4624, Computer=u.workstation, TargetUserName=u.username,
                      LogonType=2, IpAddress=ip, AuthPackage="Kerberos"))
    return Decoy("fat_finger_logins", ev,
                 "Three failed logons then success - at the user's own desk, during business hours, under "
                 "the lockout threshold. Classic Monday-morning typo, not an attack.")
