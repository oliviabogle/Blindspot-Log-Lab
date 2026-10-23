"""Normal, benign background activity. This is the haystack the analyst searches."""

from __future__ import annotations

from datetime import timedelta

from . import org
from .model import Context, User

WIN_LOGON_OK = 4624
WIN_LOGON_FAIL = 4625
WIN_LOGOFF = 4634


def _internal_ip(ctx: Context, host: str) -> str:
    return org.ip_of(ctx.assets, host)


def _vpn_home_ip(ctx: Context, u: User) -> str:
    if u.username not in ctx.vpn_ips:
        ctx.vpn_ips[u.username] = ctx.ips.external()
    return ctx.vpn_ips[u.username]


def _workday_user(ctx: Context, u: User, day, noise: float) -> None:
    rng = ctx.rng
    ws_ip = _internal_ip(ctx, u.workstation)
    remote = rng.random() < 0.25
    login = ctx.at(day, rng.choice([6, 7, 7, 8, 8, 9]))
    logout = login + timedelta(hours=rng.uniform(7.5, 10), minutes=rng.randint(0, 50))

    if remote:
        home_ip = _vpn_home_ip(ctx, u)
        assigned = f"10.99.0.{rng.randint(10, 250)}"
        ctx.add(login - timedelta(minutes=2), "vpn", user=u.username, action="connect",
                src_ip=home_ip, geo_city=u.home_city, geo_country="US",
                mfa="push_approved" if u.mfa_enrolled else "none", assigned_ip=assigned,
                client="AnyConnect-5.1")
        ctx.add(logout, "vpn", user=u.username, action="disconnect", src_ip=home_ip,
                geo_city=u.home_city, geo_country="US", assigned_ip=assigned,
                bytes_in=rng.randint(20, 900) * 1_000_000, bytes_out=rng.randint(2, 90) * 1_000_000,
                duration_min=int((logout - login).total_seconds() // 60))
        src_ip = assigned
    else:
        src_ip = ws_ip
        if rng.random() < 0.08 * noise:   # fat-fingered password: normal, not an incident
            ctx.add(login - timedelta(seconds=rng.randint(15, 70)), "windows", EventID=WIN_LOGON_FAIL,
                    Computer=u.workstation, TargetUserName=u.username, LogonType=2,
                    IpAddress=ws_ip, Status="0xC000006A", FailureReason="Bad password")
        ctx.add(login, "windows", EventID=WIN_LOGON_OK, Computer=u.workstation,
                TargetUserName=u.username, LogonType=2, IpAddress=ws_ip, AuthPackage="Kerberos")
        ctx.add(logout, "windows", EventID=WIN_LOGOFF, Computer=u.workstation,
                TargetUserName=u.username, LogonType=2)

    def work_time():
        span = (logout - login).total_seconds()
        return login + timedelta(seconds=rng.uniform(600, max(900, span - 600)))

    # File share activity
    cui_depts = ("Engineering", "Manufacturing", "Program Management", "Quality", "Contracts")
    if u.department in cui_depts:
        for _ in range(int(rng.randint(3, 10) * noise)):
            path, _name = org.cui_filename(rng)
            ctx.add(work_time(), "fileshare", user=u.username, src_ip=src_ip,
                    server=path.split("\\")[2], path=path,
                    action=rng.choice(["read"] * 5 + ["write"]),
                    bytes=rng.randint(40, 9000) * 1000, classification="CUI")
    for _ in range(int(rng.randint(0, 3) * noise)):
        share = rng.choice(org.NON_CUI_SHARES)
        fname = rng.choice(["lunch_menu.pdf", "parking_map.png", "brochure_v3.pptx",
                            "safety_poster.pdf", "org_chart.pdf", "holiday_schedule.xlsx"])
        ctx.add(work_time(), "fileshare", user=u.username, src_ip=src_ip,
                server=share.split("\\")[2], path=f"{share}\\{fname}", action="read",
                bytes=rng.randint(50, 3000) * 1000, classification="Internal")

    # Email
    for _ in range(int(rng.randint(1, 5) * noise)):
        external = rng.random() < 0.35
        if external and u.department in ("Program Management", "Contracts", "Engineering"):
            to = f"{rng.choice(['pm', 'buyer', 'supplier.quality', 'engineering'])}@{org.PRIME_DOMAIN}"
        elif external:
            to = f"sales@{rng.choice(['mcmaster.example', 'grainger.example', 'fastenal.example'])}"
        else:
            to = f"{rng.choice([x for x in ctx.users if x.account_type == 'named']).username}@{org.DOMAIN}"
        ctx.add(work_time(), "email", direction="outbound" if external else "internal",
                sender=f"{u.username}@{org.DOMAIN}", recipient=to,
                subject=rng.choice(["Status update", "RE: schedule", "Meeting notes", "PO question",
                                    "RE: drawing review", "Weekly report", "Quick question"]),
                attachment=rng.choice(["", "", "", "notes.docx", "schedule.xlsx"]),
                tls=True, verdict="delivered", size_kb=rng.randint(8, 900))
    if rng.random() < 0.5 * noise:
        ctx.add(work_time(), "email", direction="inbound",
                sender=f"noreply@{rng.choice(['mcmaster.example', 'sam.gov.example', 'linkedin.example'])}",
                recipient=f"{u.username}@{org.DOMAIN}",
                subject=rng.choice(["Your order has shipped", "Registration reminder", "Newsletter"]),
                attachment="", tls=True, verdict="delivered", size_kb=rng.randint(10, 200))

    # Web traffic
    for _ in range(int(rng.randint(2, 7) * noise)):
        site = rng.choice(org.NORMAL_WEB)
        ctx.add(work_time(), "firewall", action="allow", src=src_ip, dst=ctx.ips.host(site),
                dport=443, proto="tcp", app="https", host=site,
                bytes_out=rng.randint(1, 80) * 1000, bytes_in=rng.randint(10, 4000) * 1000)

    # Endpoint process telemetry (only when on the workstation)
    if not remote:
        apps = ["outlook.exe", "chrome.exe", "teams.exe", "excel.exe", "winword.exe"]
        if u.department == "Engineering":
            apps += ["SolidWorks.exe", "acad.exe"]
        if u.department == "Manufacturing":
            apps += ["mastercam.exe"]
        for app in rng.sample(apps, k=min(len(apps), rng.randint(2, 4))):
            ctx.add(work_time(), "endpoint", host=u.workstation, user=u.username, type="process",
                    image=app, parent="explorer.exe", cmdline=app, signer="Valid")


def _admin_activity(ctx: Context, admin: User, day) -> None:
    rng = ctx.rng
    servers = [a for a in ctx.assets if a.role not in ("Workstation",) and not a.os.startswith("Vendor")]
    src = _internal_ip(ctx, admin.workstation)
    for _ in range(rng.randint(1, 3)):
        srv = rng.choice(servers)
        t = ctx.at(day, rng.randint(8, 16))
        ctx.add(t, "windows", EventID=WIN_LOGON_OK, Computer=srv.hostname,
                TargetUserName=admin.username, LogonType=10, IpAddress=src, AuthPackage="Kerberos",
                MFA="duo_approved")
        ctx.add(t, "endpoint", host=srv.hostname, user=admin.username, type="process",
                image=rng.choice(["mmc.exe", "powershell.exe", "ServerManager.exe"]),
                parent="explorer.exe", cmdline="(interactive admin session)", signer="Valid")
        ctx.add(t + timedelta(minutes=rng.randint(5, 50)), "windows", EventID=WIN_LOGOFF,
                Computer=srv.hostname, TargetUserName=admin.username, LogonType=10)


def generate_baseline(ctx: Context, noise: float = 1.0) -> None:
    rng = ctx.rng
    for d in range(ctx.days):
        day = ctx.start + timedelta(days=d)
        weekday = day.weekday() < 5
        for u in ctx.users:
            if not u.baseline or u.status != "active":
                continue
            if u.account_type == "admin":
                if weekday:
                    _admin_activity(ctx, u, day)
                continue
            if u.account_type != "named":
                continue
            if weekday:
                if rng.random() < 0.06:      # PTO / sick day
                    continue
                _workday_user(ctx, u, day, noise)
            elif rng.random() < 0.08:      # a little weekend VPN email-checking
                t = ctx.at(day, rng.randint(9, 17))
                ip = _vpn_home_ip(ctx, u)
                ctx.add(t, "vpn", user=u.username, action="connect", src_ip=ip,
                        geo_city=u.home_city, geo_country="US",
                        mfa="push_approved" if u.mfa_enrolled else "none",
                        assigned_ip=f"10.99.0.{rng.randint(10, 250)}", client="AnyConnect-5.1")
                ctx.add(t + timedelta(minutes=rng.randint(10, 60)), "vpn", user=u.username,
                        action="disconnect", src_ip=ip, geo_city=u.home_city, geo_country="US",
                        bytes_in=rng.randint(2, 60) * 1_000_000, bytes_out=rng.randint(1, 9) * 1_000_000)

        # Nightly backup job (service account)
        bt = day.replace(hour=1, minute=rng.randint(0, 15), second=rng.randint(0, 59))
        ctx.add(bt, "windows", EventID=WIN_LOGON_OK, Computer="BACKUP01", TargetUserName="svc-backup",
                LogonType=4, IpAddress="10.10.0.40", AuthPackage="Kerberos")
        # Nightly EDR health check-in
        av_off = ctx.state.get("av_off", {})
        for a in ctx.assets:
            if a.edr_installed:
                t = day.replace(hour=3, minute=rng.randint(0, 59), second=rng.randint(0, 59))
                off = a.hostname in av_off and t > av_off[a.hostname]
                ctx.add(t, "endpoint", host=a.hostname, user="SYSTEM", type="av_status",
                        realtime_protection="off" if off else "on",
                        signature_age_days=rng.choice([0, 0, 1]) if not off else (t - av_off[a.hostname]).days + 1,
                        tamper_protection="off" if off else "on")
        # Internet background radiation hitting the perimeter (blocked = working as intended)
        for _ in range(int(rng.randint(15, 40) * noise)):
            ctx.add(ctx.at(day, rng.randint(0, 23)), "firewall", action="deny", src=ctx.ips.noise(),
                    dst="10.10.1.1", dport=rng.choice([22, 23, 445, 3389, 8080, 5900, 1433]),
                    proto="tcp", app="-", host="-", bytes_out=0, bytes_in=60)
        # Some inbound spam correctly quarantined
        for _ in range(rng.randint(0, 3)):
            target = rng.choice([u for u in ctx.users if u.account_type == "named" and u.status == "active"])
            ctx.add(ctx.at(day, rng.randint(0, 23)), "email", direction="inbound",
                    sender=f"promo@{rng.choice(['deals-now.example', 'cheap-meds.example', 'win-big.example'])}",
                    recipient=f"{target.username}@{org.DOMAIN}", subject="You have been selected!!",
                    attachment="", tls=False, verdict="quarantined:spam", size_kb=rng.randint(5, 50))


def generate_scanner_activity(ctx: Context):
    """Authorized weekly vulnerability scan. Looks like a port scan - on purpose."""
    rng = ctx.rng
    sunday = next((ctx.start + timedelta(days=d) for d in range(ctx.days)
                   if (ctx.start + timedelta(days=d)).weekday() == 6), ctx.start)
    t = sunday.replace(hour=2, minute=0, second=0)
    scanner_ip = org.ip_of(ctx.assets, "VULNSCAN01")
    events = []
    targets = rng.sample([a for a in ctx.assets if a.hostname != "VULNSCAN01"], k=min(12, len(ctx.assets) - 1))
    for a in targets:
        for port in rng.sample([22, 80, 135, 139, 443, 445, 3389, 5985], k=4):
            t += timedelta(seconds=rng.randint(1, 20))
            events.append(ctx.add(t, "firewall", action="allow", src=scanner_ip, dst=a.ip, dport=port,
                                  proto="tcp", app="scan", host="-", bytes_out=120, bytes_in=rng.choice([0, 60, 1400])))
    events.append(ctx.add(t - timedelta(minutes=30), "windows", EventID=WIN_LOGON_OK, Computer="DC01",
                          TargetUserName="svc-scan", LogonType=3, IpAddress=scanner_ip, AuthPackage="Kerberos"))
    return events
