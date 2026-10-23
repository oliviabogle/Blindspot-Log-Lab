"""
NIST SP 800-171 Rev 2 control catalog (subset) with CMMC Level 2 practice IDs.

CMMC Level 2 (32 CFR Part 170) incorporates the 110 security requirements of
NIST SP 800-171 Revision 2, so this lab uses Rev 2 numbering. Titles below are
short paraphrases for training use; consult the official publication for the
authoritative requirement text.
"""

from __future__ import annotations

import re

FAMILIES = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CM": "Configuration Management",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PS": "Personnel Security",
    "PE": "Physical Protection",
    "RA": "Risk Assessment",
    "CA": "Security Assessment",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}

# Section number (3.x) -> family abbreviation
_SECTION_TO_FAMILY = {
    "1": "AC", "2": "AT", "3": "AU", "4": "CM", "5": "IA", "6": "IR", "7": "MA",
    "8": "MP", "9": "PS", "10": "PE", "11": "RA", "12": "CA", "13": "SC", "14": "SI",
}

# control id -> short paraphrased title
CONTROLS: dict[str, str] = {
    # Access Control
    "3.1.1": "Limit system access to authorized users, processes, and devices",
    "3.1.2": "Limit system access to the transactions and functions users are permitted to execute",
    "3.1.3": "Control the flow of CUI in accordance with approved authorizations",
    "3.1.5": "Employ the principle of least privilege, including for privileged accounts",
    "3.1.6": "Use non-privileged accounts when accessing nonsecurity functions",
    "3.1.7": "Prevent non-privileged users from executing privileged functions; audit privileged function execution",
    "3.1.8": "Limit unsuccessful logon attempts",
    "3.1.9": "Provide privacy and security notices (system use banner) consistent with CUI rules",
    "3.1.10": "Use session lock with pattern-hiding displays after a period of inactivity",
    "3.1.11": "Terminate (automatically) a user session after a defined condition",
    "3.1.12": "Monitor and control remote access sessions",
    "3.1.21": "Limit use of portable storage devices on external systems",
    # Awareness & Training
    "3.2.1": "Ensure personnel are aware of security risks associated with their activities",
    # Audit & Accountability
    "3.3.1": "Create and retain system audit logs to enable monitoring, analysis, investigation, and reporting",
    "3.3.2": "Ensure actions of individual users can be uniquely traced so they can be held accountable",
    "3.3.5": "Correlate audit record review, analysis, and reporting processes",
    "3.3.8": "Protect audit information and logging tools from unauthorized access, modification, and deletion",
    "3.3.9": "Limit management of audit logging functionality to a subset of privileged users",
    # Configuration Management
    "3.4.1": "Establish and maintain baseline configurations and inventories of systems",
    "3.4.2": "Establish and enforce security configuration settings",
    "3.4.3": "Track, review, approve or disapprove, and log changes to systems",
    "3.4.8": "Apply deny-by-exception (blacklisting) or permit-by-exception (whitelisting) policy for software",
    "3.4.9": "Control and monitor user-installed software",
    # Identification & Authentication
    "3.5.1": "Identify system users, processes acting on behalf of users, and devices",
    "3.5.2": "Authenticate (verify) identities of users, processes, or devices before allowing access",
    "3.5.3": "Use multifactor authentication for local and network access to privileged accounts and network access to non-privileged accounts",
    "3.5.6": "Disable identifiers after a defined period of inactivity",
    "3.5.7": "Enforce minimum password complexity and change of characters when new passwords are created",
    "3.5.10": "Store and transmit only cryptographically protected passwords",
    # Incident Response
    "3.6.1": "Establish an operational incident-handling capability",
    "3.6.2": "Track, document, and report incidents to designated officials and authorities",
    # Media Protection
    "3.8.7": "Control the use of removable media on system components",
    "3.8.8": "Prohibit the use of portable storage devices when such devices have no identifiable owner",
    # Personnel Security
    "3.9.2": "Ensure CUI and systems are protected during and after personnel actions such as terminations and transfers",
    # Risk Assessment
    "3.11.2": "Scan for vulnerabilities periodically and when new vulnerabilities are identified",
    "3.11.3": "Remediate vulnerabilities in accordance with risk assessments",
    # System & Communications Protection
    "3.13.1": "Monitor, control, and protect communications at external and key internal boundaries",
    "3.13.6": "Deny network communications traffic by default; allow by exception",
    "3.13.8": "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission",
    "3.13.9": "Terminate network connections associated with communications sessions after inactivity",
    # System & Information Integrity
    "3.14.1": "Identify, report, and correct system flaws in a timely manner",
    "3.14.2": "Provide protection from malicious code at designated locations",
    "3.14.3": "Monitor system security alerts and advisories and take action",
    "3.14.6": "Monitor systems, including inbound and outbound traffic, to detect attacks and indicators of attack",
    "3.14.7": "Identify unauthorized use of organizational systems",
}

_CONTROL_RE = re.compile(r"3\.(\d{1,2})\.(\d{1,2})")


def family_of(control_id: str) -> str:
    section = control_id.split(".")[1]
    return _SECTION_TO_FAMILY[section]


def cmmc_id(control_id: str) -> str:
    """'3.1.8' -> 'AC.L2-3.1.8'"""
    return f"{family_of(control_id)}.L2-{control_id}"


def normalize(text: str) -> list[str]:
    """Extract every 800-171 control id from free text.

    Accepts '3.1.8', 'AC.L2-3.1.8', 'ac.l2-3.1.8; 3.5.3', etc.
    """
    return [f"3.{a}.{b}" for a, b in _CONTROL_RE.findall(text or "")]


def describe(control_id: str) -> str:
    title = CONTROLS.get(control_id, "(not in lab catalog)")
    return f"{cmmc_id(control_id)}  {title}"
