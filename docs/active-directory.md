# Active Directory

## Why populate the domain instead of leaving it empty

An empty AD forest with three test users isn't a representative attack surface — it's a demo. Real MSP-managed domains are messy: thousands of accounts, inconsistent group membership, department sprawl, and the occasional account that never should have ended up in a privileged group. The goal here is a domain that behaves like that, so the detection work built against it generalizes past "I know exactly what's in my own lab."

## Populating the domain

[BadBlood](https://github.com/davidprowe/BadBlood) bulk-populates a fresh AD forest with a realistic org structure in minutes: roughly **2,500 users** (a small number intentionally disabled, matching real offboarding drift), **550 groups**, and **220+ OUs** organized by department. It also plants a handful of accidental-looking misconfigurations along the way — including a few accounts BadBlood drops directly into privileged groups (Domain Admins, Builtin Administrators) as shadow admins.

That shadow-admin drop isn't cleaned up. It's kept on purpose as a live "audit your privileged group membership" exercise — the kind of finding a PingCastle or BloodHound run should surface in any real environment, and a natural first writeup for anyone building a detection lab on top of this.

## Structure

- **Domain / forest:** `corp.local`, NetBIOS `CORP`
- **Domain controller:** DC01, running AD DS + DNS
- **Member server:** SRV01, hosting file shares with realistic NTFS permission boundaries (department-scoped shares, not one flat "Everyone" share)
- **Workstations:** WS01 and WS02, domain-joined, standing in for a phishing target and a lateral-movement target respectively
- **Audit policy:** command-line process auditing (Event ID 4688) and PowerShell Script Block Logging are enabled via GPO, so the domain actually produces the telemetry the detection stack depends on. A domain with no audit policy is a domain with nothing to detect.

## Attack surface

The domain isn't hardened by default — it's built to have the same class of weaknesses a real MSP-managed environment tends to accumulate:

- Kerberoastable and AS-REP-roastable service accounts
- The BadBlood-planted shadow admins described above
- Realistic (not maximally locked-down) GPO and password policy

This surface feeds the attack/detection labs that run against the domain — RMM abuse simulation, DNS attacks, and Kerberos attacks (Kerberoasting, AS-REP roasting) launched from the Kali box on BLUETEAM. See the main [README](../README.md) for links to the individual detection-engineering repos built on top of this domain.
