# Tips and Tricks

Real gotchas hit building this lab. Symptom, fix, one-line why.

---

**DC01 unreachable, "cannot find the domain controller"**
```powershell
Set-DnsClientServerAddress -InterfaceAlias "Ethernet1" -ServerAddresses 8.8.8.8   # broken
Set-DnsClientServerAddress -InterfaceAlias "Ethernet1" -ServerAddresses 10.10.10.11   # fixed
nltest /dsgetdc:corp.local /force
```
Domain join and the DC locator run on DNS SRV records. Only the DC serves them.

---

**`whoami` says the wrong thing about domain membership**
```powershell
whoami                                          # shows the logged-in account, not the machine's state
(Get-CimInstance Win32_ComputerSystem).Domain   # this is the actual proof
nltest /sc_query:corp.local                     # and this — secure channel health
```
A local login on a domain-joined box still shows `HOST\administrator`.

---

**Kerberos auth fails, no obvious reason**
```powershell
w32tm /query /status
w32tm /resync /force
```
Kerberos rejects anything outside a 5-minute clock skew. Silent failure, confusing symptom.

---

**Multihomed DC hands out the wrong IP**
```powershell
Resolve-DnsName corp.local        # returned the NAT IP, not the lab IP
Get-DnsServerResourceRecord -ZoneName corp.local -RRType A   # found the stale record
```
Don't multihome a DC. Microsoft says so for exactly this reason.

---

**AD cmdlets fail with "cannot find an object with identity"**
```powershell
Get-ADDomain -Server DC01.corp.local -Credential (Get-Credential)   # works from a local session
```
No domain session = no domain credentials = the cmdlet falls back to the computer name.

---

**OpenSSH silently rejects a valid public key**
```powershell
[System.IO.File]::WriteAllText($path, $key + "`n")   # no BOM — this is the one that works
```
`Set-Content -Encoding UTF8` writes a BOM. OpenSSH won't tell you why it's rejecting the file.

---

**Wazuh agent won't come back after a config change**
```powershell
Stop-Service -Force WazuhSvc
Get-Service WazuhSvc   # confirm Stopped before continuing
Start-Service WazuhSvc
```
`Restart-Service` hangs the agent. Stop, verify, start — every time.

---

**Zone transfer succeeds, WPAD injection does nothing**
```
Get-DnsServerGlobalQueryBlockList
```
The Global Query Block List silently blocks `wpad`/`isatap` by default. The control was already on — check the config before assuming the attack failed.

---

**RMM tool renamed to dodge detection, still gets caught**
```
win.eventdata.company: "AnyDesk Software GmbH"
```
Sysmon's `Company` field comes from the binary's signed metadata, not the filename. Rename-proof for free.
