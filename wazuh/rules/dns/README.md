# DNS attack detection

Wazuh rules for the DNS zone transfer, dynamic-update spoofing, and WPAD abuse chain run against DC01. Full write-up: **[I Broke DNS, Exploited It, Then Fixed It (Here's How)](https://medium.com/@johnnymeintel/i-broke-dns-exploited-it-then-fixed-it-heres-how-c612346fcc3b)**.

- **100310** fires when a DNS record is CREATED via dynamic update (Windows DNS Server Audit Event 519).
- **100311** fires when a DNS record is DELETED via dynamic update (Event 520).

Both key off `Microsoft-Windows-DNSServer/Audit` shipped to the agent as an `eventchannel` `<localfile>`, and map to MITRE T1584.002.
