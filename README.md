# Fontaine Cloud threat intelligence

<a href="https://github.com/Fontaine-Cloud/threat-intel/commits/main"><img alt="Last update" src="https://img.shields.io/github/last-commit/Fontaine-Cloud/threat-intel?style=flat-square&label=updated&labelColor=111d31&color=0758e8"></a>
<a href="https://raw.githubusercontent.com/Fontaine-Cloud/threat-intel/main/blocklist.txt"><img alt="Addresses" src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Fontaine-Cloud/threat-intel/main/badge.json&style=flat-square"></a>
<a href="https://fontaine.host/threat-intelligence/"><img alt="Dashboard" src="https://img.shields.io/badge/dashboard-fontaine.host-0758e8?style=flat-square&labelColor=111d31"></a>
<a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-CC_BY_4.0-0758e8?style=flat-square&labelColor=111d31"></a>

Addresses that [Fontaine Cloud](https://fontaine.host)'s threat research saw attacking in the last 7 days: password guessing, exploits for published vulnerabilities, hunts for leaked secrets and open-proxy abuse. Known research scanners are left out. The list is refreshed every hour.

| File | Contents |
| --- | --- |
| [`blocklist.txt`](blocklist.txt) | One IP address per line, `#` comments at the top |
| [`stats/`](stats) | A JSON snapshot per day: totals, attack types, ports, countries, networks, tools and the most tried logins |

The live dashboard is at [fontaine.host/threat-intelligence](https://fontaine.host/threat-intelligence/).

## Using the blocklist

```
https://raw.githubusercontent.com/Fontaine-Cloud/threat-intel/main/blocklist.txt
```

### nftables

```sh
curl -s https://raw.githubusercontent.com/Fontaine-Cloud/threat-intel/main/blocklist.txt -o /tmp/fontaine-blocklist.txt
nft add table inet fontaine
nft add set inet fontaine blocklist '{ type ipv4_addr; }'
nft add chain inet fontaine input '{ type filter hook input priority -10; policy accept; }'
nft add rule inet fontaine input ip saddr @blocklist drop
nft flush set inet fontaine blocklist
nft add element inet fontaine blocklist "{ $(grep -v '^#' /tmp/fontaine-blocklist.txt | paste -sd,) }"
```

To refresh, run the `curl`, `flush` and `add element` lines again.

### ipset and iptables

```sh
curl -s https://raw.githubusercontent.com/Fontaine-Cloud/threat-intel/main/blocklist.txt -o /tmp/fontaine-blocklist.txt
ipset create fontaine hash:ip -exist
ipset flush fontaine
grep -v '^#' /tmp/fontaine-blocklist.txt | sed 's/^/add fontaine /' | ipset restore -exist
iptables -I INPUT -m set --match-set fontaine src -j DROP
```

To refresh, run the first four lines again.

> [!NOTE]
> Attackers often use shared addresses such as cloud servers and NAT gateways, so blocking an address can also block legitimate users behind it.

## License

The data is licensed under [CC BY 4.0](LICENSE). Credit "Fontaine Cloud threat intelligence" with a link to https://fontaine.host/threat-intelligence/.
