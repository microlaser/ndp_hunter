# IPv6 NDP Hunter 🕵️‍♂️🛡️

**NDP Hunter** is a lightweight Python tool for detecting IPv6 Man-in-the-Middle attacks on local networks. It sniffs the physical layer for anomalous **Neighbor Discovery Protocol (NDP)** traffic, specifically targeting Rogue Router Advertisements (Rogue RAs), DNS hijacking via the RDNSS option, and Neighbor Advertisement spoofing.

---

## ⚠️ The Threat: IPv6 Local Network Hijacking

Even if your machine is configured to use secure IPv4 DNS servers, modern operating systems (Linux, macOS, Windows) prefer IPv6 over IPv4 by default (RFC 6724).

Because basic NDP lacks authentication, an attacker on the same local network can broadcast a **Rogue Router Advertisement**. This tricks your machine into accepting the attacker's device as the local IPv6 router and — critically — accepting the attacker's rogue IPv6 DNS server via the **RDNSS option (RFC 6106)**. Your DNS traffic is then silently hijacked, bypassing your secure IPv4 configuration entirely.

NDP Hunter detects this attack class at the packet level, alerting on both the rogue RA itself and any untrusted DNS server embedded in RDNSS options.

---

## ✨ What's New (v2)

Version 2 replaces the original `tcpdump` subprocess wrapper with a [Scapy](https://scapy.net/)-based packet engine. This enables structured packet parsing rather than screen-scraping tcpdump output.

**New capabilities:**

- **RDNSS extraction (RFC 6106)** — Parses ICMPv6 RA packets for DNS server options and alerts when an untrusted IPv6 DNS server is advertised. This is the actual DNS hijack vector the tool exists to detect.
- **Router MAC baselining** — On first startup, the source MAC of the first RA from each router IP is recorded as the expected baseline. Any subsequent RA from the same IP with a *different* MAC triggers an alert. Alternatively, pass `--trusted-router` MACs explicitly to skip the learning phase.
- **Trusted RDNSS allowlist** — Pass one or more `--trusted-rdnss` addresses. Any RDNSS option containing an address outside the allowlist triggers an immediate alert.
- **Unsolicited NA spoof detection** — Flags Neighbor Advertisements with `Solicited=0, Override=1`, a reliable indicator of NA poisoning attempts.
- **Prefix logging** — Advertised IPv6 prefixes are logged in verbose mode for audit purposes.
- **Structured file logging** — All events, including alerts, are written to `/var/log/ndp_hunter.log` (configurable) in ISO 8601 format, suitable for log aggregation.
- **`--dump-state`** — On exit, prints the full observed router MAC and RDNSS table for inspection.
- **Fixed Linux interface fallback** — The original tool fell back to `any` on Linux, which uses cooked captures (SLL) and hides L2 MAC addresses. v2 exits with an error and requires an explicit `-i` argument instead, preserving MAC visibility.
- **Removed `shell=True`** — All subprocess calls now use argument lists to eliminate shell injection risk.

---

## ⚙️ Prerequisites

- Python 3.10+
- [Scapy](https://scapy.net/) — `pip install scapy`
- Root privileges (raw socket access)

```bash
pip install scapy
```

---

## 🚀 Usage

```bash
git clone https://github.com/microlaser/ndp_hunter.git
cd ndp_hunter
sudo python3 ndp_hunter.py [options]
```

### Auto-detect interface, learn baseline dynamically

```bash
sudo python3 ndp_hunter.py
```

### Specify interface and trusted router MAC

```bash
sudo python3 ndp_hunter.py -i eth0 --trusted-router aa:bb:cc:dd:ee:ff
```

### Lock down trusted DNS servers (alert on anything else)

```bash
sudo python3 ndp_hunter.py -i wlan0 \
  --trusted-rdnss 2606:4700:4700::1111 \
  --trusted-rdnss 2606:4700:4700::1001
```

### Verbose mode with state dump on exit

```bash
sudo python3 ndp_hunter.py -v --dump-state
```

### Full options

```
-i, --interface       Interface to sniff (default: auto-detect via routing table)
--trusted-router MAC  Trusted router MAC(s). Any RA from an unlisted MAC alerts.
                      Repeat for multiple. Omit to use auto-baseline mode.
--trusted-rdnss IPv6  Trusted RDNSS address(es). Any unlisted DNS server in an
                      RA option triggers an alert. Repeat for multiple.
--logfile PATH        Log file path (default: /var/log/ndp_hunter.log)
--dump-state          Print observed router/RDNSS state table on exit
-v, --verbose         Show all packets, not just alerts
-h, --help            Show this help message
```

---

## 🔍 Alert Types

| Alert | Trigger |
|---|---|
| `ROGUE ROUTER ADVERTISEMENT` | RA source MAC not in trusted list or differs from learned baseline |
| `ROGUE RDNSS (DNS HIJACK VECTOR)` | RA contains RDNSS option with an address not in `--trusted-rdnss` list |
| `UNSOLICITED NA WITH OVERRIDE` | Neighbor Advertisement with `S=0, O=1` — classic NA spoofing signature |

---

## 📋 Sample Output

```
2026-06-11T14:22:01Z [INFO] ndp_hunter starting | interface=wlan0
2026-06-11T14:22:01Z [INFO] Trusted routers : ['(auto-baseline)']
2026-06-11T14:22:01Z [INFO] Trusted RDNSS   : ['(log new, no alert)']
----------------------------------------------------------------------
2026-06-11T14:22:09Z [INFO]   RDNSS servers advertised by fe80::1 (aa:bb:cc:dd:ee:ff): 2606:4700:4700::1111
2026-06-11T14:23:44Z [WARNING] [ALERT #1] ROGUE ROUTER ADVERTISEMENT | src=fe80::1 mac=de:ad:be:ef:00:01 | MAC changed from aa:bb:cc:dd:ee:ff to de:ad:be:ef:00:01 for router fe80::1
2026-06-11T14:23:44Z [WARNING] [ALERT #2] ROGUE RDNSS (DNS HIJACK VECTOR) | src=fe80::1 mac=de:ad:be:ef:00:01 | untrusted DNS server advertised: 2001:db8::53
```

---

## 🔗 Related Tools

| Repo | Description |
|---|---|
| [ndp_monitor.sh](https://github.com/microlaser/ndp_monitor.sh) | ICMPv6 NA monitor with nmap neighbor correlation |
| [net_exploit_detector](https://github.com/microlaser/net_exploit_detector) | 16-module behavioral anomaly detector (tcpdump/Python) |
| [wifi-guardian](https://github.com/microlaser/wifi-guardian) | Evil Twin / rogue AP detection (macOS) |
| [wifi-guardian-linux](https://github.com/microlaser/wifi-guardian-linux) | Linux port of wifi-guardian |
| [pff2](https://github.com/microlaser/pff2) | Hardened macOS pf firewall ruleset |

---

## ⚖️ Legal

This tool is intended for use on networks you own or have explicit authorization to monitor. Unauthorized packet capture may violate local laws.

---

## 📄 License

MIT
