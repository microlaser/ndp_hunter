# IPv6 NDP Hunter 🕵️‍♂️🛡️

**NDP Hunter** is a lightweight, zero-configuration Python script designed to detect covert IPv6 Man-in-the-Middle (MitM) and DNS hijacking attacks on local networks. 

It sniffs the physical layer for anomalous **Neighbor Discovery Protocol (NDP)** traffic, specifically targeting rogue Router Advertisements (Rogue RAs) and Neighbor Advertisement spoofing.

## ⚠️ The Threat: IPv6 Local Network Hijacking

Even if your machine is configured to use secure IPv4 DNS servers, modern operating systems (Linux, macOS, Windows) default to preferring IPv6 over IPv4 (per RFC 6724). 

Because basic NDP lacks authentication, an attacker on the same local network (like public Wi-Fi) can broadcast a **Rogue Router Advertisement**. This tricks your machine into accepting the attacker's device as the local IPv6 router and, crucially, accepting the attacker's rogue IPv6 DNS server. Your DNS traffic is then silently hijacked, bypassing your secure IPv4 configurations entirely.

## ✨ Features

* **OS Agnostic:** Automatically detects macOS or Linux environments.
* **Auto-Binding:** Dynamically identifies the active routing interface (e.g., `en0` on Mac, `wlan0`/`eth0` on Linux) to begin capturing immediately.
* **Surgical Packet Inspection:** Leverages `tcpdump` with highly specific BPF filters to ignore background noise and isolate ICMPv6 Types 134 (Router Advertisement) and 136 (Neighbor Advertisement).
* **Layer 2 Visibility:** Exposes the source MAC addresses of the broadcasting devices, allowing you to definitively identify rogue hardware on the LAN.

## ⚙️ Prerequisites

* **Python 3.x**
* **tcpdump** must be installed and accessible in the system path.
  * *Debian/Ubuntu:* `sudo apt update && sudo apt install tcpdump`
  * *macOS:* Pre-installed by default.
* **Root Privileges:** Required for raw socket access and promiscuous network sniffing.

## 🚀 Usage

1. Clone the repository:
   ```bash
   git clone [https://github.com/yourusername/ipv6-ndp-hunter.git](https://github.com/yourusername/ipv6-ndp-hunter.git)
   cd ipv6-ndp-hunter
