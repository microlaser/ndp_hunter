#!/usr/bin/env python3
"""
ndp_hunter.py — IPv6 NDP anomaly detector
Detects rogue Router Advertisements and DNS hijacking via RDNSS option inspection.
Requires: scapy (pip install scapy), root privileges.
"""

import os
import sys
import json
import signal
import logging
import argparse
import platform
import subprocess
from datetime import datetime, timezone
from collections import defaultdict

try:
    from scapy.all import (
        sniff, IPv6, ICMPv6ND_RA, ICMPv6ND_NA,
        ICMPv6NDOptPrefixInfo, ICMPv6NDOptRDNSS,
        ICMPv6NDOptSrcLLAddr, Ether
    )
except ImportError:
    print("[-] scapy is required: pip install scapy")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

LOG_FILE = "/var/log/ndp_hunter.log"

def setup_logging(verbose: bool, logfile: str) -> logging.Logger:
    logger = logging.getLogger("ndp_hunter")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%dT%H:%M:%SZ")

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    try:
        fh = logging.FileHandler(logfile)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except PermissionError:
        logger.warning(f"Cannot write to {logfile} — file logging disabled.")

    return logger


# ---------------------------------------------------------------------------
# Baseline state
# ---------------------------------------------------------------------------

class NDPState:
    """Tracks observed router MACs, prefixes, and RDNSS servers per interface."""

    def __init__(self, trusted_routers: list[str], trusted_rdnss: list[str]):
        # Normalize to lowercase
        self.trusted_routers  = {m.lower() for m in trusted_routers}
        self.trusted_rdnss    = {ip.lower() for ip in trusted_rdnss}

        # Learned at runtime: first-seen router MAC per src-IP becomes baseline
        # if no --trusted-routers supplied
        self.seen_routers: dict[str, str] = {}       # src_ip -> mac
        self.seen_rdnss:   dict[str, set] = defaultdict(set)  # src_ip -> {rdnss}
        self.alert_count   = 0

    def is_rogue_router(self, src_ip: str, mac: str) -> tuple[bool, str]:
        mac = mac.lower()
        if self.trusted_routers:
            if mac not in self.trusted_routers:
                return True, f"MAC {mac} not in trusted router list"
            return False, ""

        # Auto-baseline: first RA from a src_ip locks in the expected MAC
        if src_ip not in self.seen_routers:
            self.seen_routers[src_ip] = mac
            return False, ""

        if self.seen_routers[src_ip] != mac:
            return True, (f"MAC changed from {self.seen_routers[src_ip]} to {mac} "
                          f"for router {src_ip}")
        return False, ""

    def is_rogue_rdnss(self, src_ip: str, rdnss_addrs: list[str]) -> list[str]:
        rogues = []
        for addr in rdnss_addrs:
            addr = addr.lower()
            if self.trusted_rdnss and addr not in self.trusted_rdnss:
                rogues.append(addr)
            elif addr not in self.seen_rdnss[src_ip]:
                # First time seeing this RDNSS from this router — log but don't alert
                self.seen_rdnss[src_ip].add(addr)
        return rogues


# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------

def get_active_interface() -> str:
    os_type = platform.system()
    if os_type == "Darwin":
        try:
            out = subprocess.check_output(
                ["route", "-n", "get", "default"], stderr=subprocess.DEVNULL
            ).decode()
            for line in out.splitlines():
                if "interface:" in line:
                    return line.split(":")[1].strip()
        except Exception:
            pass
        return "en0"
    elif os_type == "Linux":
        try:
            out = subprocess.check_output(
                ["ip", "route", "list", "default"], stderr=subprocess.DEVNULL
            ).decode()
            parts = out.split()
            # "default via <gw> dev <iface> ..."
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
        except Exception:
            pass
        # Do NOT fall back to "any" — MAC addresses are invisible on cooked captures
        print("[-] Could not auto-detect interface. Use -i <interface>.")
        sys.exit(1)
    else:
        print(f"[-] Unsupported OS: {os_type}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Packet handlers
# ---------------------------------------------------------------------------

def handle_ra(pkt, state: NDPState, logger: logging.Logger) -> None:
    """Process ICMPv6 Router Advertisement packets."""
    if not pkt.haslayer(ICMPv6ND_RA):
        return

    src_ip  = pkt[IPv6].src if pkt.haslayer(IPv6) else "unknown"
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "unknown"
    ts      = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    logger.debug(f"RA  src={src_ip} mac={src_mac}")

    # --- Router MAC check ---
    rogue_router, reason = state.is_rogue_router(src_ip, src_mac)
    if rogue_router:
        state.alert_count += 1
        logger.warning(
            f"[ALERT #{state.alert_count}] ROGUE ROUTER ADVERTISEMENT | "
            f"src={src_ip} mac={src_mac} | {reason}"
        )

    # --- Prefix extraction (informational) ---
    prefixes = []
    layer = pkt
    while layer:
        if isinstance(layer, ICMPv6NDOptPrefixInfo):
            prefixes.append(f"{layer.prefix}/{layer.prefixlen}")
        layer = layer.payload if hasattr(layer, "payload") else None

    if prefixes:
        logger.debug(f"  Advertised prefixes: {', '.join(prefixes)}")

    # --- RDNSS option check (RFC 6106) — the DNS hijack vector ---
    rdnss_addrs = []
    layer = pkt
    while layer:
        if isinstance(layer, ICMPv6NDOptRDNSS):
            for addr in layer.dns:
                rdnss_addrs.append(str(addr))
        layer = layer.payload if hasattr(layer, "payload") else None

    if rdnss_addrs:
        logger.info(f"  RDNSS servers advertised by {src_ip} ({src_mac}): "
                    f"{', '.join(rdnss_addrs)}")
        rogues = state.is_rogue_rdnss(src_ip, rdnss_addrs)
        for rogue in rogues:
            state.alert_count += 1
            logger.warning(
                f"[ALERT #{state.alert_count}] ROGUE RDNSS (DNS HIJACK VECTOR) | "
                f"src={src_ip} mac={src_mac} | "
                f"untrusted DNS server advertised: {rogue}"
            )


def handle_na(pkt, state: NDPState, logger: logging.Logger) -> None:
    """Process ICMPv6 Neighbor Advertisement packets (spoof detection)."""
    if not pkt.haslayer(ICMPv6ND_NA):
        return

    src_ip  = pkt[IPv6].src if pkt.haslayer(IPv6) else "unknown"
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "unknown"
    target  = str(pkt[ICMPv6ND_NA].tgt)

    # Solicited=0 + Override=1 is a hallmark of NA spoofing
    ra_layer = pkt[ICMPv6ND_NA]
    solicited = bool(ra_layer.S)
    override  = bool(ra_layer.O)

    if not solicited and override:
        state.alert_count += 1
        logger.warning(
            f"[ALERT #{state.alert_count}] UNSOLICITED NA WITH OVERRIDE (spoof indicator) | "
            f"src={src_ip} mac={src_mac} | target={target}"
        )
    else:
        logger.debug(f"NA  src={src_ip} mac={src_mac} target={target} "
                     f"S={int(solicited)} O={int(override)}")


def packet_callback(pkt, state: NDPState, logger: logging.Logger) -> None:
    if pkt.haslayer(ICMPv6ND_RA):
        handle_ra(pkt, state, logger)
    elif pkt.haslayer(ICMPv6ND_NA):
        handle_na(pkt, state, logger)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="ndp_hunter — IPv6 Rogue RA / DNS Hijack Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 ndp_hunter.py
  sudo python3 ndp_hunter.py -i eth0 --trusted-router aa:bb:cc:dd:ee:ff
  sudo python3 ndp_hunter.py -i wlan0 --trusted-rdnss 2606:4700:4700::1111 --verbose
  sudo python3 ndp_hunter.py --dump-state
"""
    )
    p.add_argument("-i", "--interface",
                   help="Network interface to sniff (default: auto-detect)")
    p.add_argument("--trusted-router", dest="trusted_routers", action="append",
                   default=[], metavar="MAC",
                   help="Trusted router MAC address (repeat for multiple). "
                        "Any RA from an unlisted MAC triggers an alert.")
    p.add_argument("--trusted-rdnss", dest="trusted_rdnss", action="append",
                   default=[], metavar="IPv6",
                   help="Trusted RDNSS (DNS) server IPv6 address (repeat for multiple). "
                        "Any RDNSS option containing an unlisted address triggers an alert.")
    p.add_argument("--logfile", default=LOG_FILE, metavar="PATH",
                   help=f"Log file path (default: {LOG_FILE})")
    p.add_argument("--dump-state", action="store_true",
                   help="Print observed router/RDNSS state on Ctrl+C and exit")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show all packets, not just alerts")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if os.geteuid() != 0:
        print("[-] Root privileges required (raw socket access). Run with sudo.")
        sys.exit(1)

    args   = parse_args()
    logger = setup_logging(args.verbose, args.logfile)
    state  = NDPState(args.trusted_routers, args.trusted_rdnss)

    iface = args.interface or get_active_interface()

    logger.info(f"ndp_hunter starting | interface={iface}")
    logger.info(f"Trusted routers : {args.trusted_routers or ['(auto-baseline)']}")
    logger.info(f"Trusted RDNSS   : {args.trusted_rdnss   or ['(log new, no alert)']}")
    logger.info(f"Log file        : {args.logfile}")
    logger.info("Monitoring for ICMPv6 RA (type 134) and NA (type 136). Ctrl+C to stop.")
    print("-" * 70)

    bpf = "icmp6 and (icmp6[icmp6type] == 134 or icmp6[icmp6type] == 136)"

    def _shutdown(sig, frame):
        print()
        logger.info(f"Shutting down. Total alerts: {state.alert_count}")
        if args.dump_state:
            print("\n--- Observed State ---")
            print("Routers (src_ip -> MAC):")
            for ip, mac in state.seen_routers.items():
                print(f"  {ip:40s}  {mac}")
            print("RDNSS servers (router src_ip -> DNS addrs):")
            for ip, addrs in state.seen_rdnss.items():
                for addr in addrs:
                    print(f"  {ip:40s}  {addr}")
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    sniff(
        iface=iface,
        filter=bpf,
        prn=lambda pkt: packet_callback(pkt, state, logger),
        store=False
    )


if __name__ == "__main__":
    main()
