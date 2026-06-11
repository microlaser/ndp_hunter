#!/usr/bin/env python3
import subprocess
import sys
import platform
import os
import signal

def check_privileges():
    """Ensure the script is executed with root privileges for raw socket access."""
    if os.geteuid() != 0:
        print("[-] Privilege escalation required. Please execute with sudo.")
        sys.exit(1)

def get_active_interface(os_type):
    """Determine the active network interface routing traffic."""
    if os_type == "Darwin":
        # macOS: typically en0 for Wi-Fi, but we can extract the default route
        try:
            route_out = subprocess.check_output("route -n get default", shell=True).decode()
            for line in route_out.split('\n'):
                if "interface:" in line:
                    return line.split(':')[1].strip()
        except Exception:
            return "en0"
            
    elif os_type == "Linux":
        # Linux: extract the interface attached to the default route
        try:
            route_out = subprocess.check_output("ip route list default", shell=True).decode()
            return route_out.split()[4]
        except Exception:
            print("[-] Could not auto-detect Linux interface. Defaulting to 'any'.")
            return "any"
    else:
        print(f"[-] Unsupported OS: {os_type}")
        sys.exit(1)

def main():
    check_privileges()
    
    os_type = platform.system()
    interface = get_active_interface(os_type)
    
    print(f"[*] Initializing ICMPv6 anomaly detection on interface: {interface}")
    print("[*] Listening for Router Advertisements (Rogue RAs) and Neighbor Spoofing...")
    print("[*] Press Ctrl+C to terminate.\n")
    print("-" * 70)

    # tcpdump flags breakdown:
    # -i : Interface to listen on
    # -n : Do not resolve IP addresses to hostnames (prevents DNS leak/delay)
    # -e : Print the link-level header (crucial for capturing the source MAC address)
    # -vvv : Maximum verbosity to see the ICMPv6 payload (prefixes, MTU, DNS payload)
    # Filter: Capture only ICMPv6 Router Advertisements and Neighbor Advertisements
    
    bpf_filter = "icmp6 and (icmp6[icmp6type] == icmp6-routeradvert or icmp6[icmp6type] == icmp6-neighboradvert)"
    
    cmd = [
        "tcpdump", 
        "-i", interface, 
        "-n", "-e", "-vvv", 
        bpf_filter
    ]

    try:
        # We use Popen so we can gracefully handle the termination
        process = subprocess.Popen(cmd)
        process.wait()
    except KeyboardInterrupt:
        print("\n[*] Terminating packet capture...")
        process.terminate()
        sys.exit(0)
    except FileNotFoundError:
        print("[-] tcpdump is not installed or not in the system PATH.")
        sys.exit(1)

if __name__ == "__main__":
    main()
