from scapy.all import *
from collections import defaultdict
from colorama import Fore, Style, init
import time
import csv
import os

init(autoreset=True)

# =========================================================
# CREATE LOG FILES
# =========================================================

if not os.path.exists("attack_logs.csv"):
    with open("attack_logs.csv", "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Time", "Attack Type", "Source IP"])

if not os.path.exists("attack_logs.txt"):
    open("attack_logs.txt", "w").close()

# =========================================================
# PACKET COUNTERS
# =========================================================

total_packets = 0
tcp_packets = 0
udp_packets = 0
icmp_packets = 0

# =========================================================
# ATTACK TRACKING
# =========================================================

syn_count = defaultdict(int)
port_scan = defaultdict(set)

# =========================================================
# LOGGING FUNCTION
# =========================================================

def log_attack(attack_type, src_ip):

    # TXT LOG
    with open("attack_logs.txt", "a") as log:
        log.write(f"{time.ctime()} - {attack_type} from {src_ip}\n")

    # CSV LOG
    with open("attack_logs.csv", "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            time.ctime(),
            attack_type,
            src_ip
        ])

# =========================================================
# PACKET PROCESSING
# =========================================================

def process_packet(packet):

    global total_packets
    global tcp_packets
    global udp_packets
    global icmp_packets

    total_packets += 1

    print("=" * 70)

    # =====================================================
    # IP LAYER
    # =====================================================

    if packet.haslayer(IP):

        ip_layer = packet[IP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        protocol = "OTHER"

        src_port = "N/A"
        dst_port = "N/A"

        # =================================================
        # TCP
        # =================================================

        if packet.haslayer(TCP):

            tcp_packets += 1
            protocol = "TCP"

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            flags = packet[TCP].flags

            # =================================================
            # SYN FLOOD DETECTION
            # =================================================

            if "S" in str(flags):

                syn_count[src_ip] += 1

                if syn_count[src_ip] > 5:

                    print(Fore.RED + "[!!!] POSSIBLE SYN FLOOD DETECTED")
                    print(Fore.RED + f"Attacker IP : {src_ip}")
                    print(Fore.RED + f"SYN Count   : {syn_count[src_ip]}")

                    log_attack("SYN Flood", src_ip)

            # =================================================
            # PORT SCAN DETECTION
            # =================================================

            port_scan[src_ip].add(dst_port)

            if len(port_scan[src_ip]) > 3:

                print(Fore.YELLOW + "[!!!] POSSIBLE PORT SCAN DETECTED")
                print(Fore.YELLOW + f"Attacker IP  : {src_ip}")
                print(Fore.YELLOW + f"Ports Scanned: {len(port_scan[src_ip])}")

                log_attack("Port Scan", src_ip)

            # =================================================
            # SUSPICIOUS PORTS
            # =================================================

            suspicious_ports = [21, 22, 23, 3389]

            if dst_port in suspicious_ports:

                print(Fore.MAGENTA + "[!] Suspicious Destination Port Detected")

        # =================================================
        # UDP
        # =================================================

        elif packet.haslayer(UDP):

            udp_packets += 1
            protocol = "UDP"

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # =================================================
        # ICMP
        # =================================================

        elif packet.haslayer(ICMP):

            icmp_packets += 1
            protocol = "ICMP"

        # =================================================
        # FORCE LOGGING FOR TESTING
        # =================================================

        log_attack("Traffic Detected", src_ip)

        # =================================================
        # DISPLAY OUTPUT
        # =================================================

        print(Fore.CYAN + f"Time             : {time.strftime('%H:%M:%S')}")
        print(Fore.GREEN + f"Source IP        : {src_ip}")
        print(Fore.GREEN + f"Destination IP   : {dst_ip}")
        print(Fore.YELLOW + f"Protocol         : {protocol}")
        print(Fore.BLUE + f"Source Port      : {src_port}")
        print(Fore.BLUE + f"Destination Port : {dst_port}")

        print(Fore.WHITE + "Packet Statistics")
        print("-" * 30)

        print(Fore.CYAN + f"Total Packets : {total_packets}")
        print(Fore.GREEN + f"TCP Packets   : {tcp_packets}")
        print(Fore.YELLOW + f"UDP Packets   : {udp_packets}")
        print(Fore.MAGENTA + f"ICMP Packets  : {icmp_packets}")

    print("=" * 70)

# =========================================================
# MAIN
# =========================================================

print(Fore.MAGENTA + "=" * 70)
print(Fore.MAGENTA + "PurpleShield - Smart Traffic Analyzer")
print(Fore.MAGENTA + "=" * 70)

print(Fore.GREEN + "[*] Starting live traffic monitoring...")
print(Fore.MAGENTA + "=" * 70)

sniff(prn=process_packet, store=False)
