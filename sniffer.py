from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from colorama import Fore, init
from datetime import datetime
from collections import defaultdict

init(autoreset=True)

print(Fore.GREEN + "=" * 70)
print(Fore.GREEN + "PurpleShield - Smart Traffic Analyzer")
print(Fore.GREEN + "=" * 70)

# -----------------------------
# Protocol Counters
# -----------------------------
tcp_count = 0
udp_count = 0
icmp_count = 0
total_packets = 0

# -----------------------------
# Port Scan Detection
# -----------------------------
scan_tracker = defaultdict(set)
SCAN_THRESHOLD = 10

# -----------------------------
# SYN Flood Detection
# -----------------------------
syn_tracker = defaultdict(int)
SYN_THRESHOLD = 20

# -----------------------------
# Blocked IP Tracking
# -----------------------------
blocked_ips = set()

# -----------------------------
# Alert Tracking
# -----------------------------
scan_alerted_ips = set()
syn_alerted_ips = set()


# -----------------------------
# Simulated Blocking Function
# -----------------------------
def block_ip(ip):

    if ip not in blocked_ips:

        blocked_ips.add(ip)

        print(
            Fore.RED +
            f"\n[BLOCKED] Attacker IP blocked: {ip}"
        )


# -----------------------------
# Packet Processing Function
# -----------------------------
def process_packet(packet):

    global tcp_count
    global udp_count
    global icmp_count
    global total_packets

    total_packets += 1

    timestamp = datetime.now().strftime("%H:%M:%S")

    if IP in packet:

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        print(Fore.BLUE + "\n" + "=" * 70)
        print(Fore.YELLOW + f"Time             : {timestamp}")
        print(Fore.CYAN + f"Source IP        : {src_ip}")
        print(Fore.MAGENTA + f"Destination IP   : {dst_ip}")

        # -----------------------------
        # TCP TRAFFIC
        # -----------------------------
        if packet.haslayer(TCP):

            tcp_count += 1

            sport = packet[TCP].sport
            dport = packet[TCP].dport

            print(Fore.GREEN + "Protocol         : TCP")
            print(Fore.WHITE + f"Source Port      : {sport}")
            print(Fore.WHITE + f"Destination Port : {dport}")

            # -----------------------------
            # SYN Flood Detection Logic
            # -----------------------------
            tcp_flags = packet[TCP].flags

            if tcp_flags == "S":

                syn_tracker[src_ip] += 1

                if (
                    syn_tracker[src_ip] > SYN_THRESHOLD
                    and src_ip not in syn_alerted_ips
                ):

                    syn_alerted_ips.add(src_ip)

                    print(
                        Fore.RED +
                        "\n[!!!] POSSIBLE SYN FLOOD DETECTED"
                    )

                    print(
                        Fore.RED +
                        f"Attacker IP      : {src_ip}"
                    )

                    print(
                        Fore.RED +
                        f"SYN Packets      : {syn_tracker[src_ip]}"
                    )

                    block_ip(src_ip)

            # -----------------------------
            # Port Scan Detection Logic
            # -----------------------------
            scan_tracker[src_ip].add(dport)

            if (
                len(scan_tracker[src_ip]) > SCAN_THRESHOLD
                and src_ip not in scan_alerted_ips
            ):

                scan_alerted_ips.add(src_ip)

                print(
                    Fore.RED +
                    "\n[!!!] POSSIBLE PORT SCAN DETECTED"
                )

                print(
                    Fore.RED +
                    f"Attacker IP      : {src_ip}"
                )

                print(
                    Fore.RED +
                    f"Ports Scanned    : {len(scan_tracker[src_ip])}"
                )

                block_ip(src_ip)

            # -----------------------------
            # Suspicious Ports
            # -----------------------------
            suspicious_ports = [22, 23, 3389, 4444]

            if dport in suspicious_ports:

                print(
                    Fore.RED +
                    "[!] Suspicious Destination Port Detected"
                )

        # -----------------------------
        # UDP TRAFFIC
        # -----------------------------
        elif packet.haslayer(UDP):

            udp_count += 1

            sport = packet[UDP].sport
            dport = packet[UDP].dport

            print(Fore.YELLOW + "Protocol         : UDP")
            print(Fore.WHITE + f"Source Port      : {sport}")
            print(Fore.WHITE + f"Destination Port : {dport}")

        # -----------------------------
        # ICMP TRAFFIC
        # -----------------------------
        elif packet.haslayer(ICMP):

            icmp_count += 1

            print(Fore.RED + "Protocol         : ICMP")

        # -----------------------------
        # LIVE STATISTICS
        # -----------------------------
        print(Fore.GREEN + "\nPacket Statistics")
        print(Fore.GREEN + "-" * 30)

        print(Fore.WHITE + f"Total Packets : {total_packets}")
        print(Fore.WHITE + f"TCP Packets   : {tcp_count}")
        print(Fore.WHITE + f"UDP Packets   : {udp_count}")
        print(Fore.WHITE + f"ICMP Packets  : {icmp_count}")

        print(Fore.BLUE + "=" * 70)


print(Fore.YELLOW + "\n[*] Starting live traffic monitoring...\n")

sniff(
    iface="lo",
    prn=process_packet,
    store=False
)
