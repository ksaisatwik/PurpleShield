# PurpleShield IDS

## Author
K SAI SATWIK

---

## Overview

PurpleShield IDS is a beginner-friendly Intrusion Detection System (IDS) developed using Python and Scapy.

The project monitors live network traffic, captures packets in real time, analyzes protocols, detects suspicious activities such as SYN Flood attacks and Port Scans, and stores attack logs for further analysis.

This project was built for learning cybersecurity, packet analysis, and network traffic monitoring.

---

## Features

- Live Packet Sniffing
- TCP Traffic Monitoring
- UDP Traffic Monitoring
- ICMP Packet Detection
- SYN Flood Detection
- Port Scan Detection
- Real-Time Packet Statistics
- TXT Attack Logging
- CSV Attack Logging
- Colorized Terminal Alerts
- Suspicious Traffic Detection
- Lightweight and Beginner Friendly

---

## Technologies Used

- Python
- Scapy
- Colorama
- CSV
- Kali Linux
- Git & GitHub

---

## Project Structure

```bash
PurpleShield/
│── sniffer.py
│── attack_logs.txt
│── attack_logs.csv
│── README.md
│── venv/
```

---

## Installation

### Clone the Repository

```bash
git clone https://github.com/ksaisatwik/PurpleShield.git
```

### Move into Project Folder

```bash
cd PurpleShield
```

### Create Virtual Environment

```bash
python3 -m venv venv
```

### Activate Virtual Environment

```bash
source venv/bin/activate
```

### Install Required Packages

```bash
pip install scapy colorama
```

---

## Running the Project

Start the Intrusion Detection System:

```bash
sudo python3 sniffer.py
```

---

## Testing the IDS

Open another terminal and run:

```bash
sudo nmap -sS -T4 -p 1-100 <your-ip>
```

Example:

```bash
sudo nmap -sS -T4 -p 1-100 10.51.66.195
```

---

## Attack Logs

Detected traffic and suspicious activity are stored in:

- `attack_logs.txt`
- `attack_logs.csv`

---

## Sample Detection Output

```text
[!] SYN Flood Attack Detected
Source IP: 192.168.1.10
Destination Port: 443
```

---

## Learning Objectives

This project helped in understanding:

- Packet Sniffing
- Network Protocols
- TCP/IP Basics
- Cybersecurity Monitoring
- Intrusion Detection Systems
- Network Traffic Analysis
- Python for Cybersecurity

---

## Future Improvements

- GUI Dashboard
- Machine Learning Detection
- Email Alerts
- Web Dashboard
- Real-Time Graphs
- Threat Intelligence Integration
- Multi-threaded Packet Processing

---

## License

This project is developed for educational and learning purposes.
