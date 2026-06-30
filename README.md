# Network IDS — ICMP Flood Detector

A lightweight, GUI-based Intrusion Detection System (IDS) built with Python, Scapy, and Tkinter. It sniffs live ICMP traffic on a selected network interface and raises real-time alerts when it detects ping flood behavior from a host.

## Features

- Live packet sniffing on any available network interface
- Real-time ICMP packet logging with per-source counters
- Automatic ping flood detection based on a configurable threshold
- Color-coded alert console (info, success, warning)
- Simple Start / Stop / Clear Logs controls
- Built with a dark-themed Tkinter dashboard

## How It Works

The application uses Scapy to passively sniff ICMP packets on the chosen interface. For every ICMP packet, it tracks how many times each source IP has pinged the host. If a source crosses a defined threshold (`THRESHOLD = 10` by default), the app flags it as a potential ping flood and displays a warning in the log console.

## Requirements

- Python 3.8+
- [Scapy] (https://scapy.net/)
- Tkinter (usually bundled with Python)
- Administrator/root privileges (required for packet sniffing)

Install dependencies:

pip install scapy

## Usage

1. Clone the repository:
   git clone https://github.com/Shah-Kavya-03/network-ids-icmp.git
   cd network-ids-icmp

2. Run the application with elevated privileges (required for raw packet capture):

   **Windows (run as Administrator):**
   python IDS.py

   **Linux/macOS:**
   sudo python3 IDS.py

3. In the GUI:
   - Select a network interface from the dropdown
   - Click **▶ Start IDS** to begin monitoring
   - Watch the log console for ICMP activity and flood alerts
   - Click **⛔ Stop IDS** to stop monitoring and reset counters
   - Click **🧹 Clear Logs** to clear the console output

## Configuration

You can adjust detection sensitivity by changing the threshold value in `Networking.py`:

THRESHOLD = 10  # Number of ICMP packets from a single source before flagging

## Disclaimer

This project is intended for educational purposes and authorized network monitoring only. Do not use it to monitor networks you do not own or have explicit permission to test. Packet sniffing may require elevated/root privileges and may be subject to local laws and organizational policies.

## License

This project is licensed under the MIT License.
