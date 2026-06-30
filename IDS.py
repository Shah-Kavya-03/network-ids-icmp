import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, ICMP, get_if_list
from collections import defaultdict
import threading


try:
    from scapy.arch.windows import get_windows_if_list
    WINDOWS = True
except ImportError:
    WINDOWS = False

icmp_count = defaultdict(int)
THRESHOLD = 10
running = False
ids_lock = threading.Lock()

def show_alert(message, color="white"):
    alert_box.config(state='normal')
    alert_box.insert(tk.END, message + "\n", color)
    alert_box.tag_config(color, foreground=color)
    alert_box.see(tk.END)
    alert_box.config(state='disabled')

def update_status(text, color):
    status_label.config(text=f"Status: {text}", fg=color)

def clear_logs():
    alert_box.config(state='normal')
    alert_box.delete(1.0, tk.END)
    alert_box.config(state='disabled')

def detect_packet(packet):
    global running
    if not running:
        return
    
    if not (packet.haslayer(ICMP) and packet.haslayer(IP)):
        return
    
    try:
        src = packet[IP].src
    except:
        except (AttributeError, IndexError) as e:
        show_alert(f"⚠ Could not parse packet: {e}", "#ffaa00")
        return
    
    icmp_count[src] += 1
    show_alert(f"ICMP Packet from {src} (Count: {icmp_count[src]})", "#00eaff")

    if icmp_count[src] >= THRESHOLD and icmp_count[src] % 3 == 0:
        how_alert(f"⚠ ALERT: Ping Flood from {src} (Count: {icmp_count[src]})", "#ff4d4d")


def start_ids():
    global running

    iface = interface_var.get()

    if not iface:
        show_alert("❌ Please select an interface!", "#ff4d4d")
        with ids_lock:
            running = False
        root.after(0, lambda: dropdown.config(state="readonly"))
        root.after(0, lambda: start_btn.config(state="normal"))
        root.after(0, lambda: update_status("Stopped", "#f40909"))
        return

    show_alert(f"✅ Using Interface: {iface}", "#00ff4c")
    show_alert("IDS Started... Monitoring ICMP Traffic...", "#00ff4c")

    while True:
        with ids_lock:
            if not running:
                break
        sniff(prn=detect_packet, store=0, iface=iface, filter="icmp", timeout=2)

def stop_ids():
    global running
    with ids_lock:
        running = False
    icmp_count.clear()

    dropdown.config(state="readonly")
    start_btn.config(state="normal")
    update_status("Stopped", "#f40909")

    show_alert("⛔ IDS Stopped. Counters Reset.", "#f40909")

def run_ids():
    global running
    with ids_lock:
        if running:
            return
        running = True
    dropdown.config(state="disabled")
    start_btn.config(state="disabled")
    update_status("Running", "#00ff4c")

    thread = threading.Thread(target=start_ids)
    thread.start()

root = tk.Tk()
root.title("Network IDS Dashboard")
root.geometry("850x550")
root.configure(bg="#0f172a")

title = tk.Label(root, text="⚡ Network Intrusion Detection System ⚡", font=("Arial", 16, "bold"), bg="#020617", fg="#00eaff", pady=12)
title.pack(fill="x")

frame_top = tk.Frame(root, bg="#0f172a")
frame_top.pack(pady=10)

tk.Label(frame_top, text="Select Interface:", font=("Arial", 11), bg="#0f172a", fg="white").grid(row=0, column=0, padx=5)

interfaces = get_if_list()
if WINDOWS:
    try:
        friendly = get_windows_if_list()
        descriptive = [i.get('name') or i.get('description') for i in friendly if i.get('name') or i.get('description')]
        if descriptive:
            interfaces = descriptive
    except Exception:
        pass

interface_var = tk.StringVar()

dropdown = ttk.Combobox(frame_top, textvariable=interface_var, width=55, state="readonly")
dropdown['values'] = interfaces
dropdown.grid(row=0, column=1, padx=5)

frame_buttons = tk.Frame(root, bg="#0f172a")
frame_buttons.pack(pady=10)

start_btn = tk.Button(frame_buttons, text="▶ Start IDS", command=run_ids, bg="#00ff9c", fg="black", width=15)
start_btn.grid(row=0, column=0, padx=10)

stop_btn = tk.Button(frame_buttons, text="⛔ Stop IDS", command=stop_ids, bg="#f40909", fg="white", width=15)
stop_btn.grid(row=0, column=1, padx=10)

clear_btn = tk.Button(frame_buttons, text="🧹 Clear Logs", command=clear_logs, bg="#00eaff", fg="black", width=15)
clear_btn.grid(row=0, column=2, padx=10)

status_label = tk.Label(root, text="Status: Stopped", font=("Arial", 12, "bold"), fg="#f40909", bg="#0f172a")
status_label.pack()

# Logs Frame
frame_logs = tk.Frame(root, bg="#0f172a")
frame_logs.pack(pady=10)

scrollbar = tk.Scrollbar(frame_logs)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

alert_box = tk.Text(frame_logs, height=20, width=100, bg="#020617", fg="white", insertbackground="white", state='disabled', yscrollcommand=scrollbar.set)

alert_box.pack()
scrollbar.config(command=alert_box.yview)

root.mainloop()
