# ---------------------------------------------
# sniffer.py
# Advanced Network Sniffer – Live Packet Capture
# By Mahdi Zebardast Barzin
# ---------------------------------------------

from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import json
import os


# -------------------------------------------------------------
# 🇬🇧 English:
# This function captures network packets live using Scapy.
# It extracts essential info and stores them in a structured list.
#
# 🇮🇷 فارسی:
# این تابع پکت‌های شبکه را به‌صورت زنده شنود می‌کند،
# اطلاعات مهم هر پکت را استخراج کرده و در یک لیست ذخیره می‌کند.
# -------------------------------------------------------------

captured_packets = []  # ذخیره‌سازی پکت‌ها


def packet_handler(packet):
    """
    🇬🇧 Handle each captured packet and extract metadata.
    🇮🇷 پردازش هر پکت و استخراج اطلاعات مهم.
    """

    packet_info = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "protocol": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "length": len(packet)
    }

    # --- Identify protocol ---
    if packet.haslayer(TCP):
        packet_info["protocol"] = "TCP"
        packet_info["src_ip"] = packet[IP].src
        packet_info["dst_ip"] = packet[IP].dst
        packet_info["src_port"] = packet[TCP].sport
        packet_info["dst_port"] = packet[TCP].dport

    elif packet.haslayer(UDP):
        packet_info["protocol"] = "UDP"
        packet_info["src_ip"] = packet[IP].src
        packet_info["dst_ip"] = packet[IP].dst
        packet_info["src_port"] = packet[UDP].sport
        packet_info["dst_port"] = packet[UDP].dport

    elif packet.haslayer(ICMP):
        packet_info["protocol"] = "ICMP"
        packet_info["src_ip"] = packet[IP].src
        packet_info["dst_ip"] = packet[IP].dst

    # --- Save packet info ---
    captured_packets.append(packet_info)

    # Print live for debugging
    print(f"[{packet_info['protocol']}] {packet_info['src_ip']} -> {packet_info['dst_ip']}")


# -------------------------------------------------------------
# 🇬🇧 English:
# This function starts the sniffer and saves raw packets to JSON.
#
# 🇮🇷 فارسی:
# این تابع شنود شبکه را شروع کرده و خروجی خام پکت‌ها را در فایل JSON ذخیره می‌کند.
# -------------------------------------------------------------

def start_sniffing(interface=None, packet_count=0):
    """
    :param interface: 🇬🇧 Network interface name / 🇮🇷 نام کارت شبکه
    :param packet_count: 🇬🇧 Number of packets to capture (0 = infinite)
                         🇮🇷 تعداد پکت‌ها (صفر یعنی بی‌نهایت)
    """

    print("🔍 Starting live packet capture...")
    print("Press CTRL + C to stop.\n")

    sniff(
        iface=interface,
        prn=packet_handler,
        store=False,
        count=packet_count
    )

    # Save to file
    save_packets_to_json()


# -------------------------------------------------------------
# 🇬🇧 Save captured packet metadata into results/raw_packets.json
# 🇮🇷 ذخیره‌سازی تمام پکت‌های شنود شده در فایل JSON
# -------------------------------------------------------------

def save_packets_to_json():
    output_path = "results/raw_packets.json"

    # ایجاد پوشه اگر وجود نداشت
    os.makedirs("results", exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(captured_packets, f, indent=4, ensure_ascii=False)

    print(f"\n📁 Saved: {output_path}")
    print("✨ Packet capture completed!")


# -------------------------------------------------------------
# 🇬🇧 Script entry point
# 🇮🇷 نقطه شروع اجرای اسکریپت
# -------------------------------------------------------------

if __name__ == "__main__":
    start_sniffing(packet_count=0)   # 0 = run until stopped
