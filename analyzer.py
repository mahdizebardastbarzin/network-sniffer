# ---------------------------------------------------
# analyzer.py
# Advanced Network Sniffer – Traffic Analyzer Module
# By Mahdi Zebardast Barzin
# ---------------------------------------------------

import json
from collections import Counter
import os


# -------------------------------------------------------------
# 🇬🇧 English:
# Load raw captured packets stored by sniffer.py.
#
# 🇮🇷 فارسی:
# بارگذاری پکت‌های خام ذخیره شده در فایل JSON.
# -------------------------------------------------------------
def load_packets(json_path="results/raw_packets.json"):
    if not os.path.exists(json_path):
        raise FileNotFoundError("❌ raw_packets.json not found!")

    with open(json_path, "r", encoding="utf-8") as f:
        packets = json.load(f)

    return packets


# -------------------------------------------------------------
# 🇬🇧 English:
# Analyze protocols, IP traffic, ports and detect heavy traffic.
#
# 🇮🇷 فارسی:
# تحلیل پروتکل‌ها، ترافیک IP، پورت‌ها و شناسایی نقاط پرترافیک.
# -------------------------------------------------------------
def analyze_packets(packets):

    protocol_list = []
    src_ips = []
    dst_ips = []
    ports = []

    for pkt in packets:
        protocol_list.append(pkt["protocol"])

        if pkt["src_ip"]:
            src_ips.append(pkt["src_ip"])
        if pkt["dst_ip"]:
            dst_ips.append(pkt["dst_ip"])

        if pkt["src_port"]:
            ports.append(pkt["src_port"])
        if pkt["dst_port"]:
            ports.append(pkt["dst_port"])

    analysis = {
        "total_packets": len(packets),
        "protocol_usage": Counter(protocol_list),
        "top_source_ips": Counter(src_ips).most_common(10),
        "top_destination_ips": Counter(dst_ips).most_common(10),
        "top_ports": Counter(ports).most_common(10),
    }

    return analysis


# -------------------------------------------------------------
# 🇬🇧 English:
# Save analysis results into JSON for later HTML reporting.
#
# 🇮🇷 فارسی:
# ذخیره نتایج تحلیل در فایل JSON برای ساخت گزارش HTML.
# -------------------------------------------------------------
def save_analysis(analysis_data, output_path="results/analysis.json"):

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(analysis_data, f, indent=4, ensure_ascii=False)

    print(f"📁 Analysis saved to {output_path}")


# -------------------------------------------------------------
# 🇬🇧 Script entry point for standalone usage
# 🇮🇷 نقطه اجرای مستقل اسکریپت
# -------------------------------------------------------------
if __name__ == "__main__":
    print("🔍 Loading captured packets...")
    packets = load_packets()

    print("📊 Analyzing traffic...")
    results = analyze_packets(packets)

    print("💾 Saving analysis...")
    save_analysis(results)

    print("✨ Analysis completed!")
