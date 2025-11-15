# ---------------------------------------------------
# report_builder.py
# Advanced Network Sniffer – HTML & JSON Report Builder
# By Mahdi Zebardast Barzin
# ---------------------------------------------------

import json
import os

# -------------------------------------------------------------
# 🇬🇧 Load analysis data from JSON produced by analyzer.py
# 🇮🇷 بارگذاری داده‌های تحلیل شده از فایل JSON تولید شده توسط analyzer.py
# -------------------------------------------------------------
def load_analysis(json_path="results/analysis.json"):
    if not os.path.exists(json_path):
        raise FileNotFoundError("❌ analysis.json not found!")

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return data

# -------------------------------------------------------------
# 🇬🇧 Load HTML template from templates folder
# 🇮🇷 بارگذاری قالب HTML از پوشه templates
# -------------------------------------------------------------
def load_template(template_path="templates/report_template.html"):
    if not os.path.exists(template_path):
        raise FileNotFoundError("❌ report_template.html not found!")

    with open(template_path, "r", encoding="utf-8") as f:
        html_template = f.read()

    return html_template

# -------------------------------------------------------------
# 🇬🇧 Build HTML report from analysis data
# 🇮🇷 ساخت گزارش HTML از داده‌های تحلیل
# -------------------------------------------------------------
def build_html_report(analysis_data, output_path="results/traffic_report.html"):
    template = load_template()

    # جایگذاری اطلاعات در قالب HTML
    html_content = template.replace("{{total_packets}}", str(analysis_data.get("total_packets", 0)))

    # Protocol usage
    protocol_html = ""
    for proto, count in analysis_data.get("protocol_usage", {}).items():
        protocol_html += f"<li>{proto}: {count}</li>\n"
    html_content = html_content.replace("{{protocol_usage}}", protocol_html)

    # Top Source IPs
    src_html = ""
    for ip, count in analysis_data.get("top_source_ips", []):
        src_html += f"<li>{ip}: {count}</li>\n"
    html_content = html_content.replace("{{top_source_ips}}", src_html)

    # Top Destination IPs
    dst_html = ""
    for ip, count in analysis_data.get("top_destination_ips", []):
        dst_html += f"<li>{ip}: {count}</li>\n"
    html_content = html_content.replace("{{top_destination_ips}}", dst_html)

    # Top Ports
    port_html = ""
    for port, count in analysis_data.get("top_ports", []):
        port_html += f"<li>{port}: {count}</li>\n"
    html_content = html_content.replace("{{top_ports}}", port_html)

    # ایجاد پوشه results اگر وجود ندارد
    os.makedirs("results", exist_ok=True)

    # ذخیره HTML
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"📁 HTML report saved: {output_path}")

# -------------------------------------------------------------
# 🇬🇧 Save analysis as JSON backup
# 🇮🇷 ذخیره نسخه پشتیبان JSON از تحلیل
# -------------------------------------------------------------
def save_json_report(analysis_data, output_path="results/traffic_report.json"):
    os.makedirs("results", exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(analysis_data, f, indent=4, ensure_ascii=False)

    print(f"📁 JSON report saved: {output_path}")

# -------------------------------------------------------------
# 🇬🇧 Script entry point for standalone usage
# 🇮🇷 نقطه شروع اجرای مستقل اسکریپت
# -------------------------------------------------------------
if __name__ == "__main__":
    print("🔍 Loading analysis data...")
    data = load_analysis()

    print("📄 Building HTML report...")
    build_html_report(data)

    print("💾 Saving JSON report backup...")
    save_json_report(data)

    print("✨ Report generation completed!")
