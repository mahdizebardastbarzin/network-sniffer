# 🕵️‍♂️ Advanced Network Sniffer  
**Live Network Monitoring & Traffic Analysis Tool**  
**ابزار حرفه‌ای برای مانیتورینگ زنده شبکه و تحلیل ترافیک**

---

## 🧰 Features | ویژگی‌ها
- 🖥️ **Live Packet Capture / شنود زنده پکت‌ها**  
- 🌐 **Protocol & IP Traffic Analysis / تحلیل پروتکل‌ها و ترافیک IP**  
- ⚡ **Top Ports & Heavy Traffic Detection / شناسایی پورت‌های پرترافیک**  
- 📊 **Generate JSON & HTML Reports / تولید گزارش‌های JSON و HTML**  

---

## 📁 Project Structure | ساختار پروژه
```
network-sniffer/
│── sniffer.py
│── analyzer.py
│── report_builder.py
│── reports/
│    ├── traffic_report.json
│    ├── traffic_report.html
│── README.md
```

---

# ⚙️ Installation (Windows) | نصب در ویندوز

برای جلوگیری از خطای زیر در ویندوز:

```
WARNING: No libpcap provider available!
RuntimeError: winpcap is not installed
```

دو راه داری:

---

# ✅ روش 1: نصب Npcap (پیشنهادی) | Npcap Installation (Recommended)
**Npcap نسخه جدید و رسمی WinPcap برای ویندوز است.**

### 1️⃣ دانلود Npcap  
به سایت رسمی برو:  
https://nmap.org/npcap/

### 2️⃣ اجرای نصب
در هنگام نصب حتماً تیک زیر را بزن:

✔️ **Install Npcap in WinPcap API-compatible Mode**

### 3️⃣ ریستارت ویندوز  
پس از نصب، سیستم را ریستارت کن.

---

# ✅ روش 2: اجرای Sniffer روی لایه ۳ (بدون نیاز به Npcap) | Alternative: Layer 3 Mode
اگر نمی‌خوای Npcap نصب کنی، می‌تونی از Scapy در **لایه IP (لایه ۳)** استفاده کنی.

در این حالت فقط بسته‌های IP Capture می‌شن و لایه 2 (Ethernet) غیرفعال خواهد بود.

در فایل `sniffer.py` این بخش را اضافه کن:

```python
from scapy.config import conf
conf.sniff_promisc = False     # Disable layer-2 promiscuous mode
conf.use_pcap = False          # Force Scapy to use layer-3 sockets
```

---

# 💻 Installing Required Libraries | نصب کتابخانه‌ها

### 1️⃣ Python 3.8+  
حتماً نسخه پایتون ۳.۸ یا بالاتر.

### 2️⃣ نصب Scapy  
```bash
pip install scapy
```

---

# 🚀 Usage | نحوه استفاده

## ▶️ 1. Start Live Sniffer | اجرای شنود زنده
```bash
python sniffer.py
```
## Stop and Save: Ctrl + c

## ▶️ 2. Run Traffic Analyzer | اجرای تحلیلگر ترافیک
```bash
python analyzer.py
```

## ▶️ 3. Generate JSON & HTML Report | ساخت گزارش‌ها
```bash
python report_builder.py
```

گزارش‌ها در این مسیر ذخیره می‌شن:

```
/reports/traffic_report.json
/reports/traffic_report.html
```

---

# 🛠 Notes | نکات مهم

- برای شنود لایه ۲ روی ویندوز **حتماً باید Npcap نصب باشد**.  
- روی لینوکس نیاز به هیچ کاری نیست.  
- برای خروج از Sniffer از **CTRL + C** استفاده کن.  

---

# ⭐ Author | نویسنده  
**Mahdi Zebardast Barzin**  
- Website: https://madresema.ir  
- Email: mr.mahdizebardast@gmail.com  
- Phone: +98-922-478-9838  
- GitHub: https://github.com/mahdizebardastbarzin  
- Instagram: https://www.instagram.com/madresema.ir/  
- Telegram: https://t.me/info_madresema
