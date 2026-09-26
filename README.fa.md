# WG Bridge

[English](README.md) | **فارسی**

[![Tests](https://github.com/Alirezaafshar20/wg-bridge/actions/workflows/test.yml/badge.svg)](https://github.com/Alirezaafshar20/wg-bridge/actions/workflows/test.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

تانل مسیریابی‌شدهٔ WireGuard بین سرور ورودی ایران و کلاینت خروجی خارج. یک جفت Peer، ترافیک خروجی سرویس‌ها و پنل‌های مستقر روی سرور ایران را منتقل می‌کند.

```text
Users → Server (Iran / ingress) ⇄ WireGuard ⇄ Client (Outside / egress) → Internet
```

## Requirements

Ubuntu 22.04/24.04 یا Debian 12/13، دسترسی root، systemd، کرنل دارای WireGuard و IPv6 فعال، و IPv4 عمومی روی هر دو میزبان. UDP خروجی ایران به خارج و UDP ورودی پورت تانل روی خارج باید مجاز باشد؛ پورت پیش‌فرض خارج `51830` است. سایر وابستگی‌ها را نصب‌کننده از مخازن سیستم‌عامل نصب می‌کند.

```bash
apt-get update && apt-get install -y curl ca-certificates
```

## Install

```bash
curl --proto '=https' --tlsv1.2 -fsSL --retry 2 https://raw.githubusercontent.com/Alirezaafshar20/wg-bridge/v0.2.0/install.sh -o /root/wg-bridge-install.sh && bash /root/wg-bridge-install.sh
```

## پیکربندی

- **۱ — Server (Iran):** میزبان ورودی، پنل و مدیریت کاربران.
- **۲ — Client (Outside):** میزبان خروج ترافیک به اینترنت.

ابتدا **Client خارج** را راه‌اندازی کنید؛ سپس کد اتصال آن را در **Server ایران** وارد کنید. این نام‌ها نقش استقرار را مشخص می‌کنند؛ اتصال WireGuard از ایران به نقطهٔ مقابل در خارج آغاز می‌شود. کد اتصال حاوی کلید خصوصی است و برای یک جفت سرور استفاده می‌شود.

## مدیریت

```bash
wg-bridge
wg-bridge status
wg-bridge doctor
```

وضعیت، عیب‌یابی، راه‌اندازی مجدد، کد اتصال، توقف، شروع و حذف کامل از منو در دسترس‌اند. سرویس‌ها با راه‌اندازی سیستم فعال می‌شوند. توقف تانل، خروج اینترنتی مشمول تانل را مسدود نگه می‌دارد؛ پاسخ اتصال‌های مدیریتی ورودی و مسیرهای مستثنا برقرار می‌مانند.

## ارتقا

```bash
curl --proto '=https' --tlsv1.2 -fsSL --retry 2 https://raw.githubusercontent.com/Alirezaafshar20/wg-bridge/v0.2.0/install.sh -o /root/wg-bridge-install.sh && bash /root/wg-bridge-install.sh --upgrade
```

مدیر تانل به‌روز می‌شود و کلیدها، پیکربندی WireGuard و اتصال‌های فعال حفظ می‌شوند. نام نقش‌های نسخهٔ 0.1 به همان کارکرد ورودی و خروجی قبلی نگاشت می‌شود.

## حذف

```bash
wg-bridge uninstall
```

با `REMOVE` تأیید کنید. حذف از منو یا با `bash /root/wg-bridge-install.sh --uninstall` هم در دسترس است. تانل، کلیدها، قوانین فایروال و مسیریابی متعلق به ابزار، تنظیمات systemd، مدیر و فرمان اجرایی حذف می‌شوند. تنظیمات ثبت‌شدهٔ شبکه در صورت باقی‌بودن مقادیر تحت مدیریت ابزار بازگردانی می‌شوند؛ بسته‌های مشترک سیستم‌عامل باقی می‌مانند.

## نگهداری

```bash
journalctl -u wg-bridge-network -u wg-quick@wgb-exit --no-pager -n 60
```

MTU پیش‌فرض `1380` است. خروج IPv6 در صورت پشتیبانی خارج با NAT66 انجام می‌شود؛ در غیر این صورت ترافیک اینترنتی IPv6 مشمول تانل مسدود می‌شود. VPN دارای policy routing و firewalld فعال پذیرفته نمی‌شوند. nftables سفارشی، TProxy، چند WAN و DNAT ورودی نیازمند تنظیم مستقل‌اند. WireGuard به مسیر UDP سالم نیاز دارد و استتار پروتکل انجام نمی‌دهد.

[طراحی شبکه و مسیرهای مستثنا](docs/network.md) · [توسعه و آزمون](CONTRIBUTING.md) · [تغییرات نسخه‌ها](CHANGELOG.md) · [طرح ویدیوی فارسی](docs/video-fa.md)

مجوز [MIT](LICENSE)
