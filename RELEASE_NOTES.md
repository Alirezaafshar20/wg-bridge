# WG Bridge v0.1.0 — initial preview

An independent WireGuard tunnel between two servers. Select Server on the outside exit and Client on the Iran entry. No panel or end-user VPN profiles are created.

- Automatic dependency installation, key generation and setup through a secret pairing code.
- Internet egress through the outside server, with incoming connections' reply paths preserved.
- IPv4 and IPv6, with outgoing IPv6 blocked when the exit has no IPv6 route.
- Automatic startup, status, diagnostics, safe stop, restart and uninstall.
- English documentation by default, a complete Persian guide and a Persian video outline.

Real WireGuard namespace tests cover TCP/UDP, IPv4/IPv6, forwarded traffic, existing/new incoming TCP, tunnel stop/restart, IPv6 blocking and cleanup. 300 HTTP requests with 40 workers test routing correctness; they are not a production capacity benchmark. CI also exercises actual installer/systemd lifecycle on disposable Ubuntu VMs.

This is the initial preview release. Plain WireGuard requires a working UDP path; it does not provide transport obfuscation. One pairing code is for exactly one server pair. Existing policy-routing VPNs and active firewalld are rejected. Read the routing exceptions and integration limits before deployment.

[English installation guide](https://github.com/Alirezaafshar20/wg-bridge#readme) · [راهنمای فارسی](https://github.com/Alirezaafshar20/wg-bridge/blob/main/README.fa.md)

<details>
<summary>توضیحات فارسی</summary>

تانل مستقل WireGuard بین دو سرور، با نصب سادهٔ Server روی خارج و Client روی ایران. هیچ پنل یا کانفیگ کاربری ساخته نمی‌شود.

- نصب وابستگی‌ها، تولید کلید و انتقال تنظیمات با کد اتصال محرمانه.
- خروج ترافیک عادی ایران و شبکه‌های پشت آن از خارج؛ حفظ مسیر پاسخ اتصال‌های ورودی.
- IPv4 و IPv6، یا مسدودکردن خروج IPv6 در صورت نبود مسیر خارج.
- شروع خودکار، وضعیت، عیب‌یابی، توقف امن، شروع مجدد و حذف تنظیمات.
- راهنمای انگلیسی پیش‌فرض، راهنمای کامل فارسی و طرح ویدیوی آموزشی فارسی.

آزمون‌ها شامل TCP/UDP، IPv4/IPv6، ترافیک عبوری، حفظ اتصال‌های ورودی، توقف و شروع مجدد، مسدودکردن IPv6 و پاک‌سازی هستند. تست ۳۰۰ درخواست با ۴۰ worker، بنچمارک ظرفیت کاربران واقعی نیست. نصب و سرویس‌های systemd هم روی ماشین‌های آزمایشی Ubuntu بررسی می‌شوند.

این اولین نسخهٔ آزمایشی است. ارتباط نیازمند مسیر UDP سالم است و استتار ترافیک ندارد. هر کد اتصال فقط برای یک جفت سرور است. VPN دارای policy routing و firewalld فعال پذیرفته نمی‌شوند؛ پیش از نصب، محدودیت‌ها و مسیرهای مستثنا را بخوانید.

</details>
