# WG Bridge v0.1.0 — initial preview

تانل مستقل WireGuard بین دو سرور، با نصب سادهٔ Server روی خارج و Client روی ایران. هیچ پنل یا کانفیگ کاربری ساخته نمی‌شود.

- نصب وابستگی‌ها، تولید کلید و انتقال تنظیمات با کد اتصال محرمانه.
- خروج ترافیک عادی ایران و شبکه‌های پشت آن از خارج؛ حفظ مسیر پاسخ اتصال‌های ورودی.
- IPv4 و IPv6، یا مسدودکردن خروج IPv6 در صورت نبود مسیر خارج.
- شروع خودکار، وضعیت، عیب‌یابی، توقف امن، شروع مجدد و حذف تنظیمات.
- راهنمای فارسی و انگلیسی و طرح ویدیوی آموزشی.

Real WireGuard namespace tests cover TCP/UDP, IPv4/IPv6, forwarded traffic, existing/new incoming TCP, tunnel stop/restart, IPv6 blocking and cleanup. 300 HTTP requests with 40 workers test routing correctness; they are not a production capacity benchmark. CI also exercises actual installer/systemd lifecycle on disposable Ubuntu VMs.

This is the initial preview release. Plain WireGuard requires a working UDP path; it does not provide transport obfuscation. One pairing code is for exactly one server pair. Existing policy-routing VPNs and active firewalld are rejected. Read the routing exceptions and integration limits before deployment.

[نصب و راهنمای فارسی](https://github.com/Alirezaafshar20/wg-bridge#readme) · [English guide](https://github.com/Alirezaafshar20/wg-bridge/blob/main/README.en.md)
