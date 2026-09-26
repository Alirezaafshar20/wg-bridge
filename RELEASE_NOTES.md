# WG Bridge v0.3.0

WG Bridge now forwards **one selected IPv4 service port** from Iran to a service on Outside through WireGuard. The installer suggests available random ports, with configurable public/target ports and **TCP, UDP or both**.

- Remove full-host routing, WireGuard default routes, policy marks, the dummy sink and IPv6 egress changes. Ordinary host Internet traffic keeps its route.
- Keep the selected mapping isolated when the peer or tunnel is down; unrelated inbound services and LAN forwarding continue to use their existing paths.
- Add Iran public-port editing through the menu or `wg-bridge port PORT`.
- Use **WGB2** pairing to carry the target port and protocol. The destination application runs on Outside and must accept the private tunnel address.
- Add visible pairing input, clearer step explanations, colored “Press Enter to use …” defaults and a grouped menu opened directly with `wg-bridge`. Retain the alirezaw creator links and Ubuntu 26.04.1 support.

**Migration:** v0.1/v0.2 full-routing installations require uninstall/reinstall on both hosts. On Iran, stop `wg-quick@wgb-exit.service` and `wg-bridge-network.service` to restore direct Internet first. Remove the old tunnel with `wg-bridge uninstall`, then install Outside followed by Iran with a fresh WGB2 code. `--upgrade` rejects legacy state before modifying the installed manager; it remains available for compatible v0.3 installations.

Validation covers real TCP/UDP forwarding, host route preservation, peer failure, stopped interfaces, port changes, lifecycle rollback and complete removal on Ubuntu 22.04, 24.04 and 26.04. This remains a preview release; correctness tests do not establish production capacity.

[English](https://github.com/itsalirezaw/wg-bridge#readme) · [فارسی](https://github.com/itsalirezaw/wg-bridge/blob/main/README.fa.md)

<details>
<summary>توضیحات فارسی</summary>

نسخهٔ 0.3 فقط یک پورت IPv4 انتخابی ایران را از داخل WireGuard به سرویس خارج منتقل می‌کند. پورت‌های آزاد تصادفی پیشنهاد می‌شوند و پورت ورودی، پورت مقصد و TCP/UDP قابل انتخاب‌اند. کد اتصال هنگام ورود دیده می‌شود و پیش‌فرض‌های رنگی با راهنمای Enter نمایش داده می‌شوند. منو مستقیماً با `wg-bridge` باز می‌شود. مسیر اینترنت عمومی و IPv6 سرور تغییر نمی‌کند؛ قطع تانل فقط همان نگاشت را از دسترس خارج می‌کند. تغییر پورت ایران از منو یا فرمان `wg-bridge port PORT` ممکن است.

برای انتقال از 0.1 یا 0.2 ابتدا هر دو سرویس WG Bridge را روی ایران متوقف کنید، تانل قدیمی را روی هر دو سمت حذف کنید و نصب جدید را از خارج شروع کنید. کد جدید WGB2 لازم است؛ کد WGB1 قابل استفاده نیست. برنامهٔ مقصد باید روی خارج فعال باشد. راهنمای دقیق در README فارسی آمده است.

</details>
