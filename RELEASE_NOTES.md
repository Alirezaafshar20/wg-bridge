# WG Bridge v0.2.0

- **Server (Iran)** is the ingress and panel host; **Client (Outside)** provides Internet egress.
- New installations use explicit `entry`/`exit` state. Existing v0.1 roles and pairing codes remain compatible; the transport direction and routing are preserved.
- `install.sh --upgrade` updates the manager without replacing keys or restarting the tunnel.
- Full uninstall removes owned network configuration, keys, services, manager and launcher. Use the menu, `wg-bridge uninstall` or `install.sh --uninstall`.
- English and Persian documentation now use separate Requirements and Install commands with operational details in dedicated sections.

Validation includes real WireGuard network tests and Ubuntu 22.04/24.04 installer lifecycle tests, including legacy upgrade, removal cancellation, rollback and full uninstall. This remains a preview release; correctness tests do not establish production throughput or user capacity.

[English documentation](https://github.com/Alirezaafshar20/wg-bridge#readme) · [فارسی](https://github.com/Alirezaafshar20/wg-bridge/blob/main/README.fa.md) · [Changelog](https://github.com/Alirezaafshar20/wg-bridge/blob/main/CHANGELOG.md)

<details>
<summary>توضیحات فارسی</summary>

در نسخهٔ 0.2، ایران با نقش Server و خارج با نقش Client نمایش داده می‌شوند. مسیر ترافیک و جهت آغاز ارتباط WireGuard حفظ شده‌اند و تنظیمات نسخهٔ قبلی همچنان سازگارند.

ارتقای مدیر بدون تعویض کلیدها یا راه‌اندازی مجدد تانل انجام می‌شود. حذف کامل از منو، فرمان `wg-bridge uninstall` و گزینهٔ `--uninstall` نصب‌کننده در دسترس است. راهنماهای فارسی و انگلیسی بازنویسی شده‌اند و Requirements و Install دستورهای جدا دارند.

تست‌های شبکه و نصب روی Ubuntu 22.04 و 24.04 شامل سازگاری نسخهٔ قبلی، لغو حذف، بازگردانی نصب ناموفق و حذف کامل هستند. این انتشار همچنان آزمایشی است؛ آزمون درستی عملکرد، ظرفیت مصرف واقعی را تضمین نمی‌کند.

</details>
