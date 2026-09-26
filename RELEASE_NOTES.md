# WG Bridge v0.4.0

Run your panel on Iran and send selected outbounds through kernel WireGuard to an outside Internet exit. Multiple user inbounds share the link, while SSH and unrelated services retain their host default routes.

- New installs use panel routing with WGB3 pairing. No SOCKS daemon or panel configuration is installed.
- Bind panel outbounds to `10.204.0.2` / `wgb-exit`; configure inbound selection and DNS manually. English and Persian guides include Xray/3x-ui examples and integration notes for other engines.
- Outside enables scoped forwarding and NAT. Iran uses source/interface policy routing, terminal unreachable routes and an OUTPUT guard. Stopping/removing WireGuard cannot fall through to direct host routing for correctly bound traffic.
- IPv4 egress; interface-bound IPv6 is blocked. Global host IPv6 and default routes are preserved.
- `wg-bridge routing` converts v0.3 pairs, Outside first then Iran, with backups and rollback. Keys and transport ports stay the same; the old public port mapping is removed.
- `wg-bridge doctor` checks source routing, HTTPS exit address and UDP DNS. `wg-bridge panel` prints panel settings; `wg-bridge` opens the menu.
- UDP 9999 remains the configurable default for new installations.

Upgrade both hosts using the README, then run `wg-bridge routing` on Outside and Iran. Existing panel-routing installs need only the manager upgrade. Older v0.1/v0.2 full-routing installations require uninstall/reinstall. WGB2 remains supported for existing legacy mappings.

All CI checks passed on Ubuntu 22.04, 24.04 and 26.04. Validation covers real WireGuard TCP/UDP/DNS, source/interface binding, strict reverse-path filtering, 300 HTTP requests with 40 workers per mode, tunnel failures, unrelated services, conversion rollback and installer lifecycle. A live pair also passed Xray 26.9.9 TCP/UDP/DNS and stop/restart tests. These are correctness checks, not a throughput or user-capacity guarantee. [Validation record](docs/validation.md).

[English installation](README.md) · [نصب فارسی](README.fa.md) · [Panel guide](docs/panels.md) · [راهنمای پنل](docs/panels.fa.md)

---

نسخه 0.4 خروجی انتخاب‌شدهٔ پنل ایران را با WireGuard به اینترنت خارج می‌فرستد. چند اینباند می‌توانند یک خروجی مشترک داشته باشند؛ مسیر پیش‌فرض SSH و سرویس‌های دیگر تغییر نمی‌کند. SOCKS نصب نمی‌شود و تنظیم خروجی، Routing و DNS داخل پنل دستی است.

برای تبدیل 0.3، ابتدا هر دو مدیر را ارتقا دهید و سپس `wg-bridge routing` را روی خارج و بعد ایران اجرا کنید. کلیدها و پورت فعلی حفظ، از تنظیمات قبلی پشتیبان‌گیری و فوروارد عمومی قدیمی حذف می‌شود. خروجی این نسخه IPv4 است. راهنمای فارسی پنل و ضبط ویدیو در مخزن قرار دارد.
