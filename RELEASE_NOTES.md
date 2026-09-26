# WG Bridge v0.3.1

WireGuard transport now defaults to **UDP 9999** on both servers. The transport port remains editable and is separate from the single forwarded service port.

Outside setup now asks for Iran's public IPv4 and planned WireGuard UDP port. Both peers receive an explicit endpoint and a 25-second keepalive, allowing either server to initiate. The pairing code carries the Iran endpoint, and Iran setup rejects a mismatch before modifying the network.

- Open the selected WireGuard UDP ports in both provider firewalls; any chosen port still needs a working network path.
- Use Outside menu option **8 — Set Iran peer endpoint**, or `wg-bridge peer IRAN_PUBLIC_IPV4 IRAN_WIREGUARD_UDP_PORT`, to configure the remote endpoint without replacing keys. An active tunnel restarts; changes roll back if that restart fails.
- Compatible upgrades preserve existing ports and configuration. After upgrading an older pair, use the Outside peer command with Iran's **current** WireGuard port to enable bidirectional initiation. The new default does not silently move existing installations.
- New managers accept older WGB2 codes. Use v0.3.1 or newer on both hosts for codes containing the new peer fields.
- One selected IPv4 TCP/UDP service port is forwarded; ordinary Internet routes and host IPv6 remain unchanged.

Validation covers actual WireGuard initiation from Outside, TCP/UDP forwarding, custom ports, preserved host connectivity, peer changes, rollback, upgrade and uninstall on Ubuntu 22.04, 24.04 and 26.04. This is a preview release; these tests do not establish production capacity or guarantee that a provider permits every UDP port.

[English](https://github.com/itsalirezaw/wg-bridge#readme) · [فارسی](https://github.com/itsalirezaw/wg-bridge/blob/main/README.fa.md)

<details>
<summary>توضیحات فارسی</summary>

پیش‌فرض پورت ارتباط خود WireGuard روی هر دو سرور **UDP 9999** است و همچنان می‌توانید پورت دلخواه را وارد کنید. پورت سرویس جداست و فقط همان یک پورت از ایران به خارج منتقل می‌شود.

در نصب خارج، IP عمومی و پورت WireGuard ایران هم پرسیده می‌شود تا هر دو سمت بتوانند ارتباط را آغاز کنند. Keepalive هر دو طرف ۲۵ ثانیه است. مقادیر ایران داخل کد اتصال قرار می‌گیرند و نصب ایران تطابقشان را بررسی می‌کند. UDP ارتباط WireGuard باید در فایروال ارائه‌دهندهٔ هر دو سرور باز باشد.

برای نصب قبلی، ابتدا مدیر هر دو سمت را ارتقا دهید و سپس روی خارج گزینهٔ 8، Set Iran peer endpoint، را با IP و پورت فعلی WireGuard ایران اجرا کنید. کلیدها حفظ می‌شوند؛ ارتقا پورت‌های قبلی را خودکار به 9999 تغییر نمی‌دهد. مدیر جدید کدهای WGB2 قدیمی را می‌پذیرد؛ برای کد جدید، هر دو سمت باید نسخهٔ 0.3.1 یا جدیدتر باشند.

</details>
