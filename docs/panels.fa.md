# تنظیم پنل

[English](panels.md)

ابتدا اتصال دو سرور باید در حالت **panel-routing-v1** نسخه 0.4 یا جدیدتر برقرار باشد و `wg-bridge doctor` روی ایران موفق شود. جفت سرور نسخه 0.3 باید ابتدا روی خارج و سپس روی ایران با `wg-bridge routing` تبدیل شود. سرویس SOCKS نصب نمی‌شود و `127.0.0.1:1080` آدرس WireGuard نیست.

## ثنایی و سایر پنل‌های Xray

در Outbounds یک خروجی اضافه کنید. در تب JSON، **فقط شیء زیر** را وارد کنید؛ این نمونه جایگزین کل تنظیمات Xray نیست. IP مبدأ متعلق به ایران است. خروجی‌های داخلی `direct` و `blocked` را نگه دارید.

```json
{
  "tag": "wg-out",
  "protocol": "freedom",
  "sendThrough": "10.204.0.2",
  "settings": {"domainStrategy": "ForceIPv4"},
  "streamSettings": {
    "sockopt": {
      "interface": "wgb-exit",
      "domainStrategy": "ForceIPv4"
    }
  }
}
```

فیلد `settings.domainStrategy` برای هسته‌های قدیمی و `sockopt.domainStrategy` برای Xray فعلی است؛ هر دو برای سازگاری درج شده‌اند. در فرم، Protocol را freedom، Tag را wg-out و Send Through را 10.204.0.2 بگذارید. Sockopts را روشن و Interface را wgb-exit وارد کنید. Redirect و Dialer Proxy خالی، Mark صفر و TProxy خاموش بمانند. انتخاب پروتکل WireGuard در Outbound، یک peer جداگانه داخل Xray می‌سازد؛ برای استفاده از رابط موجود باید همان freedom را انتخاب کنید.

## DNS

در بخش تنظیمات DNS هسته، **شیء DNS زیر** را وارد یا با تنظیمات موجود ادغام کنید:

```json
{
  "servers": ["1.1.1.1", "8.8.8.8"],
  "queryStrategy": "UseIPv4",
  "tag": "wg-dns"
}
```

قانون wg-dns در بخش بعد، درخواست‌های DNS داخلی Xray را از تونل می‌فرستد. در این روش از localhost یا روش‌های DNS با حالت local استفاده نکنید؛ آن‌ها مسیر موردنظر را دور می‌زنند. این مثال DNS داخلی کل نمونه Xray را به خارج هدایت می‌کند؛ تنظیمات تفکیک DNS سفارشی باید جداگانه بررسی شود. DNS خود سیستم‌عامل تغییر نمی‌کند. درخواست DNS ارسالی از برنامهٔ کاربر نیز مثل بقیه ترافیک از خروجی انتخاب‌شده عبور می‌کند.

## Routing

قانون داخلی api را در ابتدای فهرست و قوانین مسدودسازی خود را حفظ کنید. پیش از قوانین عمومی direct، **این دو قانون** را به فهرست rules موجود اضافه کنید:

```json
{
  "type": "field",
  "inboundTag": ["wg-dns"],
  "outboundTag": "wg-out"
}
```

```json
{
  "type": "field",
  "inboundTag": ["YOUR_USER_INBOUND_TAG_1", "YOUR_USER_INBOUND_TAG_2"],
  "outboundTag": "wg-out"
}
```

عبارت‌های نمونه را با تگ واقعی اینباندهای فعال کاربران عوض کنید؛ api را وارد نکنید. در فرم Routing هم می‌توانید تمام اینباندهای موردنظر را انتخاب و Outbound را wg-out بگذارید. شماره پورت اینباندها می‌تواند متفاوت باشد. فیلد port در قانون Routing پورت **مقصد** است و برای انتخاب پورت ورودی کاربران نیست. ذخیره کنید و از کنترل پنل تغییرات را اعمال یا Xray را مجدداً راه‌اندازی کنید. اگر قانون direct زودتر تطبیق پیدا کند، قانون تونل اجرا نمی‌شود.

## سایر پنل‌ها

پنل‌های Xray دارای امکان Outbound و Routing سفارشی می‌توانند همین تنظیمات را بپذیرند. هسته باید در شبکه میزبان اجرا شود و اجازه انتخاب رابط را داشته باشد. Docker با شبکه host به رابط دسترسی دارد؛ شبکه bridge به ادغام شبکه جداگانه نیاز دارد.

برای sing-box، نمونه خروجی مستقیم به این صورت است:

```json
{
  "type": "direct",
  "tag": "wg-out",
  "bind_interface": "wgb-exit",
  "inet4_bind_address": "10.204.0.2"
}
```

این فقط بخش Outbound است. اینباندها را به آن هدایت و DNS نسخه نصب‌شده را هم برای عبور از wg-out و پاسخ IPv4 تنظیم کنید. قالب DNS بین نسخه‌های sing-box فرق دارد. این نمونه بر اساس نام فیلدهای رسمی است؛ به معنی آزموده‌شدن تمام پنل‌ها و نسخه‌ها نیست.

## آزمایش نهایی

1. روی ایران doctor باید handshake، HTTPS و DNS با UDP را موفق گزارش کند و IP خروجی خارج را نشان دهد.
2. با یک کلاینت واقعی به اینباند کاربر متصل شوید. IP عمومی، بازشدن سایت با نام دامنه و برنامه دارای UDP را بررسی کنید.
3. برای آزمایش کوتاه، تونل را از منو متوقف کنید. کاربر منتخب باید دسترسی اینترنت را از دست بدهد، ولی SSH و اینترنت مستقیم خود سرور باقی بمانند. سپس تونل را شروع کنید.

خروجی تونل IPv4 است؛ مقصد IPv6 صریح باید قطع شود و به مسیر مستقیم ایران برنگردد. IPv6 عادی میزبان مستقل می‌ماند. برای کاربرانی که باید از تونل استفاده کنند، خروجی جایگزین مستقیم یا قانون direct با اولویت بالاتر نگذارید.

منابع: [خروجی Xray](https://xtls.github.io/en/config/outbound.html)، [انتخاب رابط](https://xtls.github.io/en/config/transports/sockopt.html)، [DNS](https://xtls.github.io/en/config/dns.html)، [Routing](https://xtls.github.io/en/config/routing.html)، [sing-box](https://sing-box.sagernet.org/configuration/shared/dial/).
