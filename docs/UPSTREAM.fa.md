# منابع بالادست و دارایی نرم‌افزاری

باینری شخص ثالث در این مخزن بازنشر نشده است. برای استفاده از هر ابزار، نسخه، منبع، SHA، شرایط مجوز همان پروژه و سازگاری سیستم‌عامل باید بررسی شود. درج لینک به معنای نصب آن در تولید نیست.

- [sing-box](https://github.com/SagerNet/sing-box) و [مستندات رسمی](https://sing-box.sagernet.org/)؛ نسخهٔ منبع بررسی‌شدهٔ پروژه 1.14.3 است.
- [frp](https://github.com/fatedier/frp) و [مستندات شبکه](https://gofrp.org/en/docs/features/common/network/network/).
- [GOST](https://github.com/go-gost/gost) و [مستندات HTTP2](https://gost.run/reference/handlers/http2/).
- [wgcf](https://github.com/ViRb3/wgcf)؛ ابزار مستقل برای ساخت پروفایل WireGuard/WARP، با نسخهٔ محلی بررسی‌شدهٔ 2.3.0. این ابزار، کلاینت رسمی Cloudflare نیست.
- [راهنمای رسمی WARP در Linux](https://developers.cloudflare.com/warp-client/get-started/linux/) و [حالت‌های WARP](https://developers.cloudflare.com/warp-client/warp-modes/).
- [مرجع nftables](https://www.netfilter.org/projects/nftables/manpage.html) برای تفسیر ruleها و تفکیک metadata از پورت واقعی.
- [منبع URLTest نسخهٔ sing-box بررسی‌شده](https://github.com/SagerNet/sing-box/blob/v1.14.3/common/urltest/urltest.go) برای رفتار واقعی درخواست `HEAD`.

SHA دارایی‌های بررسی‌شده در [فایل provenance عمومی](../evidence/upstream-assets.json) آمده است. تطبیق SHA، تنها هویت فایل را نشان می‌دهد؛ پذیرش عملکرد، liveness منبع و ایمنی تغییر باید جداگانه بررسی شوند.

مجوز عمومی جداگانه‌ای برای کد این مخزن در این نسخه تعیین نشده است. مجوز ابزارهای بالادست مستقل است و باید از همان مخزن خوانده شود.
