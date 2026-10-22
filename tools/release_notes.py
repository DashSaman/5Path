"""Write Persian release notes bound to one immutable commit."""
import os,pathlib
tag=os.environ['RELEASE_TAG'];commit=os.environ['GITHUB_SHA']
text=f'''## ثبت نسخهٔ {tag}

این انتشار به commit `{commit}` متصل است و کد، مستندات فارسی، شمای فنی و شواهد پالایش‌شدهٔ همان نسخه را شامل می‌شود.

### بررسی‌ها

- آزمون‌های خودکار اجزای محلی و کنترل syntax اجرا شده‌اند.
- مسیرهای لینک محلی و خروجی عمومی برای الگوهای credential، کلید و فایل خصوصی بررسی شده‌اند.
- ZIP فقط از فایل‌های ثبت‌شدهٔ همین commit ساخته شده و SHA256 آن ضمیمه است.

### اثر روی سرور و محدودیت‌ها

انتشار GitHub هیچ نصب، restart، تغییر T6 یا XUI و انتقال کاربر انجام نمی‌دهد. وضعیت نصب WARP، UDP ترکیه، ظرفیت و PDF را از README و تاریخچهٔ همین commit بخوانید. موفقیت CI، شاهد آزمون WAN یا کیفیت واقعی کاربران نیست. نسخهٔ فعلی پیش‌انتشار است.

### تغییرهای ثبت‌شده

'''+pathlib.Path('CHANGELOG.md').read_text(encoding='utf-8')
pathlib.Path(os.environ['RELEASE_NOTES_PATH']).write_text(text,encoding='utf-8')
