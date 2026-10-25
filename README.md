# Telegram Proxy — nexoraict

لیست زنده‌ی پروکسی‌های MTProto تلگرام، با جستجو، فیلتر نوع (FakeTLS / Secure / ساده)، علاقه‌مندی، کپی لینک، QR و دکمه‌ی «اتصال در تلگرام».
منبع لیست: [SoliSpirit/mtproto](https://github.com/SoliSpirit/mtproto) (بروزرسانی هر ۱۲ ساعت). سایت هر ۳۰ دقیقه لیست را دوباره می‌گیرد.

سایت فقط یک صفحه‌ی HTML ثابت است و به هیچ سروری نیاز ندارد.

## بالا آوردن روی GitHub Pages
1. در GitHub یک مخزن عمومی بسازید، مثلاً `tg-proxy`.
2. همه‌ی فایل‌های این پوشه را در ریشه‌ی مخزن آپلود کنید.
3. `Settings → Pages` → Source: **Deploy from a branch** → Branch: `main` و پوشه‌ی `/ (root)` → Save.
4. بعد از چند دقیقه سایت روی `https://USERNAME.github.io/REPO/` باز می‌شود.

## اجرای محلی (اختیاری)
```bash
node server.js     # سپس http://localhost:8787
```
