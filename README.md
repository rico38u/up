# NEXORA — Social Network Starter

مشروع Full‑Stack حقيقي (وليس صفحة HTML تجريبية فقط) مبني بـ Node.js + Express + SQLite + Socket.IO.

## ما الذي يعمل فعليًا؟
- إنشاء حساب سريع باسم مستخدم/بريد وكلمة مرور.
- تسجيل الدخول والخروج مع كوكي جلسة HttpOnly.
- كلمات المرور محفوظة كـ bcrypt hashes، مع rate limiting وHelmet وCSRF token.
- منشورات حقيقية نصية وصور وفيديوهات في قاعدة البيانات.
- ملف شخصي قابل للتعديل، صورة شخصية وصورة غلاف.
- رسائل مباشرة حقيقية بين الحسابات، وتحديث لحظي عبر Socket.IO.
- صور/فيديو/صوت داخل المحادثة، وتسجيل رسالة صوتية من المتصفح.
- مكالمات فيديو P2P عبر WebRTC + Socket.IO signaling (الاتصال يعتمد على شبكة المستخدمين وSTUN، وقد تحتاج TURN للنشر العام).
- متجر حقيقي للقوائم: المستخدم يضيف منتج/لعبة ورابط شراء/تنزيل حقيقي. لا توجد عناصر أو منشورات seed داخل قاعدة البيانات.
- Google / TikTok / Facebook OAuth قابلة للتفعيل من ملف `.env`.

## تشغيل المشروع
```bash
npm install
copy .env.example .env   # Windows
# أو: cp .env.example .env
npm start
```
ثم افتح: `http://localhost:3000`

## OAuth
ضع مفاتيح OAuth في `.env`. لا تضع الأسرار في الواجهة الأمامية.

### Google
استخدم Google Identity Services / OAuth 2.0 وأنشئ Web OAuth client. اجعل callback:
`http://localhost:3000/auth/google/callback`

### TikTok
فعّل Login Kit، وأضف callback:
`http://localhost:3000/auth/tiktok/callback`
ويجب تسجيل redirect URI وفق شروط TikTok.

### Facebook
فعّل Facebook Login واملأ `FACEBOOK_APP_ID`, `FACEBOOK_APP_SECRET` و`FACEBOOK_GRAPH_VERSION` المناسبة لتطبيقك، ثم callback:
`http://localhost:3000/auth/facebook/callback`

### Instagram + WhatsApp
لم يتم وضع أزرار مزيفة لتوهم المستخدم بأنهما يعملان. في هذا البناء، لا يوجد تدفق عام موحد لتسجيل دخول المستهلكين عبر WhatsApp، بينما تسجيل Instagram يعتمد على نوع حساب Instagram/منتج Meta وصلاحياته وليس بديلًا مباشرًا موحدًا لكل الحسابات الشخصية. عند وجود خدمة OAuth/OTP فعلية تختارها، أضفها كموفر backend بدل اختراع تدفق محلي.

## ملاحظات الأمان للإنتاج
- استخدم HTTPS واضبط `COOKIE_SECURE=true`.
- استخدم `JWT_SECRET` عشوائيًا طويلًا وثابتًا في بيئة الإنتاج.
- أضف تخزين كائنات (S3/R2/etc.) بدل `uploads/` عند التوسع.
- استخدم قاعدة PostgreSQL بدل SQLite عند الحمل العالي.
- أضف TURN server لمكالمات WebRTC خارج الشبكات البسيطة.
- راجع سياسات وأذونات كل مزود OAuth قبل الإطلاق.
