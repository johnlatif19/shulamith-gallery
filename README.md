# 🎨 Shulamith Gallery

**Shulamith Gallery** - موقع فني متكامل للفنانة مريم (Shulamith)، خريجة كلية فنون جميلة. يقدم الموقع عرضاً للأعمال الفنية، إدارة المعارض، والتواصل مع العملاء.

## 🚀 المميزات

- 🎨 **معارض ديناميكية**: إنشاء وإدارة المعارض الفنية
- 🖼️ **إدارة الأعمال الفنية**: إضافة، تعديل، وحذف الأعمال مع الصور
- 📸 **رفع الصور**: دعم Cloudinary لرفع الصور
- 🌐 **دعم لغات**: العربية والإنجليزية مع RTL/LTR
- 📧 **نظام التواصل**: استقبال الرسائل وإرسال تأكيدات إيميل
- 🔐 **نظام مصادقة**: JWT لحماية لوحة التحكم
- 📊 **لوحة تحكم كاملة**: إدارة الموقع بالكامل
- 📱 **تصميم متجاوب**: يعمل على جميع الأجهزة
- ⚡ **أداء محسّن**: Lazy loading، تحسين الصور، Core Web Vitals

## 🛠️ التقنيات المستخدمة

### Backend
- **Node.js** + **Express.js**
- **Firebase Admin SDK** (قاعدة البيانات)
- **Cloudinary** (إدارة الصور)
- **Nodemailer** (SMTP)
- **JWT** (المصادقة)
- **Helmet** + **CORS** (الأمان)
- **Express Rate Limit** (الحماية)

### Frontend
- **HTML5** + **CSS3** (تصميم مخصص)
- **JavaScript Vanilla**
- **RTL/LTR Support**
- **Masonry Grid** (المعرض)
- **Lightbox** (عرض الأعمال)
- **Form Validation** (Client & Server)

## 📦 التثبيت والتشغيل

### المتطلبات المسبقة
- Node.js (v18 أو أحدث)
- npm أو yarn
- حساب Firebase
- حساب Cloudinary
- SMTP server (Gmail, SendGrid, etc.)

### 1. استنساخ المشروع
```bash
git clone https://github.com/your-username/shulamith-gallery.git
cd shulamith-gallery
