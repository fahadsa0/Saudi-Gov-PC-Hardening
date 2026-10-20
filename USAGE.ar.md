<div dir="rtl">

# 📘 دليل الاستخدام

طريقة تنزيل سكربتات التحصين والتحقق منها وتشغيلها والتراجع عنها. English: [USAGE.md](USAGE.md)

> ⚠️ هذه السكربتات تغيّر إعدادات الأمان في Windows. **جرّبها أولاً على جهاز افتراضي (VM).** لا تشغّلها على جهاز عمل أو جهاز إنتاج بدون موافقة فريق تقنية المعلومات أو الأمن السيبراني.

---

## 1. المتطلبات

| المتطلب | التفاصيل |
|---|---|
| نظام التشغيل | Windows 10 / 11 (يفضّل Pro أو Enterprise أو Education) |
| PowerShell | **Windows PowerShell 5.1** (مدمج في النظام، افتح "Windows PowerShell"). نسخة PowerShell 7 لم تُختبر. |
| الصلاحيات | مسؤول محلي **Administrator** |
| الملفات | كل ملفات `.ps1` لازم تكون **في نفس المجلد** (السكربتات تحمّل `Common.ps1`) |
| نسخة Home | تشتغل، لكن فحص BitLocker لن يكون متاحاً |

---

## 2. تنزيل الملفات والتحقق منها

1. افتح صفحة **Releases** في المستودع ونزّل أحدث ملف ZIP.
2. انسخ قيم الهاش (SHA-256) المكتوبة في **وصف الإصدار**.
3. فك الضغط في مجلد، مثلاً `C:\Hardening`.
4. اضغط يمين على زر ابدأ واختر **Terminal (Admin)** أو **Windows PowerShell (Admin)**.
5. ادخل المجلد واحسب الهاش (هذا الأمر لا ينفّذ أي سكربت):
   ```powershell
   cd C:\Hardening
   Get-FileHash .\*.ps1 -Algorithm SHA256 | Select-Object Hash, @{n='File';e={Split-Path $_.Path -Leaf}}
   ```
6. قارن كل هاش بالمكتوب في وصف الإصدار. **إذا اختلف أي هاش، لا تشغّل السكربتات.**
7. بعد التطابق فقط، فك الحظر عن الملفات:
   ```powershell
   Get-ChildItem .\*.ps1 | Unblock-File
   ```

> ليش فك الحظر؟ Windows يعلّم الملفات المنزّلة من الإنترنت كغير موثوقة، وسياسة `RemoteSigned` ترفض تشغيلها حتى تفك الحظر.

---

## 3. وش يسوي كل سكربت

| السكربت | التغييرات | خيارات اختيارية |
|---|---|---|
| `Hardening-Script.ps1` | تعطيل SMBv1، تفعيل الجدار الناري (منع الوارد وتسجيل المحجوب)، تسجيل أوامر PowerShell، تعطيل PowerShell v2، ضبط سياسة التنفيذ | `-ExecutionPolicy AllSigned` و`-RequireSmbSigning` و`-Cleanup` |
| `Hardening-Accounts.ps1` | تعطيل Guest، سياسة كلمات المرور والقفل، NLA وTLS لسطح المكتب البعيد، قفل الشاشة عند الخمول، حماية LSA، تعطيل WDigest | `-LockoutThreshold` و`-LockoutMinutes` و`-MinPasswordLength` و`-InactivitySeconds` و`-SkipPasswordPolicy` و`-SkipLsaProtection` و`-AcceptUefiLock` |
| `Hardening-Storage.ps1` | تعطيل AutoRun/AutoPlay، تفعيل تدقيق الفلاشات، تقرير حالة BitLocker | `-BlockUnencryptedRemovableWrite` و`-BlockAllRemovableStorage` |
| `Hardening-Firewall.ps1` | تعطيل NetBIOS وLLMNR وmDNS وتسجيل الدخول كضيف في SMB، وحظر المنافذ الواردة القديمة (23 و512-514 TCP و69 UDP) | `-ExtraTcpPorts` و`-ExtraUdpPorts` |
| `Integrity-Check.ps1` | فحص DISM وإصلاحه عند الحاجة فقط، ثم SFC | `-Source` و`-SkipSfc` و`-CreateManifest` و`-VerifyScripts` |
| `Restore-Hardening.ps1` | التراجع عن التغييرات المسجلة | `-List` و`-BackupFile` و`-WhatIf` |

---

## 4. تشغيل السكربتات

### الخطوة 1: المعاينة (ما تغيّر أي شي)
```powershell
.\Hardening-Script.ps1   -WhatIf
.\Hardening-Accounts.ps1 -WhatIf
.\Hardening-Storage.ps1  -WhatIf
.\Hardening-Firewall.ps1 -WhatIf
```
اقرأ الناتج، فهو يعرض اللي *سيتغيّر* فقط.

### الخطوة 2: التطبيق
```powershell
.\Hardening-Script.ps1
.\Hardening-Accounts.ps1
.\Hardening-Storage.ps1
.\Hardening-Firewall.ps1
```
تقدر تشغّل السكربتات اللي تحتاجها فقط، فهي مستقلة عن بعض.

### الخطوة 3: إعادة التشغيل
مطلوبة لحماية LSA ولاكتمال إزالة SMBv1 وPowerShell v2.

### أمثلة بخيارات
```powershell
.\Hardening-Script.ps1 -ExecutionPolicy AllSigned -RequireSmbSigning
.\Hardening-Accounts.ps1 -LockoutThreshold 3 -MinPasswordLength 12
.\Hardening-Storage.ps1 -BlockUnencryptedRemovableWrite
.\Hardening-Firewall.ps1 -ExtraTcpPorts 5900
```

---

## 5. قراءة النتائج

| المستوى | المعنى |
|---|---|
| `[OK]` (أخضر) | تم تطبيق تغيير بنجاح |
| `[INFO]` (سماوي) | معلومة، أو الإعداد كان مضبوطاً من قبل |
| `[WARN]` (أصفر) | يحتاج انتباهك (إعادة تشغيل، توافق، BitLocker غير مفعّل، إلخ) |
| `[ERROR]` (أحمر) | فشلت خطوة، والخطوات الأخرى كملت |

في النهاية يطبع كل سكربت ملخصاً: عدد الخطوات والفاشلة والتحذيرات. رمز الخروج `0` إذا ما فشلت أي خطوة، و`1` إذا فشلت.

**السجلات:** `C:\ProgramData\EndpointHardening\Logs`  
**بيانات التراجع:** `C:\ProgramData\EndpointHardening\Backup` (للنظام والمسؤولين فقط)

---

## 6. التراجع

```powershell
.\Restore-Hardening.ps1 -List
.\Restore-Hardening.ps1 -BackupFile "C:\ProgramData\EndpointHardening\Backup\<file>.json" -WhatIf
.\Restore-Hardening.ps1 -BackupFile "C:\ProgramData\EndpointHardening\Backup\<file>.json"
```
استرجع كل ملف نسخة احتياطية تبغى تتراجع عنه، ثم أعد التشغيل.

**ما يُسترجع تلقائياً** (إعادة تفعيلها تضعف الأمان): SMBv1 وPowerShell v2 وحساب Guest وسياسة كلمات المرور المحلية (القيم القديمة مكتوبة في سجل Accounts) وحماية LSA إذا طُبّقت بقفل UEFI.

---

## 7. فحص السلامة

```powershell
.\Integrity-Check.ps1                     # إصلاح ملفات النظام DISM + SFC (قد ياخذ وقت طويل)
.\Integrity-Check.ps1 -Source "WIM:D:\sources\install.wim:1"   # مصدر إصلاح بدون إنترنت
.\Integrity-Check.ps1 -CreateManifest     # إنشاء SHA256SUMS.txt للسكربتات
.\Integrity-Check.ps1 -VerifyScripts      # مقارنة السكربتات مع SHA256SUMS.txt
```

---

## 8. حل المشاكل

| المشكلة | الحل |
|---|---|
| `running scripts is disabled on this system` أو "not digitally signed" | تحقق من الهاش، ثم شغّل `Get-ChildItem .\*.ps1 \| Unblock-File`. افحص السياسة بـ `Get-ExecutionPolicy -List`. |
| ما لقى `Common.ps1` | خلّ كل السكربتات في نفس المجلد وشغّلها منه. |
| `Administrator privileges are required` | افتح PowerShell بخيار **Run as administrator**. |
| تحذير إن Group Policy يغلب الإعدادات | الجهاز مدار بدومين أو Intune، اطلب من المسؤول تطبيق الإعدادات مركزياً. |
| ظهر `[ERROR]` في خطوة | اقرأ الرسالة وملف السجل، والخطوات الباقية ما تأثرت. افتح Issue وأرفق السجل (بعد حذف أسماء الجهاز والمستخدم). |
| انقفل الحساب بسبب سياسة القفل | انتظر مدة القفل، أو استخدم حساب مسؤول ثاني، أو شغّل Restore. |
| تطبيق أو طابعة مشتركة وقفت بعد تغييرات NetBIOS/SMB/الجدار الناري | شغّل `Restore-Hardening.ps1` لتلك النسخة، ثم أعد التطبيق بدون السكربت المتسبب. |

---

## 9. طريقة العمل الموصى بها للجهات

1. جرّب كل شي على لقطة (Snapshot) من جهاز افتراضي.
2. راجع كل إعداد مقابل سياسة الأمن لديك.
3. جرّبه على عدد قليل من الأجهزة لمدة أسبوع.
4. طبّقه تدريجياً مع حفظ السجلات.
5. للأجهزة المُدارة، حوّل الإعدادات إلى Group Policy أو Intune بدل التشغيل اليدوي.

هذا مشروع مستقل، وغير تابع لأي جهة حكومية أو معتمد منها، ولم يُدقَّق مقابل معيار محدد.

</div>
