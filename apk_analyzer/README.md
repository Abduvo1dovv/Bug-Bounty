# APK Analyzer (no decompile)

APK ichidan **dekompilyatsiyasiz** xavfli/maxfiy ma'lumotlarni topadigan skript.
`apktool`, `jadx`, `dex2jar` kerak emas — APK ZIP arxiv sifatida ochiladi va
fayllar ichidan stringlar to'g'ridan-to'g'ri sug'urib olinadi.

## O'rnatish

```bash
pip install -r requirements.txt
```

`colorama` faqat rangli chiqish uchun, majburiy emas.

## Foydalanish

```bash
python analyze.py com.coupang.mobile.lightspeed.apk
```

Hisobot fayllari:

- `com.coupang.mobile.lightspeed.report.json` — JSON (avtomatik tahlil uchun)
- `com.coupang.mobile.lightspeed.report.txt`  — o'qish uchun matn

Qo'shimcha bayroqlar:

```bash
python analyze.py app.apk -o my_report          # hisobot prefiksi
python analyze.py app.apk --min-len 8           # qisqa shovqin stringlarni o'tkazib yuborish
python analyze.py app.apk --quiet               # terminalga bosmasin
```

## Nimalarni topadi

| Toifa       | Misol |
|-------------|-------|
| Secret      | Google API Key, AWS Key, Slack Token, GitHub PAT, Stripe, Twilio, SendGrid, Mapbox, ... |
| Auth        | JWT, `Authorization: Bearer ...`, Basic Auth in URL, hardcoded password/secret |
| Cookie      | `Set-Cookie:`, `Cookie:`, `JSESSIONID`, `PHPSESSID`, `access_token`, `refresh_token` |
| Crypto      | `-----BEGIN PRIVATE KEY-----` (RSA / EC / OpenSSH / PGP) |
| Network     | Hardcoded URL (http/https), IP, S3 bucket, Firebase URL |
| Manifest    | Xavfli ruxsatlar, `usesCleartextTraffic`, `debuggable` belgilar |

## Bug bounty uchun keyingi qadamlar

Skript topgan narsalardan asosan diqqat qilish kerak:

1. **`http://`** bilan boshlanuvchi endpoint'lar — cleartext traffic, MITM uchun
2. **Hardcoded API key/secret** — agar production keyi bo'lsa, bu odatda yuqori darajali topilma
3. **Shu APK uchun mo'ljallanmagan 3rd-party token'lar** (masalan Slack webhook) — leak
4. **`debuggable=true`** chiqsa — release build'da bu jiddiy
5. **`allowBackup=true`** + sezgir ma'lumot — `adb backup` orqali ekstraksiya mumkin
6. **Internal/staging hostlari** (`*.internal`, `*.dev`, `*.stg`) — ko'pincha qo'shimcha attack surface

> Eslatma: skript faqat statik analiz qiladi. Topilgan narsalarni qo'lda
> tekshirib chiqing — false positive bo'lishi mumkin (masalan Stripe `pk_live_`
> public key — bu maxfiy emas).

## Bug bounty etikasi

Bu skriptni faqat **siz uchun ruxsat berilgan dasturlar** (HackerOne, Bugcrowd va h.k.)
doirasidagi APK'larga qo'llang. Topilgan narsalarni dastur scope va policy'siga
muvofiq xabar qiling.
