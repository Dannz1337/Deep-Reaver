## Changelog

### v0.1 - Awal Mula
- Pembuatan script scanner sederhana dengan modul XSS dan SQLi.
- Output hasil scan hanya di terminal (tanpa report file).

### v0.2
- Penambahan module: CSRF, XXE, RCE.
- Penambahan penyimpanan hasil scan ke file .json.

### v0.3
- Penambahan fitur delay antara module.
- Penambahan support mode: full & stealth.

### v0.4
- Penambahan module: File Upload, Open Redirect, Clickjacking.
- Pemeriksaan Cookie Security & CORS.
- Penambahan WAF Detector.

### v0.5
- Penambahan AI Assistant untuk menganalisis hasil scan.
- Integrasi OpenRouter API (GPT-3.5).

### v0.6
- AI Assistant ditingkatkan dengan sistem fallback & summary otomatis.
- Bugfix parsing response dan error pada module scanning.

### v0.7
- Penambahan module: CMS Detection, JSONP, Host Header Injection.
- Output scan ditambahkan ke format .html.

### v0.8
- Perombakan scanner & struktur folder.
- AI Assistant bisa output analisis langsung ke report JSON & HTML.

### v0.9
- Integrasi dengan .env file untuk menyimpan API KEY.
- Validasi model AI & error fallback ditingkatkan.

### v1.0 (Stabil)
- Sistem stabil & modular.
- Sudah mendukung 20+ jenis pemeriksaan keamanan.
- Dukungan AI Assistant aktif, bisa terhubung OpenRouter langsung.
- Scan report lengkap dengan analisis AI.

### v1.0.1
- Pembaruan modul: `auth_bypass`, `brute_force`, dan `clickjacking`.
- Peningkatan akurasi deteksi dan pengolahan hasil.
- Penyesuaian output dan penambahan logging.

### v1.0.2 - 2025-04-21
- Pembaruan dan penyempurnaan modul:
  - `cors.py`: Validasi header & deteksi konfigurasi CORS lemah.
  - `csrf.py`: Deteksi token CSRF & support metode POST.
  - `cookie.py`: Evaluasi atribut `Secure`, `HttpOnly`, dan `SameSite`.
- Peningkatan output hasil & struktur kode yang lebih rapi.