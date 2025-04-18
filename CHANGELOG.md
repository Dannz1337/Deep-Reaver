# Changelog

Semua perubahan penting pada proyek ini didokumentasikan di bawah ini.

---

## [1.0.1] - 2025-04-18

### Update Modul Keamanan
- Peningkatan signifikan pada modul:
  - `auth_bypass.py`
  - `brute_force.py`
  - `clickjacking.py`
- Menambahkan metode pendeteksian baru untuk hasil yang lebih akurat.
- Refactor besar dengan peningkatan efisiensi dan keterbacaan kode.
- 178 baris kode ditambahkan, 63 baris dihapus.
- Siap untuk integrasi fitur lanjutan ke depannya.

---

## [1.0.0] - 2025-04-17

### Rilis Stabil
- Sistem scanner modular stabil
- Dukungan 20+ jenis pemeriksaan keamanan
- AI Assistant aktif dengan integrasi OpenRouter
- Laporan hasil scan dalam format JSON dan HTML, termasuk analisis AI

---

## [0.9.0] - 2025-04-15

### Integrasi & Upload
- Upload pertama via Termux
- Struktur direktori dibentuk di folder `/user/`
- File `.env` ditambahkan, `.gitignore` disetting
- API Key dihapus dari repo, diganti sistem `.env`
- Force push untuk sinkronisasi lokal dengan remote

---

## [0.8] - 2025-04-14

### Perombakan Struktur & AI
- Refactor total struktur folder dan modul
- AI Assistant bisa simpan analisis ke file laporan (.json & .html)

---

## [0.7] - 2025-04-13

### Modul & Output Tambahan
- Tambahan modul: CMS Detection, JSONP, Host Header Injection
- Output laporan ditambah dalam format .html

---

## [0.6] - 2025-04-12

### Peningkatan AI & Bugfix
- AI Assistant pakai sistem fallback + summary otomatis
- Bugfix parsing response dan error scanner

---

## [0.5] - 2025-04-11

### Integrasi AI
- Penambahan AI Assistant untuk analisis hasil scan
- Integrasi OpenRouter API (GPT-3.5)

---

## [0.4] - 2025-04-10

### Modul Baru & Deteksi
- Tambah modul: File Upload, Open Redirect, Clickjacking
- Tambahan pemeriksaan: Cookie Security, CORS, dan WAF Detection

---

## [0.3] - 2025-04-09

### Mode & Delay
- Tambah fitur delay antar modul
- Tambah mode scan: full & stealth

---

## [0.2] - 2025-04-08

### Modul & Laporan
- Tambah modul: CSRF, XXE, RCE
- Hasil scan bisa disimpan ke file `.json`

---

## [0.1] - 2025-04-07

### Awal Mula
- Pembuatan script scanner sederhana
- Modul awal: XSS dan SQL Injection
- Output hanya di terminal (tanpa laporan file)