# 🛡️ Sistem Deteksi Anti-Phishing URL

Aplikasi web berbasis **Flask** untuk mendeteksi tautan phishing dengan menggabungkan
**heuristik aturan** dan **model Machine Learning (Random Forest)**. Menghasilkan skor
risiko 0–100 lengkap dengan penjelasan ramah awam mengenai alasan deteksi.

Dibangun sebagai proyek Skripsi — Program Studi Sistem Informasi.

---

## ✨ Fitur Utama

**Sisi Frontend**
- 🔍 Form pemindaian URL dengan **validasi input real-time** (format URL langsung dicek)
- 📊 **Risk meter visual** berwarna (Hijau = Aman, Kuning = Waspada, Merah = Bahaya)
- 📋 **Explainable output** — kartu alasan mengapa tautan dicurigai (ramah awam)
- 📝 **Tombol umpan balik** pengguna (Tepat / Salah Prediksi) untuk crowdsourced validation
- 🧾 Halaman **admin audit log** dengan rincian skor heuristik & ML

**Sisi Backend**
- 🔗 **URL unshortener** — membuka tujuan asli di balik pemendek (`bit.ly`, `tinyurl.com`, dll.)
- 🧠 **Model Random Forest** (1200 sampel, 19 fitur leksikal/struktural URL)
- 🏷️ **14 indikator heuristik**: IP mentah, HTTPS, kata kunci, TLD berisiko, umur domain (WHOIS), sertifikat SSL, panjang URL, subdomain, simbol `@`, port, dll.
- ⚖️ Skor gabungan `50% heuristik + 50% ML`
- 🗄️ **Log audit SQLite** (IP, user-agent, skor heuristik/ML, feedback)
- 🌐 **REST API** untuk integrasi ekstensi browser / aplikasi lain

---

## 🚀 Instalasi

1. **Clone / unduh** repositori.
2. Buat virtual environment (disarankan):
   ```bash
   python -m venv .venv
   .venv\Scripts\activate        # Windows
   source .venv/bin/activate     # macOS / Linux
   ```
3. **Install dependensi**:
   ```bash
   pip install -r requirements.txt
   ```

---

## ▶️ Menjalankan

```bash
python app.py
```

Lalu buka browser di **http://localhost:5000**

> Dataset model Random Forest dilatih otomatis pada `phishing_model.pkl` saat pertama kali
> dijalankan. Database `phishing_logs.db` dibuat otomatis di `init_db()`.
> Untuk melatih ulang model, cukup hapus `phishing_model.pkl`.

---

## 🧠 Cara Kerja Deteksi

1. **Resolusi URL** — buka pemendek tautan jika ada, untuk mendapatkan tujuan asli.
2. **Skor Heuristik** (0–100) — 14 aturan indikator di `extract_features_and_score()`.
3. **Prediksi ML** (0–100) — Random Forest pada 19 fitur di `predict_ml()`.
4. **Skor Gabungan** = `0.5 × heuristik + 0.5 × ML`.
5. **Klasifikasi**:
   - ≥ 60 → **BAHAYA (PHISHING)**
   - 30 – 59 → **WASPADA (MENCURIGAKAN)**
   - < 30 → **AMAN (LEGITIMATE)**

---

## 📡 REST API

### `POST /api/v1/scan`
Endpoint utama untuk pemindaian URL secara terprogram.

**Request:**
```json
{ "url": "https://contoh.com/login" }
```

**Response (200 OK):**
```json
{
  "error": false,
  "scan_id": 42,
  "input_url": "https://contoh.com/login",
  "final_url": "https://contoh.com/login",
  "risk_score": 60,
  "status": "BAHAYA (PHISHING)",
  "reasons": [ { "param": "...", "detail": "...", "type": "danger" } ],
  "is_shortened": false,
  "ml_confidence": 58.4,
  "heuristic_score": 72,
  "model_version": "rf-v1.0",
  "timestamp": "2026-09-02T21:53:09.123456"
}
```

**Error (400):**
```json
{ "error": true, "message": "Parameter 'url' wajib diisi.", "code": 400 }
```

### `POST /api/scan`
Endpoint API lama (backward-compatible).

Contoh pemakaian dengan `curl`:
```bash
curl -X POST http://localhost:5000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://bit.ly/3xYz"}'
```

---

## 🗄️ Skema Database (`scan_logs`)

| Kolom | Tipe | Keterangan |
|---|---|---|
| `id` | INTEGER PK | ID baris |
| `input_url` | TEXT | URL yang dimasukkan pengguna |
| `final_url` | TEXT | URL tujuan asli (hasil unshorten) |
| `risk_score` | INTEGER | Skor akhir gabungan (0–100) |
| `status` | TEXT | BAHAYA / WASPADA / AMAN |
| `reasons` | TEXT | JSON daftar alasan deteksi |
| `user_feedback` | TEXT | Umpan balik pengguna |
| `client_ip` | TEXT | IP pemohon |
| `user_agent` | TEXT | User-Agent pemohon |
| `ml_confidence` | REAL | Probabilitas ML (0–1) |
| `heuristic_score` | INTEGER | Skor heuristik (0–100) |
| `created_at` | TIMESTAMP | Waktu pemindaian |

---

## 📁 Struktur Proyek

```
AntiPhishing_Project/
├── app.py               # Aplikasi Flask satu-file (logika, ML, DB, API)
├── requirements.txt     # Dependensi Python
├── templates/           # Template HTML (index, result, admin)
├── static/style.css     # Gaya halaman (tampilan)
├── .gitignore           # File/folder yang diabaikan git
└── AGENTS.md            # Instruksi untuk agent OpenCode
```

---

## 📚 Teknologi

- **Flask** — web framework
- **scikit-learn** — Random Forest classifier
- **python-whois** — pemeriksaan umur domain
- **requests** / **urllib3** — HTTP & unshorten URL
- **SQLite** — penyimpanan log audit

---

## 📝 Catatan

- Model dilatih pada **dataset sintetis**; akurasi ~100% pada data latih namun performa
  dunia nyata berbeda. Untuk keperluan produksi/penelitian, ganti dengan dataset publik
  terverifikasi (mis. `phishtank`, `openphish`).
- SSL verification dinonaktifkan secara global (diperlukan untuk unshorten URL).
