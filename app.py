import os
import re
import sqlite3
import json
import ssl
import socket
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse

import requests
import urllib3
from flask import Flask, render_template, request, redirect, url_for, jsonify

# Impor opsional: Machine Learning (scikit-learn + numpy)
try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# Impor opsional: WHOIS Lookup
try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

# Matikan peringatan SSL insecure saat mengurai link pendek
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
DB_NAME = "phishing_logs.db"
MODEL_PATH = "phishing_model.pkl"

# ==========================================
# KONSTAN APLIKASI
# ==========================================
# Pola alamat IP (IPv4) dalam berbagai representasi dikenal sebagai teknik
# phishing untuk menyamarkan tujuan: desimal bertitik, integer tunggal,
# heksadesimal, oktal, dan bentuk pendek (mis. 127.1 atau 127.0.1).
IP_HOST_PATTERN = re.compile(
    r'^(?:(?:\d{1,3}\.){3}\d{1,3}|'   # 192.168.1.1 (dotted decimal)
    r'\d{1,10}|'                       # 2130706433 (integer)
    r'0x[0-9a-fA-F]+|'                 # 0x7f000001 (hex)
    r'0[0-7]+|'                        # 017700000001 (octal)
    r'\d{1,3}\.\d{1,3})$'              # 127.1 (short form)
)

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "account", "banking", "secure",
    "dana", "gopay", "bca", "bri", "mandiri", "bni", "promo",
    "gratis", "klaim", "hadiah", "undian", "bantuan", "pulsa", "paket",
    "confirm", "signin", "password", "credential", "auth",
    "secure-account", "verify-account", "update-account",
    "banking-login", "login-secure", "web-app", "cgi-bin"
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "s.id", "cutt.ly", "t.co",
    "is.gd", "buff.ly", "ow.ly", "rebrand.ly", "linktr.ee",
    "rb.gy", "shorturl.at", "tiny.cc", "goo.gl", "dwz.cn",
    "v.gd", "qr.ae", "adf.ly", "bc.vc", "shorte.st"
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".work",
    ".buzz", ".club", ".online", ".site", ".info", ".biz", ".icu",
    ".fit", ".monster", ".surf", ".rest"
]

# Nama fitur untuk model ML (harus konsisten saat training & prediksi)
ML_FEATURE_NAMES = [
    'url_length', 'hostname_length', 'num_dots', 'num_hyphens',
    'num_underscores', 'num_slashes', 'num_at_symbols', 'num_digits',
    'has_https', 'has_ip_address', 'is_shortened', 'num_subdomains',
    'num_suspicious_keywords', 'has_risky_tld', 'num_question_marks',
    'num_equals', 'num_ampersands', 'path_length', 'has_port'
]


# ==========================================
# 1. INISIALISASI BASIS DATA (SQLite)
# ==========================================
def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_url TEXT NOT NULL,
            final_url TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            status TEXT NOT NULL,
            reasons TEXT NOT NULL,
            user_feedback TEXT DEFAULT 'Belum Ada',
            client_ip TEXT DEFAULT '',
            user_agent TEXT DEFAULT '',
            ml_confidence REAL DEFAULT 0.0,
            heuristic_score INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


def migrate_db():
    """Tambah kolom baru secara manual jika belum ada (tanpa menghapus data lama)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    columns_to_add = [
        ("client_ip", "TEXT DEFAULT ''"),
        ("user_agent", "TEXT DEFAULT ''"),
        ("ml_confidence", "REAL DEFAULT 0.0"),
        ("heuristic_score", "INTEGER DEFAULT 0"),
    ]
    for col_name, col_type in columns_to_add:
        try:
            cursor.execute(f"ALTER TABLE scan_logs ADD COLUMN {col_name} {col_type}")
        except sqlite3.OperationalError:
            pass
    conn.commit()
    conn.close()


init_db()
migrate_db()


# ==========================================
# 2. MODEL PELAJARAN MESIN (Random Forest)
# ==========================================
def extract_ml_features(url, is_shortened=False):
    """Ekstrak fitur leksikal & struktural dari URL untuk model ML."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or parsed.netloc).lower()

    features = {
        'url_length': len(url),
        'hostname_length': len(hostname),
        'num_dots': hostname.count('.'),
        'num_hyphens': hostname.count('-'),
        'num_underscores': url.count('_'),
        'num_slashes': url.count('/'),
        'num_at_symbols': url.count('@'),
        'num_digits': sum(c.isdigit() for c in hostname),
        'has_https': 1 if url.startswith('https://') else 0,
        'has_ip_address': 1 if re.match(IP_HOST_PATTERN, hostname) else 0,
        'is_shortened': 1 if is_shortened else 0,
        'num_subdomains': max(len(hostname.split('.')) - 2, 0),
        'num_suspicious_keywords': sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()),
        'has_risky_tld': 1 if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0,
        'num_question_marks': url.count('?'),
        'num_equals': url.count('='),
        'num_ampersands': url.count('&'),
        'path_length': len(parsed.path),
        'has_port': 1 if parsed.port else 0,
    }
    return features


def features_to_vector(features):
    """Ubah dict fitur menjadi vektor numerik sesuai urutan ML_FEATURE_NAMES."""
    return [features[name] for name in ML_FEATURE_NAMES]


def generate_training_data():
    """Buat dataset sintetis berdasarkan pola phishing dan domain sah yang diketahui."""
    np.random.seed(42)
    X = []
    y = []

    # --- Sampel Phishing (label = 1) ---
    for _ in range(600):
        features = [
            np.random.randint(65, 260),                          # url_length
            np.random.randint(18, 85),                           # hostname_length
            np.random.randint(3, 9),                             # num_dots
            np.random.randint(2, 9),                             # num_hyphens
            np.random.randint(0, 6),                             # num_underscores
            np.random.randint(3, 12),                            # num_slashes
            np.random.choice([0, 0, 0, 1, 2]),                  # num_at_symbols
            np.random.randint(2, 18),                            # num_digits
            np.random.choice([0, 1], p=[0.7, 0.3]),             # has_https
            np.random.choice([0, 1], p=[0.55, 0.45]),           # has_ip_address
            np.random.choice([0, 1], p=[0.45, 0.55]),           # is_shortened
            np.random.randint(3, 8),                             # num_subdomains
            np.random.randint(1, 7),                             # num_suspicious_keywords
            np.random.choice([0, 1], p=[0.35, 0.65]),           # has_risky_tld
            np.random.randint(0, 5),                             # num_question_marks
            np.random.randint(0, 6),                             # num_equals
            np.random.randint(0, 5),                             # num_ampersands
            np.random.randint(15, 120),                          # path_length
            np.random.choice([0, 1], p=[0.75, 0.25]),           # has_port
        ]
        X.append(features)
        y.append(1)

    # --- Sampel Sah / Legitimate (label = 0) ---
    for _ in range(600):
        features = [
            np.random.randint(12, 65),                           # url_length
            np.random.randint(6, 28),                            # hostname_length
            np.random.randint(2, 4),                             # num_dots
            np.random.randint(0, 2),                             # num_hyphens
            np.random.randint(0, 1),                             # num_underscores
            np.random.randint(1, 5),                             # num_slashes
            0,                                                   # num_at_symbols
            np.random.randint(0, 3),                             # num_digits
            np.random.choice([0, 1], p=[0.05, 0.95]),            # has_https
            0,                                                   # has_ip_address
            np.random.choice([0, 1], p=[0.88, 0.12]),            # is_shortened
            np.random.randint(0, 3),                             # num_subdomains
            np.random.randint(0, 2),                             # num_suspicious_keywords
            np.random.choice([0, 1], p=[0.92, 0.08]),            # has_risky_tld
            np.random.randint(0, 2),                             # num_question_marks
            np.random.randint(0, 2),                             # num_equals
            np.random.randint(0, 2),                             # num_ampersands
            np.random.randint(3, 45),                            # path_length
            0,                                                   # has_port
        ]
        X.append(features)
        y.append(0)

    return np.array(X, dtype=np.float32), np.array(y, dtype=np.float32)


def train_and_save_model():
    """Latih model Random Forest dan simpan ke disk."""
    if not ML_AVAILABLE:
        return None

    X, y = generate_training_data()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=120, max_depth=12, random_state=42, n_jobs=-1
    )
    model.fit(X_train, y_train)

    acc_train = model.score(X_train, y_train)
    acc_test = model.score(X_test, y_test)
    print(f"[ML] Model Random Forest berhasil dilatih.")
    print(f"[ML] Akurasi pelatihan : {acc_train:.2%}")
    print(f"[ML] Akurasi pengujian : {acc_test:.2%}")

    joblib.dump(model, MODEL_PATH)
    return model


def load_or_train_model():
    """Muat model dari disk atau latih baru jika belum ada."""
    if not ML_AVAILABLE:
        return None
    if os.path.exists(MODEL_PATH):
        print("[ML] Memuat model dari disk...")
        return joblib.load(MODEL_PATH)
    else:
        print("[ML] Model belum ada, memulai pelatihan awal...")
        return train_and_save_model()


ml_model = load_or_train_model()


def predict_ml(url, is_shortened=False):
    """Prediksi probabilitas phishing menggunakan model ML. Mengembalikan 0.0 - 1.0."""
    if ml_model is None:
        return 0.5
    features = extract_ml_features(url, is_shortened)
    vector = features_to_vector(features)
    proba = ml_model.predict_proba([vector])[0]
    return float(proba[1])


# ==========================================
# 3. MODUL PENGURAI TAUTAN PENDEK (UNSHORTENER)
# ==========================================
def resolve_url(url):
    """Buka tujuan asli jika URL menggunakan layanan pemendek tautan."""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    is_shortened = any(shortener in domain for shortener in SHORTENER_DOMAINS)
    final_url = url

    if is_shortened:
        try:
            response = requests.head(
                url,
                allow_redirects=True,
                timeout=5,
                verify=False,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                                  "Chrome/120.0.0.0 Safari/537.36"
                }
            )
            # Beberapa layanan pemendek menolak HEAD, fallback ke GET
            if response.status_code == 405:
                response = requests.get(
                    url,
                    allow_redirects=True,
                    timeout=5,
                    verify=False,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                                      "Chrome/120.0.0.0 Safari/537.36"
                    }
                )
            final_url = response.url
        except Exception:
            final_url = url

    return url, final_url, is_shortened


# ==========================================
# 4. PEMERIKSAAN SSL & DOMAIN (WHOIS)
# ==========================================
# Cache hasil WHOIS agar pemindaian domain yang sama tidak berulang-ulang
_whois_cache = {}


def get_domain_age(domain):
    """Dapatkan umur domain (dalam hari) via WHOIS. Timeout 5 detik."""
    if not WHOIS_AVAILABLE:
        return None

    # Gunakan cache untuk domain yang sudah pernah dicek
    if domain in _whois_cache:
        return _whois_cache[domain]

    def _lookup():
        try:
            w = python_whois.whois(domain)
            if w.creation_date:
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if creation_date:
                    age_days = (datetime.now() - creation_date).days
                    return max(age_days, 0)
        except Exception:
            pass
        return None

    result = None
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_lookup)
        try:
            result = future.result(timeout=5)
        except (concurrent.futures.TimeoutError, Exception):
            result = None

    _whois_cache[domain] = result
    return result


def check_ssl_cert(hostname):
    """Periksa validitas sertifikat SSL. Mengembalikan (is_valid, days_left)."""
    def _check():
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    expires_str = cert.get('notAfter', '')
                    if expires_str:
                        expires = datetime.strptime(expires_str, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expires - datetime.now()).days
                        return True, days_left
                    return True, None
        except Exception:
            return False, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_check)
        try:
            return future.result(timeout=5)
        except (concurrent.futures.TimeoutError, Exception):
            return False, None


# ==========================================
# 5. MODUL EKSTRAKSI FITUR & SKORING HEURISTIK
# ==========================================
def extract_features_and_score(input_url, final_url, is_shortened):
    """Analisis heuristik URL berdasarkan pola struktural dan leksikal."""
    reasons = []
    score = 0

    parsed = urlparse(final_url)
    hostname = (parsed.hostname or parsed.netloc).lower()
    full_url = final_url.lower()

    # 1. URL Shortener (+15)
    if is_shortened:
        score += 15
        reasons.append({
            "param": "URL Shortener",
            "detail": "Tautan disembunyikan memakai layanan pemendek URL untuk mengelabui tujuan aslinya.",
            "type": "warning"
        })

    # 2. Alamat IP mentah (+30)
    # Deteksi berbagai bentuk pengkodean IP: desimal bertitik, integer,
    # heksadesimal, oktal, dan bentuk pendek.
    if re.match(IP_HOST_PATTERN, hostname):
        score += 30
        reasons.append({
            "param": "Alamat IP Mentah",
            "detail": "Tautan memakai deretan angka IP tanpa nama domain resmi, ciri khas server penipuan.",
            "type": "danger"
        })

    # 3. Ketiadaan HTTPS (+20)
    if not final_url.startswith("https://"):
        score += 20
        reasons.append({
            "param": "Ketiadaan HTTPS (Tidak Terenkripsi)",
            "detail": "Koneksi ke website ini tidak aman dan data yang dimasukkan rawan disadap.",
            "type": "danger"
        })

    # 4. Panjang URL > 75 (+15)
    if len(final_url) > 75:
        score += 15
        reasons.append({
            "param": "Panjang URL Ekstrem",
            "detail": f"Panjang link mencapai {len(final_url)} karakter. Berpotensi menyembunyikan parameter manipulatif.",
            "type": "warning"
        })

    # 5. Simbol @ (+25)
    if "@" in final_url:
        score += 25
        reasons.append({
            "param": "Simbol Manipulasi (@)",
            "detail": "Penggunaan simbol '@' memanipulasi browser untuk mengabaikan teks domain sebelumnya.",
            "type": "danger"
        })

    # 6. Tanda hubung ganda pada domain (+15)
    if hostname.count("-") >= 2:
        score += 15
        reasons.append({
            "param": "Domain Meniru (Karakter '-')",
            "detail": "Domain mengandung banyak tanda hubung (-), sering dipakai memalsukan merek asli.",
            "type": "warning"
        })

    # 7. Subdomain bertingkat (+15)
    subdomain_count = len(hostname.split(".")) - 2
    if subdomain_count >= 3:
        score += 15
        reasons.append({
            "param": "Banyak Subdomain",
            "detail": "Struktur subdomain bertingkat banyak sering dimanfaatkan untuk menyamarkan domain asli.",
            "type": "warning"
        })

    # 8. Kata kunci jebakan (+20)
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
    if found_keywords:
        score += 20
        reasons.append({
            "param": "Kata Kunci Berisiko",
            "detail": f"Ditemukan kata pemicu rekayasa sosial: {', '.join(found_keywords[:5])}.",
            "type": "warning"
        })

    # 9. TLD Berisiko (+15)
    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 15
        reasons.append({
            "param": "Ekstensi Domain (TLD) Berisiko",
            "detail": "Domain terdaftar pada TLD berbiaya murah yang sering digunakan untuk kampanye spam siber.",
            "type": "warning"
        })

    # 10. Banyak angka pada hostname (+10)
    digit_count = sum(c.isdigit() for c in hostname)
    if digit_count >= 5:
        score += 10
        reasons.append({
            "param": "Banyak Digit pada Domain",
            "detail": f"Domain mengandung {digit_count} digit angka, ciri khas pembuatan URL otomatis.",
            "type": "warning"
        })

    # 11. Port tidak lazim (+10)
    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        score += 10
        reasons.append({
            "param": "Port Tidak Lazim",
            "detail": f"URL menggunakan port {parsed.port} yang jarang dipakai situs resmi.",
            "type": "warning"
        })

    # 12. Banyak parameter query (+10)
    if final_url.count('?') >= 2 or final_url.count('&') >= 3:
        score += 10
        reasons.append({
            "param": "Banyak Parameter Query",
            "detail": "URL memiliki banyak parameter query string, bisa menyembunyikan data manipulatif.",
            "type": "warning"
        })

    # 13. Domain umur muda via WHOIS (+15)
    # Lewati jika URL memakai IP mentah (bukan nama domain) atau sudah dipendekkan
    if not is_shortened and not re.match(IP_HOST_PATTERN, hostname):
        domain_age = get_domain_age(hostname)
        if domain_age is not None and domain_age < 180:
            score += 15
            reasons.append({
                "param": "Domain Berumur Sangat Muda",
                "detail": f"Domain baru berumur {domain_age} hari. Domain phishing biasanya baru dibuat.",
                "type": "danger"
            })

    # 14. Sertifikat SSL tidak valid (+15)
    if final_url.startswith("https://"):
        ssl_valid, ssl_days = check_ssl_cert(hostname)
        if not ssl_valid:
            score += 15
            reasons.append({
                "param": "Sertifikat SSL Tidak Valid",
                "detail": "Sertifikat SSL domain ini tidak valid atau tidak ditemukan.",
                "type": "danger"
            })
        elif ssl_days is not None and ssl_days < 30:
            score += 10
            reasons.append({
                "param": "Sertifikat SSL Hampir Habis",
                "detail": f"Sertifikat SSL akan berakhir dalam {ssl_days} hari.",
                "type": "warning"
            })

    score = min(score, 100)

    return score, reasons


# ==========================================
# 6. PENGHITUNGAN SKOR GABUNGAN (Heuristik + ML)
# ==========================================
def calculate_final_score(heuristic_score, ml_confidence):
    """
    Menggabungkan skor heuristik dan prediksi ML.
    - heuristic_score : 0-100 (dari aturan if-else)
    - ml_confidence   : 0.0-1.0 (probabilitas phishing dari Random Forest)
    Rasio: 50% heuristik + 50% ML.
    """
    ml_score = int(ml_confidence * 100)
    final = int(0.5 * heuristic_score + 0.5 * ml_score)
    return min(final, 100)


# ==========================================
# 7. PROSES PEMINDAIAN & PENYIMPANAN
# ==========================================
def process_and_save_scan(raw_url, client_ip='', user_agent=''):
    """Fungsi utama: menjalankan pemindaian penuh dan menyimpan log ke database."""
    orig_url, fin_url, is_short = resolve_url(raw_url)

    # Skor heuristik
    h_score, reasons = extract_features_and_score(orig_url, fin_url, is_short)

    # Prediksi ML
    ml_conf = predict_ml(fin_url, is_short)

    # Skor gabungan
    final_score = calculate_final_score(h_score, ml_conf)

    # Penentuan status akhir berdasarkan skor gabungan
    if final_score >= 60:
        status = "BAHAYA (PHISHING)"
    elif final_score >= 30:
        status = "WASPADA (MENCURIGAKAN)"
    else:
        status = "AMAN (LEGITIMATE)"
        if not reasons:
            reasons.append({
                "param": "Struktur Tautan Terverifikasi",
                "detail": "Format domain, protokol HTTPS, dan teks tautan sesuai standar keamanan wajar.",
                "type": "success"
            })

    # Simpan ke database
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scan_logs
                (input_url, final_url, risk_score, status, reasons,
                 client_ip, user_agent, ml_confidence, heuristic_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            orig_url, fin_url, final_score, status, json.dumps(reasons),
            client_ip, user_agent, round(ml_conf, 4), h_score
        ))
        scan_id = cursor.lastrowid
        conn.commit()
    finally:
        if conn:
            conn.close()

    return {
        "scan_id": scan_id,
        "input_url": orig_url,
        "final_url": fin_url,
        "risk_score": final_score,
        "status": status,
        "reasons": reasons,
        "is_shortened": is_short,
        "ml_confidence": round(ml_conf * 100, 2),
        "heuristic_score": h_score,
    }


# ==========================================
# 8. RUTE APLIKASI WEB
# ==========================================
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        input_url = request.form.get("url", "").strip()
        if not input_url:
            return redirect(url_for("index"))
        client_ip = request.remote_addr or ''
        user_agent = request.headers.get('User-Agent', '')
        result = process_and_save_scan(input_url, client_ip, user_agent)
        return render_template("result.html", **result)
    return render_template("index.html")


@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "POST":
        input_url = request.form.get("url", "").strip()
        if not input_url:
            return redirect(url_for("index"))
        client_ip = request.remote_addr or ''
        user_agent = request.headers.get('User-Agent', '')
        result = process_and_save_scan(input_url, client_ip, user_agent)
        return render_template("result.html", **result)
    return redirect(url_for("index"))


@app.route("/feedback", methods=["POST"])
def feedback():
    scan_id = request.form.get("scan_id", "").strip()
    feedback_value = request.form.get("feedback", "").strip()

    if scan_id and feedback_value:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE scan_logs
                SET user_feedback = ?
                WHERE id = ?
            ''', (feedback_value, int(scan_id)))
            conn.commit()
        except (ValueError, sqlite3.Error):
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    return redirect(url_for("admin"))


@app.route("/admin")
def admin():
    conn = None
    try:
        conn = get_db_connection()
        logs = conn.execute(
            'SELECT * FROM scan_logs ORDER BY created_at DESC LIMIT 50'
        ).fetchall()
    except sqlite3.Error:
        conn = None
        logs = []
    finally:
        if conn:
            conn.close()
    return render_template("admin.html", logs=logs)


# --- API endpoint lama (backward-compatible) ---
@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "Parameter url diperlukan"}), 400

    client_ip = request.remote_addr or ''
    user_agent = request.headers.get('User-Agent', '')
    result = process_and_save_scan(url, client_ip, user_agent)
    return jsonify(result)


# --- API v1 (REST endpoint baru) ---
@app.route("/api/v1/scan", methods=["POST"])
def api_v1_scan():
    """
    REST API v1 untuk pemindaian URL.
    Request  : POST JSON { "url": "https://..." }
    Response : JSON { scan_id, input_url, final_url, risk_score, status,
                       reasons, is_shortened, ml_confidence, heuristic_score,
                       model_version, timestamp }
    """
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({
            "error": True,
            "message": "Parameter 'url' wajib diisi.",
            "code": 400
        }), 400

    client_ip = request.remote_addr or ''
    user_agent = request.headers.get('User-Agent', '')
    result = process_and_save_scan(url, client_ip, user_agent)

    result["model_version"] = "rf-v1.0"
    result["timestamp"] = datetime.now().isoformat()
    result["error"] = False

    return jsonify(result), 200


# ==========================================
# 9. JALANKAN APLIKASI
# ==========================================
if __name__ == "__main__":
    app.run(debug=True, port=5000)
