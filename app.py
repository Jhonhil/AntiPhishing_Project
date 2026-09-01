from flask import Flask, render_template, request, redirect, url_for
import requests
import base64
import mysql.connector

app = Flask(__name__)

# --- KONFIGURASI ---
# Ganti dengan API Key VirusTotal Anda
API_KEY = "00c144e46af49e046a2e0026bdbb89593a255bbd55e86a77e6c802624afab0f6" 

# Fungsi Koneksi Database
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="", # Kosongkan jika menggunakan XAMPP standar
        database="db_antiphishing"
    )

# --- FUNGSI LOGIKA DETEKSI ---

def check_url_virustotal(url):
    try:
        # Encode URL ke Base64 tanpa padding sesuai dokumentasi VT API v3
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        headers = {"x-apikey": API_KEY}
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Error API: {e}")
        return None

def get_education_content():
    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM tb_edukasi ORDER BY id DESC")
        results = cursor.fetchall()
        cursor.close()
        db.close()
        return results
    except Exception as e:
        print(f"Error Database: {e}")
        return []

# --- ROUTES (ALUR HALAMAN) ---

# 1. HALAMAN UTAMA (USER)
@app.route('/')
def index():
    materi = get_education_content()
    return render_template('index.html', edukasi=materi)

# 2. PROSES SCAN URL
@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form.get('url')
    if not target_url:
        return "Silakan masukkan URL!"

    data = check_url_virustotal(target_url)
    
    if data:
        stats = data['data']['attributes']['last_analysis_stats']
        is_malicious = stats['malicious'] > 0
        return render_template('result.html', url=target_url, stats=stats, malicious=is_malicious)
    else:
        return "Gagal menganalisis URL. Pastikan API Key benar dan URL valid."

# 3. HALAMAN ADMIN (MANAJEMEN KONTEN)
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    if request.method == 'POST':
        judul = request.form.get('judul')
        konten = request.form.get('konten')
        kategori = request.form.get('kategori')
        
        query = "INSERT INTO tb_edukasi (judul, konten, kategori) VALUES (%s, %s, %s)"
        cursor.execute(query, (judul, konten, kategori))
        db.commit()
        return redirect(url_for('admin'))

    cursor.execute("SELECT * FROM tb_edukasi ORDER BY id DESC")
    materi = cursor.fetchall()
    cursor.close()
    db.close()
    return render_template('admin.html', edukasi=materi)

# 4. FITUR HAPUS EDUKASI
@app.route('/delete/<int:id>')
def delete(id):
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("DELETE FROM tb_edukasi WHERE id = %s", (id,))
    db.commit()
    cursor.close()
    db.close()
    return redirect(url_for('admin'))
@app.route('/materi/<int:id>')
def detail_materi(id):
    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        # Ambil materi dari database berdasarkan ID yang diklik
        cursor.execute("SELECT * FROM tb_edukasi WHERE id = %s", (id,))
        materi = cursor.fetchone()
        cursor.close()
        db.close()
        
        if materi:
            # Pastikan nama file di bawah ini adalah detail.html
            return render_template('detail.html', item=materi)
        else:
            return "Materi tidak ditemukan!", 404
    except Exception as e:
        return f"Terjadi kesalahan database: {e}"
    
# --- MENJALANKAN APLIKASI (HARUS DI PALING BAWAH) ---
if __name__ == '__main__':
    app.run(debug=True)
    
