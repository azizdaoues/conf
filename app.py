from flask import Flask, request, jsonify
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib

app = Flask(_name_)

# =============================
# 🔹 Configuration
# =============================

DB_CONFIG = {
    'host': '10.0.0.13',         # VM PostgreSQL
    'port': 5432,
    'database': 'banking_db',
    'user': 'banking_user',
    'password': 'Postgresql'  # Ton mot de passe PostgreSQL
}

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "azizdaoues20@gmail.com"
SMTP_PASS = "lbae ltxz nshs vjqw"

# Stockage temporaire des codes MFA
mfa_codes = {}  # { "username": {"code":123456, "expire":datetime} }

# =============================
# 🔹 Fonctions utilitaires
# =============================

def get_db_connection():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        print("Erreur connexion DB:", e)
        return None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def send_email(to_email, subject, body):
    try:
        msg = MIMEText(body)
        msg["From"] = SMTP_USER
        msg["To"] = to_email
        msg["Subject"] = subject

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        print(f"✅ Email MFA envoyé à {to_email}")
        return True
    except Exception as e:
        print(f"❌ Erreur envoi email : {e}")
        return False

# =============================
# 🔹 Routes API
# =============================

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"status": "error", "message": "Champs manquants"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "error", "message": "Erreur serveur BDD"}), 500

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT id, username, email, role, password_hash 
            FROM users 
            WHERE username = %s
        """, (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            return jsonify({"status": "error", "message": "Utilisateur introuvable"}), 401

        if user["password_hash"] != hash_password(password):
            return jsonify({"status": "error", "message": "Mot de passe incorrect"}), 401

        # Générer le code MFA
        code = random.randint(100000, 999999)
        expire = datetime.now() + timedelta(minutes=5)
        mfa_codes[username] = {"code": code, "expire": expire, "role": user["role"]}

        body = f"""
Bonjour {username},

Votre code MFA est : {code}
Il est valable 5 minutes.

-- Système Bancaire Sécurisé
"""
        send_email(user["email"], "Votre code MFA", body)

        return jsonify({"status": "ok", "mfa_required": True}), 200

    except Exception as e:
        print("Erreur /login :", e)
        return jsonify({"status": "error", "message": "Erreur serveur"}), 500


@app.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    data = request.json
    username = data.get('username')
    code = data.get('code')

    if username not in mfa_codes:
        return jsonify({"status": "error", "message": "Aucun code MFA actif"}), 401

    record = mfa_codes[username]
    if datetime.now() > record["expire"]:
        del mfa_codes[username]
        return jsonify({"status": "error", "message": "Code expiré"}), 401

    if str(code) == str(record["code"]):
        role = record["role"]
        del mfa_codes[username]
        return jsonify({"status": "ok", "role": role}), 200
    else:
        return jsonify({"status": "error", "message": "Code incorrect"}), 401


if _name_ == '_main_':
    app.run(host='0.0.0.0', port=5000)
