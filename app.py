from flask import Flask, request, jsonify
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib

app = Flask(__name__)

# =============================
# 🔹 Configuration
# =============================

DB_CONFIG = {
    'host': '10.0.0.13',         # VM PostgreSQL
    'port': 5432,
    'database': 'banking_db',
    'user': 'banking_user',
    'password': 'Postgresql'  # Mot de passe PostgreSQL
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
    """Connexion à PostgreSQL"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        print("❌ Erreur connexion DB:", e)
        return None

def hash_password(password):
    """Hash SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def send_email(to_email, subject, body):
    """Envoi d’un email via Gmail"""
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
# 🔹 Routes API Authentification
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

# =============================
# 🔹 Autres routes API
# =============================

@app.route('/api/comptes', methods=['GET'])
def get_comptes():
    """Liste tous les comptes actifs"""
    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "error", "message": "Erreur base de données"}), 500

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT c.id, c.numero_compte, c.type_compte, c.solde, c.devise, c.statut,
                   cl.nom, cl.prenom, cl.email
            FROM comptes c
            JOIN clients cl ON c.client_id = cl.id
            WHERE c.statut = 'actif'
            ORDER BY cl.nom;
        """)
        comptes = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({"status": "ok", "comptes": comptes}), 200
    except Exception as e:
        print("Erreur /api/comptes:", e)
        return jsonify({"status": "error", "message": "Erreur serveur"}), 500


@app.route('/api/transactions', methods=['GET'])
def get_transactions():
    """Historique des transactions récentes"""
    limit = request.args.get('limit', 50)
    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "error", "message": "Erreur DB"}), 500

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(f"""
            SELECT t.id, t.montant, t.type_transaction, t.description, 
                   t.date_transaction, cs.numero_compte AS compte_source,
                   cd.numero_compte AS compte_dest
            FROM transactions t
            LEFT JOIN comptes cs ON t.compte_source_id = cs.id
            LEFT JOIN comptes cd ON t.compte_dest_id = cd.id
            ORDER BY t.date_transaction DESC
            LIMIT %s;
        """, (limit,))
        transactions = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({"status": "ok", "transactions": transactions}), 200
    except Exception as e:
        print("Erreur /api/transactions:", e)
        return jsonify({"status": "error", "message": "Erreur serveur"}), 500


@app.route('/api/virement', methods=['POST'])
def virement():
    """Effectuer un virement entre deux comptes"""
    data = request.json
    source = data.get('compte_source_id')
    dest = data.get('compte_dest_id')
    montant = data.get('montant')
    description = data.get('description', '')

    if not all([source, dest, montant]):
        return jsonify({"status": "error", "message": "Champs manquants"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "error", "message": "Erreur DB"}), 500

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT solde FROM comptes WHERE id = %s", (source,))
        solde = cur.fetchone()
        if not solde or solde["solde"] < float(montant):
            return jsonify({"status": "error", "message": "Solde insuffisant"}), 400

        cur.execute("BEGIN;")
        cur.execute("UPDATE comptes SET solde = solde - %s WHERE id = %s;", (montant, source))
        cur.execute("UPDATE comptes SET solde = solde + %s WHERE id = %s;", (montant, dest))
        cur.execute("""
            INSERT INTO transactions (compte_source_id, compte_dest_id, montant, type_transaction, description)
            VALUES (%s, %s, %s, 'virement', %s);
        """, (source, dest, montant, description))
        cur.execute("COMMIT;")

        cur.close()
        conn.close()
        return jsonify({"status": "ok", "message": "Virement effectué"}), 200

    except Exception as e:
        print("Erreur /api/virement:", e)
        conn.rollback()
        return jsonify({"status": "error", "message": "Erreur lors du virement"}), 500


@app.route('/logout', methods=['POST'])
def logout():
    """Déconnexion"""
    return jsonify({"status": "ok", "message": "Déconnexion réussie"}), 200


@app.route('/health', methods=['GET'])
def health():
    """Vérifie si le backend est actif"""
    return jsonify({"status": "ok", "message": "Backend opérationnel"}), 200


# =============================
# 🔹 Lancement de l'application
# =============================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
