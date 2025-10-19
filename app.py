from flask import Flask, request, jsonify, session, make_response
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib
import logging

app = Flask(__name__)
app.secret_key = 'ChangeMeInProduction2025!SecureKey'

# === Configuration Logging ===
logging.basicConfig(
    filename='/var/log/banking-app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# === Configuration Email (Gmail) ===
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'azizdaoues20@gmail.com',
    'sender_password': 'lbae ltxz nshs vjqw'
}

# === Configuration Base de Données PostgreSQL ===
DB_CONFIG = {
    'host': '10.0.0.13',
    'port': 5432,
    'database': 'banking_db',
    'user': 'banking_user',
    'password': 'Postgresql',
    'sslmode': 'require'
}

# === Stockage temporaire MFA ===
mfa_codes = {}

# === Middleware CORS Flask natif ===
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    return response

@app.before_request
def handle_options_request():
    if request.method == 'OPTIONS':
        resp = make_response()
        resp.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        return resp, 200

# === Fonctions Utilitaires ===
def get_db_connection():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        logging.error(f"Erreur connexion DB: {str(e)}")
        return None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def send_mfa_email(recipient, code, username):
    try:
        msg = MIMEText(f"""
Bonjour {username},

Votre code de vérification MFA est : {code}

Ce code est valable pendant 5 minutes.

⚠️ Si vous n'êtes pas à l'origine de cette demande, ignorez ce message.

Cordialement,
Système Bancaire Sécurisé
        """)
        msg['Subject'] = '🔐 Code MFA - Connexion Bancaire'
        msg['From'] = EMAIL_CONFIG['sender_email']
        msg['To'] = recipient

        with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
            server.starttls()
            server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
            server.send_message(msg)
        
        logging.info(f"Code MFA envoyé à {recipient}")
        return True
    except Exception as e:
        logging.error(f"Erreur envoi email: {str(e)}")
        return False

# === Routes Authentification ===
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    logging.info(f"Tentative connexion: {username} depuis {request.remote_addr}")
    
    if not username or not password:
        return jsonify({'status': 'error', 'message': 'Champs requis manquants'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'Erreur serveur'}), 500
    
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        password_hash = hash_password(password)
        cursor.execute("""
            SELECT id, username, email, role, is_active 
            FROM users 
            WHERE username = %s AND password_hash = %s
        """, (username, password_hash))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not user:
            return jsonify({'status': 'error', 'message': 'Identifiants incorrects'}), 401
        
        if not user['is_active']:
            return jsonify({'status': 'error', 'message': 'Compte désactivé'}), 403
        
        mfa_code = str(random.randint(100000, 999999))
        mfa_codes[username] = {
            'code': mfa_code,
            'expiry': datetime.now() + timedelta(minutes=5),
            'email': user['email'],
            'role': user['role'],
            'user_id': user['id']
        }
        
        if send_mfa_email(user['email'], mfa_code, username):
            return jsonify({
                'status': 'ok',
                'mfa_required': True,
                'message': 'Code MFA envoyé par email',
                'email_masked': user['email'][:3] + '***@' + user['email'].split('@')[1]
            }), 200
        else:
            return jsonify({'status': 'error', 'message': 'Erreur envoi email'}), 500
            
    except Exception as e:
        logging.error(f"Erreur login: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Erreur serveur'}), 500

@app.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    data = request.get_json()
    username = data.get('username', '').strip()
    code = data.get('code', '').strip()
    
    if not username or not code:
        return jsonify({'status': 'error', 'message': 'Données manquantes'}), 400
    
    stored = mfa_codes.get(username)
    if not stored:
        return jsonify({'status': 'error', 'message': 'Code non valide'}), 401
    if datetime.now() > stored['expiry']:
        del mfa_codes[username]
        return jsonify({'status': 'error', 'message': 'Code expiré'}), 401
    if stored['code'] != code:
        return jsonify({'status': 'error', 'message': 'Code incorrect'}), 401
    
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET last_login = %s WHERE id = %s",
                (datetime.now(), stored['user_id'])
            )
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            logging.error(f"Erreur mise à jour last_login: {str(e)}")
    
    session['username'] = username
    session['role'] = stored['role']
    session['user_id'] = stored['user_id']
    del mfa_codes[username]
    
    return jsonify({
        'status': 'ok',
        'message': 'Connexion réussie',
        'username': username,
        'role': stored['role']
    }), 200

# === Autres routes (comptes, virement, transactions, user-info, logout) ===
# inchangées — tu peux garder exactement les mêmes fonctions ici.
# Je n’ai modifié que la partie CORS.

@app.route('/logout', methods=['POST'])
def logout():
    username = session.get('username', 'Unknown')
    session.clear()
    logging.info(f"Déconnexion: {username}")
    return jsonify({'status': 'ok', 'message': 'Déconnexion réussie'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
