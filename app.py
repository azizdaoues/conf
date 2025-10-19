
from flask import Flask, request, jsonify, session
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib
import logging
import os

# -----------------------
# Configuration principale
# -----------------------
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'ChangeMeInProduction2025!SecureKey')


# Logging
LOGFILE = '/var/log/banking-app.log'
logging.basicConfig(
    filename=LOGFILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Email (Gmail) - renseigne correctement
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'azizdaoues20@gmail.com',
    'sender_password': 'lbae ltxz nshs vjqw'
}

# DB PostgreSQL - adapte ces valeurs (host doit être l'IP de la VM Postgres)
DB_CONFIG = {
    'host': '10.0.0.13',
    'port': 5432,
    'database': 'banking_db',
    'user': 'banking_user',
    'password': 'Postgresql',
    # si ton Postgres n'utilise pas SSL, passe à 'disable'
    'sslmode': 'disable'
}

# Stockage temporaire des codes MFA en mémoire
mfa_codes = {}  # { username: {code:str, expiry:datetime, email:str, role:str, user_id:int} }

# -----------------------
# Fonctions utilitaires
# -----------------------
def get_db_connection():
    """Retourne une connexion psycopg2 ou None et log l'erreur."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        logging.error(f"Erreur connexion DB: {e}")
        return None

def hash_password(password: str) -> str:
    """SHA256 hex digest (doit correspondre aux valeurs stockées en DB)."""
    return hashlib.sha256(password.encode()).hexdigest()

def send_mfa_email(recipient: str, code: str, username: str) -> bool:
    """Envoie le code MFA par SMTP. Retourne True si OK, False sinon."""
    try:
        body = f"""Bonjour {username},

Votre code de vérification MFA est : {code}

Ce code est valable pendant 5 minutes.

Si vous n'êtes pas à l'origine de cette demande, ignorez ce message.
Cordialement,
Système Bancaire Sécurisé
"""
        msg = MIMEText(body)
        msg['Subject'] = '🔐 Code MFA - Connexion Bancaire'
        msg['From'] = EMAIL_CONFIG['sender_email']
        msg['To'] = recipient

        with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
            server.starttls()
            server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
            server.send_message(msg)

        logging.info(f"Code MFA envoyé à {recipient} pour {username}")
        return True
    except Exception as e:
        logging.error(f"Erreur envoi email à {recipient}: {e}")
        return False

# -----------------------
# ROUTES AUTHENTIFICATION
# -----------------------
@app.route('/login', methods=['POST'])
def login():
    """Vérifie username/password en DB puis génère et envoie un code MFA."""
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    logging.info(f"Tentative connexion: '{username}' depuis {request.remote_addr}")

    if not username or not password:
        logging.warning("Champs manquants pour login")
        return jsonify({'status': 'error', 'message': 'Champs requis manquants'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'Erreur serveur (DB)'}), 500

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT id, username, email, role, is_active, password_hash
            FROM users
            WHERE username = %s
        """, (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            logging.warning(f"Utilisateur introuvable: {username}")
            return jsonify({'status': 'error', 'message': 'Identifiants incorrects'}), 401

        # Comparaison hashées
        if user.get('password_hash') != hash_password(password):
            logging.warning(f"Mot de passe incorrect pour {username}")
            return jsonify({'status': 'error', 'message': 'Identifiants incorrects'}), 401

        if user.get('is_active') is not None and not user['is_active']:
            logging.warning(f"Compte désactivé: {username}")
            return jsonify({'status': 'error', 'message': 'Compte désactivé'}), 403

        # Génération code MFA
        code = str(random.randint(100000, 999999))
        mfa_codes[username] = {
            'code': code,
            'expiry': datetime.now() + timedelta(minutes=5),
            'email': user['email'],
            'role': user['role'],
            'user_id': user['id']
        }

        ok = send_mfa_email(user['email'], code, username)
        if not ok:
            return jsonify({'status': 'error', 'message': 'Erreur envoi email'}), 500

        return jsonify({
            'status': 'ok',
            'mfa_required': True,
            'message': 'Code MFA envoyé par email',
            'email_masked': user['email'][:3] + '***@' + user['email'].split('@')[1]
        }), 200

    except Exception as e:
        logging.error(f"Erreur /login: {e}")
        return jsonify({'status': 'error', 'message': 'Erreur serveur'}), 500

@app.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    """Vérifie le code MFA et crée une session."""
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    code = (data.get('code') or '').strip()

    if not username or not code:
        return jsonify({'status': 'error', 'message': 'Données manquantes'}), 400

    stored = mfa_codes.get(username)
    if not stored:
        logging.warning(f"Aucun code MFA pour {username}")
        return jsonify({'status': 'error', 'message': 'Code non valide'}), 401

    if datetime.now() > stored['expiry']:
        del mfa_codes[username]
        logging.warning(f"Code MFA expiré pour {username}")
        return jsonify({'status': 'error', 'message': 'Code expiré'}), 401

    if stored['code'] != code:
        logging.warning(f"Code MFA incorrect pour {username}")
        return jsonify({'status': 'error', 'message': 'Code incorrect'}), 401

    # Mettre à jour last_login en DB (meilleure pratique)
    conn = get_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("UPDATE users SET last_login = %s WHERE id = %s",
                        (datetime.now(), stored['user_id']))
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            logging.error(f"Erreur mise à jour last_login: {e}")

    # Créer la session
    session['username'] = username
    # Normaliser role: backend s'attend à 'admin'/'agent'
    session['role'] = stored.get('role')
    session['user_id'] = stored.get('user_id')
    del mfa_codes[username]

    logging.info(f"Connexion réussie: {username} (role: {session['role']})")
    return jsonify({'status': 'ok', 'message': 'Connexion réussie', 'username': username, 'role': session['role']}), 200

# -----------------------
# ROUTES PROTÉGÉES (Admin)
# -----------------------
@app.route('/api/comptes', methods=['GET'])
def get_comptes():
    """Liste des comptes - accessible uniquement aux admins"""
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Non authentifié'}), 401
    if session.get('role') != 'admin':
        return jsonify({'status': 'error', 'message': 'Accès refusé - Admin requis'}), 403

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'Erreur base de données'}), 500

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT c.id, c.numero_compte, c.type_compte, c.solde, c.devise, c.statut,
                   cl.nom, cl.prenom, cl.email, cl.telephone
            FROM comptes c
            JOIN clients cl ON c.client_id = cl.id
            WHERE c.statut = 'actif'
            ORDER BY cl.nom, cl.prenom
        """)
        rows = cur.fetchall()
        cur.close()
        conn.close()
        logging.info(f"Consultation comptes par {session['username']}")
        return jsonify({'status': 'ok', 'comptes': rows}), 200
    except Exception as e:
        logging.error(f"Erreur get_comptes: {e}")
        return jsonify({'status': 'error', 'message': 'Erreur serveur'}), 500

@app.route('/api/virement', methods=['POST'])
def virement():
    """Effectuer un virement (Admin uniquement)"""
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Non authentifié'}), 401
    if session.get('role') != 'admin':
        return jsonify({'status': 'error', 'message': 'Accès refusé'}), 403

    data = request.get_json(silent=True) or {}
    compte_source = data.get('compte_source_id')
    compte_dest = data.get('compte_dest_id')
    montant = data.get('montant')
    description = data.get('description', '')

    if not all([compte_source, compte_dest, montant]):
        return jsonify({'status': 'error', 'message': 'Données manquantes'}), 400

    try:
        montant = float(montant)
        if montant <= 0:
            return jsonify({'status': 'error', 'message': 'Montant invalide'}), 400
    except Exception:
        return jsonify({'status': 'error', 'message': 'Montant invalide'}), 400

    if compte_source == compte_dest:
        return jsonify({'status': 'error', 'message': 'Comptes identiques'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'Erreur base de données'}), 500

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        # Vérifier solde existant
        cur.execute("SELECT solde FROM comptes WHERE id = %s AND statut = 'actif'", (compte_source,))
        row = cur.fetchone()
        if not row:
            cur.close(); conn.close()
            return jsonify({'status': 'error', 'message': 'Compte source invalide'}), 404

        if row['solde'] < montant:
            cur.close(); conn.close()
            logging.warning(f"Solde insuffisant - {session['username']} - Compte {compte_source}")
            return jsonify({'status': 'error', 'message': 'Solde insuffisant'}), 400

        # Effectuer transaction en SQL
        cur.execute("BEGIN")
        cur.execute("UPDATE comptes SET solde = solde - %s WHERE id = %s", (montant, compte_source))
        cur.execute("UPDATE comptes SET solde = solde + %s WHERE id = %s", (montant, compte_dest))
        cur.execute("""
            INSERT INTO transactions 
            (compte_source_id, compte_dest_id, montant, type_transaction, description, agent_username, date_transaction, statut)
            VALUES (%s, %s, %s, 'virement', %s, %s, NOW(), 'termine')
            RETURNING id
        """, (compte_source, compte_dest, montant, description, session['username']))
        transaction_id = cur.fetchone()['id']
        cur.execute("COMMIT")
        cur.close()
        conn.close()

        logging.info(f"Virement réussi - {session['username']} - Transaction #{transaction_id}")
        return jsonify({'status': 'ok', 'message': 'Virement effectué', 'transaction_id': transaction_id}), 200

    except Exception as e:
        if conn:
            conn.rollback()
        logging.error(f"Erreur virement: {e}")
        return jsonify({'status': 'error', 'message': 'Erreur transaction'}), 500

@app.route('/api/transactions', methods=['GET'])
def get_transactions():
    """Historique (Admin uniquement)"""
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Non authentifié'}), 401
    if session.get('role') != 'admin':
        return jsonify({'status': 'error', 'message': 'Accès refusé'}), 403

    limite = request.args.get('limit', 50, type=int)

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'Erreur base de données'}), 500

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT t.id, t.montant, t.type_transaction, t.description, 
                   t.date_transaction, t.agent_username, t.statut,
                   cs.numero_compte as compte_source,
                   cd.numero_compte as compte_dest
            FROM transactions t
            LEFT JOIN comptes cs ON t.compte_source_id = cs.id
            LEFT JOIN comptes cd ON t.compte_dest_id = cd.id
            ORDER BY t.date_transaction DESC
            LIMIT %s
        """, (limite,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        logging.info(f"Consultation transactions par {session['username']}")
        return jsonify({'status': 'ok', 'transactions': rows}), 200
    except Exception as e:
        logging.error(f"Erreur get_transactions: {e}")
        return jsonify({'status': 'error', 'message': 'Erreur serveur'}), 500

# -----------------------
# INFO UTILISATEUR / LOGOUT
# -----------------------
@app.route('/api/user-info', methods=['GET'])
def get_user_info():
    """Retourne info de session"""
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Non authentifié'}), 401
    return jsonify({'status': 'ok', 'username': session['username'], 'role': session['role']}), 200

@app.route('/logout', methods=['POST'])
def logout():
    username = session.get('username', 'Unknown')
    session.clear()
    logging.info(f"Déconnexion: {username}")
    return jsonify({'status': 'ok', 'message': 'Déconnexion réussie'}), 200

# -----------------------
# Lance l'app
# -----------------------
if __name__ == '__main__':
    # IMPORTANT: écouter 0.0.0.0 pour être joint par Nginx / autres VM
    app.run(host='0.0.0.0', port=5000, debug=False)
