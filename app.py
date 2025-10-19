from flask import Flask, request, jsonify, session
from flask_cors import CORS
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
CORS(app, supports_credentials=True)

# Configuration logging
logging.basicConfig(
    filename='/var/log/banking-app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Configuration email (Gmail)
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'azizdaoues20@gmail.com',
    'sender_password': 'lbae ltxz nshs vjqw'
}

# Configuration base de données PostgreSQL
DB_CONFIG = {
    'host': '10.0.0.13',
    'port': 5432,
    'database': 'banking_db',
    'user': 'banking_user',
    'password': 'SecureP@ss2025!',
    'sslmode': 'require'
}

# Stockage temporaire des codes MFA
mfa_codes = {}

# ===== FONCTIONS UTILITAIRES =====

def get_db_connection():
    """Connexion sécurisée à PostgreSQL"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        logging.error(f"Erreur connexion DB: {str(e)}")
        return None

def hash_password(password):
    """Hash SHA256 du mot de passe"""
    return hashlib.sha256(password.encode()).hexdigest()

def send_mfa_email(recipient, code, username):
    """Envoi du code MFA par email"""
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

# ===== ROUTES D'AUTHENTIFICATION =====

@app.route('/login', methods=['POST'])
def login():
    """Authentification étape 1 : Vérification username/password dans DB"""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    logging.info(f"Tentative connexion: {username} depuis {request.remote_addr}")
    
    if not username or not password:
        logging.warning(f"Champs manquants pour {username}")
        return jsonify({'status': 'error', 'message': 'Champs requis manquants'}), 400
    
    # Connexion DB
    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'Erreur serveur'}), 500
    
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        password_hash = hash_password(password)
        
        # Vérification dans la table users
        cursor.execute("""
            SELECT id, username, email, role, is_active, last_login 
            FROM users 
            WHERE username = %s AND password_hash = %s
        """, (username, password_hash))
        
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not user:
            logging.warning(f"Échec authentification: {username}")
            return jsonify({'status': 'error', 'message': 'Identifiants incorrects'}), 401
        
        if not user['is_active']:
            logging.warning(f"Compte désactivé: {username}")
            return jsonify({'status': 'error', 'message': 'Compte désactivé'}), 403
        
        # Génération code MFA
        mfa_code = str(random.randint(100000, 999999))
        mfa_codes[username] = {
            'code': mfa_code,
            'expiry': datetime.now() + timedelta(minutes=5),
            'email': user['email'],
            'role': user['role'],
            'user_id': user['id']
        }
        
        if send_mfa_email(user['email'], mfa_code, username):
            logging.info(f"Code MFA généré pour {username}")
            return jsonify({
                'status': 'ok',
                'mfa_required': True,
                'message': 'Code MFA envoyé par email',
                'email_masked': user['email'][:3] + '***@' + user['email'].split('@')[1]
            }), 200
        else:
            logging.error(f"Échec envoi MFA pour {username}")
            return jsonify({'status': 'error', 'message': 'Erreur envoi email'}), 500
            
    except Exception as e:
        logging.error(f"Erreur login: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Erreur serveur'}), 500

@app.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    """Authentification étape 2 : Vérification code MFA"""
    data = request.get_json()
    username = data.get('username', '').strip()
    code = data.get('code', '').strip()
    
    if not username or not code:
        return jsonify({'status': 'error', 'message': 'Données manquantes'}), 400
    
    stored = mfa_codes.get(username)
    
    if not stored:
        logging.warning(f"Code MFA inexistant pour {username}")
        return jsonify({'status': 'error', 'message': 'Code non valide'}), 401
    
    if datetime.now() > stored['expiry']:
        logging.warning(f"Code MFA expiré pour {username}")
        del mfa_codes[username]
        return jsonify({'status': 'error', 'message': 'Code expiré'}), 401
    
    if stored['code'] != code:
        logging.warning(f"Code MFA incorrect pour {username}")
        return jsonify({'status': 'error', 'message': 'Code incorrect'}), 401
    
    # Authentification réussie - Mise à jour last_login
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
    
    # Création session
    session['username'] = username
    session['role'] = stored['role']
    session['user_id'] = stored['user_id']
    del mfa_codes[username]
    
    logging.info(f"Connexion réussie: {username} - {stored['role']}")
    return jsonify({
        'status': 'ok',
        'message': 'Connexion réussie',
        'username': username,
        'role': stored['role']
    }), 200

# ===== ROUTES PROTÉGÉES (Admin uniquement) =====

@app.route('/api/comptes', methods=['GET'])
def get_comptes():
    """Liste des comptes (Admin uniquement)"""
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Non authentifié'}), 401
    
    if session.get('role') != 'admin':
        return jsonify({'status': 'error', 'message': 'Accès refusé - Admin requis'}), 403
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'Erreur base de données'}), 500
    
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT c.id, c.numero_compte, c.type_compte, c.solde, c.devise, c.statut,
                   cl.nom, cl.prenom, cl.email, cl.telephone
            FROM comptes c
            JOIN clients cl ON c.client_id = cl.id
            WHERE c.statut = 'actif'
            ORDER BY cl.nom, cl.prenom
        """)
        comptes = cursor.fetchall()
        cursor.close()
        conn.close()
        
        logging.info(f"Consultation comptes par {session['username']}")
        return jsonify({'status': 'ok', 'comptes': comptes}), 200
    except Exception as e:
        logging.error(f"Erreur requête comptes: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Erreur serveur'}), 500

@app.route('/api/virement', methods=['POST'])
def virement():
    """Effectuer un virement (Admin uniquement)"""
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Non authentifié'}), 401
    
    if session.get('role') != 'admin':
        return jsonify({'status': 'error', 'message': 'Accès refusé'}), 403
    
    data = request.get_json()
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
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Montant invalide'}), 400
    
    if compte_source == compte_dest:
        return jsonify({'status': 'error', 'message': 'Comptes identiques'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'Erreur base de données'}), 500
    
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Vérification solde
        cursor.execute("SELECT solde FROM comptes WHERE id = %s AND statut = 'actif'", (compte_source,))
        compte = cursor.fetchone()
        
        if not compte:
            return jsonify({'status': 'error', 'message': 'Compte source invalide'}), 404
        
        if compte['solde'] < montant:
            logging.warning(f"Solde insuffisant - {session['username']} - Compte {compte_source}")
            return jsonify({'status': 'error', 'message': 'Solde insuffisant'}), 400
        
        # Transaction
        cursor.execute("BEGIN")
        
        cursor.execute("UPDATE comptes SET solde = solde - %s WHERE id = %s", (montant, compte_source))
        cursor.execute("UPDATE comptes SET solde = solde + %s WHERE id = %s", (montant, compte_dest))
        
        cursor.execute("""
            INSERT INTO transactions 
            (compte_source_id, compte_dest_id, montant, type_transaction, description, agent_username)
            VALUES (%s, %s, %s, 'virement', %s, %s)
            RETURNING id
        """, (compte_source, compte_dest, montant, description, session['username']))
        
        transaction_id = cursor.fetchone()['id']
        
        cursor.execute("COMMIT")
        cursor.close()
        conn.close()
        
        logging.info(f"Virement réussi - {session['username']} - Transaction #{transaction_id}")
        return jsonify({
            'status': 'ok',
            'message': 'Virement effectué avec succès',
            'transaction_id': transaction_id
        }), 200
        
    except Exception as e:
        if conn:
            conn.rollback()
        logging.error(f"Erreur virement: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Erreur transaction'}), 500

@app.route('/api/transactions', methods=['GET'])
def get_transactions():
    """Historique des transactions (Admin uniquement)"""
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Non authentifié'}), 401
    
    if session.get('role') != 'admin':
        return jsonify({'status': 'error', 'message': 'Accès refusé'}), 403
    
    limite = request.args.get('limit', 50, type=int)
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 'error', 'message': 'Erreur base de données'}), 500
    
    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
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
        
        transactions = cursor.fetchall()
        cursor.close()
        conn.close()
        
        logging.info(f"Consultation transactions par {session['username']}")
        return jsonify({'status': 'ok', 'transactions': transactions}), 200
    except Exception as e:
        logging.error(f"Erreur requête transactions: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Erreur serveur'}), 500

@app.route('/api/user-info', methods=['GET'])
def get_user_info():
    """Informations utilisateur connecté"""
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Non authentifié'}), 401
    
    return jsonify({
        'status': 'ok',
        'username': session['username'],
        'role': session['role']
    }), 200

@app.route('/logout', methods=['POST'])
def logout():
    """Déconnexion"""
    username = session.get('username', 'Unknown')
    session.clear()
    logging.info(f"Déconnexion: {username}")
    return jsonify({'status': 'ok', 'message': 'Déconnexion réussie'}), 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
