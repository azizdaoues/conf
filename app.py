from flask import Flask, request, jsonify
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta

app = Flask(__name__)

# Utilisateurs simulés avec emails
users = {
    "admin": {
        "password": "Admin@123",
        "email": "azizdaoues19@gmail.com",
        "role": "Administrateur"
    },
    "agent": {
        "password": "Agent@123",
        "email": "ton.email.agent@gmail.com",
        "role": "Agent"
    }
}

# Stockage temporaire des codes MFA envoyés
mfa_codes = {}  # { "username": {"code":123456, "expire":datetime} }

# Paramètres SMTP (expéditeur)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "azizdaoues20@gmail.com"       # à remplacer
SMTP_PASS = "lbae ltxz nshs vjqw"         # à remplacer

def send_email(to_email, subject, body):
    msg = MIMEText(body)
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    msg["Subject"] = subject

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username in users and users[username]["password"] == password:
        # Générer un code OTP à 6 chiffres
        code = random.randint(100000, 999999)
        expire = datetime.now() + timedelta(minutes=5)
        mfa_codes[username] = {"code": code, "expire": expire}

        # Envoyer par email
        to_email = users[username]["email"]
        subject = "Votre code MFA"
        body = f"Bonjour {username},\n\nVotre code MFA est : {code}\nIl est valable pendant 5 minutes.\n\nMini-Projet Sécurité"
        send_email(to_email, subject, body)

        return jsonify({"status": "ok", "mfa_required": True}), 200
    else:
        return jsonify({"status": "error", "message": "Identifiants invalides"}), 401

@app.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    data = request.json
    username = data.get('username')
    code = data.get('code')

    if username not in mfa_codes:
        return jsonify({"status": "error", "message": "Aucun code MFA actif"}), 401

    saved_code = mfa_codes[username]["code"]
    expire_time = mfa_codes[username]["expire"]

    if datetime.now() > expire_time:
        return jsonify({"status": "error", "message": "Code expiré"}), 401

    if str(saved_code) == str(code):
        role = users[username]["role"]
        del mfa_codes[username]
        return jsonify({"status": "ok", "role": role}), 200
    else:
        return jsonify({"status": "error", "message": "Code incorrect"}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
