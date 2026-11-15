from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Modelo de usuario
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    reset_token = db.Column(db.String(255), nullable=True)
    token_expiry = db.Column(db.DateTime, nullable=True)

# Inicializar base de datos
with app.app_context():
    db.create_all()
    # Crear usuario de prueba si no existe
    if not User.query.filter_by(email='admin@empresa.local').first():
        user = User(
            email='admin@empresa.local',
            password_hash='hashed_password_123'
        )
        db.session.add(user)
        db.session.commit()

# ENDPOINT VULNERABLE: Olvidé mi contraseña
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404
    
    # Generar token de reset
    token = secrets.token_urlsafe(32)
    user.reset_token = token
    user.token_expiry = datetime.utcnow() + timedelta(minutes=5)
    db.session.commit()
    
    # ⚠️ VULNERABILIDAD: Devolver el token en la respuesta
    return jsonify({
        "status": "success",
        "message": "Reset token generated",
        "user": {
            "email": user.email,
            "reset_token": user.reset_token,  # ← ¡FUGA!
            "token_expiry": user.token_expiry.isoformat()
        }
    })

# ENDPOINT: Resetear contraseña (debería usar el token)
@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')
    
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or user.token_expiry < datetime.utcnow():
        return jsonify({"status": "error", "message": "Invalid or expired token"}), 400
    
    # Actualizar contraseña (simplificado)
    user.password_hash = f"hashed_{new_password}"
    user.reset_token = None
    user.token_expiry = None
    db.session.commit()
    
    return jsonify({"status": "success", "message": "Password updated"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
