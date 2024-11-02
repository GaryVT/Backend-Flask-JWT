from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Configurar la clave secreta para JWT
app.config['JWT_SECRET_KEY'] = 'tu_clave_secreta'  # Cambia esto por una clave segura
jwt = JWTManager(app)

# Base de datos simulada
usuarios = {}

# Ruta para registro de usuario
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')  # Por defecto, asigna 'user'

    if username in usuarios:
        return jsonify({"msg": "El usuario ya existe"}), 400

    usuarios[username] = {
        'password': generate_password_hash(password),
        'role': role  # Guardar el rol del usuario
    }
    return jsonify({"msg": "Usuario registrado exitosamente"}), 201

# Ruta de inicio de sesión
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user_data = usuarios.get(username)
    if user_data and check_password_hash(user_data['password'], password):
        access_token = create_access_token(identity={'username': username, 'role': user_data['role']})
        return jsonify(access_token=access_token), 200

    return jsonify({"msg": "Credenciales incorrectas"}), 401

# Decorador para verificar el rol del usuario
def role_required(role):
    def decorator(f):
        @jwt_required()
        def wrapper(*args, **kwargs):
            current_user = get_jwt_identity()
            if current_user['role'] != role:
                return jsonify({"msg": "No tienes permiso para acceder a este recurso"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Ruta protegida que requiere el rol de admin
@app.route('/admin', methods=['GET'])
@role_required('admin')  # Solo los usuarios con rol de admin pueden acceder
def admin_route():
    return jsonify({"msg": "Bienvenido al área de administración"})

# Ruta protegida
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    return jsonify({"msg": "Este es un recurso protegido"})

if __name__ == '__main__':
    app.run(debug=True)
