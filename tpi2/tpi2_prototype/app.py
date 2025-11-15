from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
    UserMixin,
)
from datetime import datetime  # agrega este import arriba
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import os
from functools import wraps
from flask import abort

app = Flask(__name__)

# 🔑 Clave para sesiones (cámbiala por algo propio en producción)
app.config["SECRET_KEY"] = "cambia-esto-por-algo-mas-seguro"

# 📦 Configuración base de datos
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///contactos.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# 🤖 Token del bot de Telegram
TELEGRAM_BOT_TOKEN = "8235808272:AAFtVXA-PiprWP9-HtI7VnnHcYBa-W8CWFo"

# ⚙️ Configuración de Flask-Login
login_manager = LoginManager()
login_manager.login_view = "login"  # ruta a la que redirige si no estás logeado
login_manager.init_app(app)


# 👤 MODELO: Usuario que se registra/inicia sesión
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    # 👇 NUEVOS CAMPOS
    nombre = db.Column(db.String(120), nullable=False)
    direccion = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")

    def set_password(self, password_plain):
        self.password_hash = generate_password_hash(password_plain)

    def check_password(self, password_plain):
        return check_password_hash(self.password_hash, password_plain)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        if current_user.role != "admin":
            return abort(403)  # Prohibido
        return f(*args, **kwargs)
    return decorated_function


@app.route("/admin")
@admin_required
def admin_panel():
    usuarios = User.query.all()
    solicitudes = RoleRequest.query.order_by(RoleRequest.created_at.desc()).all()
    return render_template(
        "admin.html",
        usuarios=usuarios,
        solicitudes=solicitudes,
        title="Admin Panel",
    )


@app.post("/admin/cambiar_rol/<int:user_id>")
@admin_required
def cambiar_rol(user_id):
    user = User.query.get_or_404(user_id)
    nuevo_rol = request.form.get("role")

    # Validar roles permitidos
    if nuevo_rol not in ["admin", "user", "contacto"]:
        flash("Rol inválido.", "danger")
        return redirect(url_for("admin_panel"))

    # Evitar que el admin se saque su propio rol
    if user.id == current_user.id and nuevo_rol != "admin":
        flash("No puedes quitarte el rol de administrador a ti mismo.", "warning")
        return redirect(url_for("admin_panel"))

    user.role = nuevo_rol
    db.session.commit()

    flash("Rol actualizado correctamente.", "success")
    return redirect(url_for("admin_panel"))

@app.post("/admin/solicitudes/<int:req_id>/aprobar")
@admin_required
def aprobar_solicitud(req_id):
    req = RoleRequest.query.get_or_404(req_id)
    user = User.query.get(req.user_id)

    if user is None:
        flash("Usuario no encontrado para esta solicitud.", "danger")
        return redirect(url_for("admin_panel"))

    # cambiar rol del usuario
    user.role = req.rol_solicitado
    req.estado = "aprobada"
    db.session.commit()

    flash(f"Solicitud aprobada. El usuario {user.username} ahora es {user.role}.", "success")
    return redirect(url_for("admin_panel"))


@app.post("/admin/solicitudes/<int:req_id>/rechazar")
@admin_required
def rechazar_solicitud(req_id):
    req = RoleRequest.query.get_or_404(req_id)
    req.estado = "rechazada"
    db.session.commit()

    flash("Solicitud rechazada.", "info")
    return redirect(url_for("admin_panel"))


# 📇 MODELO: Contacto que recibe mensajes de ayuda
class Contacto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    chat_id = db.Column(db.String(50), nullable=False)
    # opcional: dueño del contacto
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    user = db.relationship("User", backref="contactos")

class RoleRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    username = db.Column(db.String(80), nullable=False)
    nombre_completo = db.Column(db.String(120), nullable=False)
    rut = db.Column(db.String(20), nullable=False)
    detalles = db.Column(db.Text, nullable=True)

    # rol que quiere tener (ej: "contacto")
    rol_solicitado = db.Column(db.String(20), nullable=False, default="contacto")

    # estados: pendiente / aprobada / rechazada
    estado = db.Column(db.String(20), nullable=False, default="pendiente")

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="solicitudes_rol")

# 🧠 Cargar usuario para Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# 🧱 Crear tablas al arrancar
with app.app_context():
    db.create_all()


# 🔔 Enviar mensaje a todos los contactos
def send_telegram_message(texto):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    contactos = Contacto.query.all()

    for c in contactos:
        data = {
            "chat_id": c.chat_id,
            "text": texto,
            "parse_mode": "Markdown",
        }
        requests.post(url, data=data)


# 🏠 Página de inicio
@app.route("/")
def home():
    return render_template("index.html", title="Inicio")


# 🆘 Formulario para pedir ayuda (público)
@app.route("/ayuda")
def ayuda():
    return render_template("ayuda.html", title="Pedir ayuda")


@app.route("/solicitar_ayuda", methods=["POST"])
@login_required
def solicitar_ayuda():
    # Construimos el mensaje AUTOMÁTICAMENTE usando los datos del usuario
    texto = (
        "🚨 *ALERTA DE EMERGENCIA* 🚨\n\n"
        "El usuario ha solicitado ayuda.\n\n"
        f"👤 Nombre: {current_user.nombre}\n"
        f"📍 Dirección: {current_user.direccion}\n"
    )

    send_telegram_message(texto)

    return render_template("enviado.html", title="Solicitud enviada")

@app.route("/solicitar_cambio_rol", methods=["GET", "POST"])
@login_required
def solicitar_cambio_rol():
    if request.method == "POST":
        rut = request.form["rut"]
        detalles = request.form.get("detalles", "")
        rol_solicitado = request.form.get("rol_solicitado", "contacto")

        # Opcional: evitar solicitudes duplicadas pendientes
        existente = RoleRequest.query.filter_by(
            user_id=current_user.id, estado="pendiente"
        ).first()
        if existente:
            flash("Ya tienes una solicitud de cambio de rol pendiente.", "warning")
            return redirect(url_for("solicitar_cambio_rol"))

        req = RoleRequest(
            user_id=current_user.id,
            username=current_user.username,
            nombre_completo=current_user.nombre,
            rut=rut,
            detalles=detalles,
            rol_solicitado=rol_solicitado,
        )
        db.session.add(req)
        db.session.commit()

        flash("Solicitud enviada al administrador.", "success")
        return redirect(url_for("home"))

    return render_template("solicitar_rol.html", title="Solicitar cambio de rol")


@app.route("/contactos", methods=["GET", "POST"])
@admin_required
def contactos():
    if request.method == "POST":
        user_id = int(request.form["user_id"])
        chat_id = request.form["chat_id"]

        user = User.query.get_or_404(user_id)

        # Solo usuarios con rol contacto
        if user.role != "contacto":
            flash("Solo puedes asignar chat a usuarios con rol 'contacto'.", "danger")
            return redirect(url_for("contactos"))

        # ¿Ya existe un Contacto ligado a este usuario?
        contacto = Contacto.query.filter_by(user_id=user.id).first()

        if contacto is None:
            contacto = Contacto(
                nombre=user.nombre,
                chat_id=chat_id,
                user_id=user.id,
            )
            db.session.add(contacto)
        else:
            contacto.chat_id = chat_id  # actualizar

        db.session.commit()
        flash("Contacto enlazado/actualizado correctamente.", "success")
        return redirect(url_for("contactos"))

    # Para el GET: mostramos lista de usuarios contacto y contactos existentes
    usuarios_contacto = User.query.filter_by(role="contacto").all()
    lista = Contacto.query.all()

    return render_template(
        "contactos.html",
        title="Contactos",
        contactos=lista,
        usuarios_contacto=usuarios_contacto,
    )


# 📝 Registro de usuario
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        nombre = request.form["nombre"]
        direccion = request.form["direccion"]

        # ¿Usuario ya existe?
        if User.query.filter_by(username=username).first():
            flash("Ese nombre de usuario ya existe.", "danger")
            return redirect(url_for("register"))

        user = User(
            username=username,
            nombre=nombre,
            direccion=direccion,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Registro exitoso, ahora puedes iniciar sesión.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", title="Registro")



# 🔐 Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash("Usuario o contraseña incorrectos.", "danger")
            return redirect(url_for("login"))

        login_user(user)
        flash("Sesión iniciada.", "success")
        return redirect(url_for("home"))

    return render_template("login.html", title="Iniciar sesión")


# 🚪 Logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("home"))

with app.app_context():
    # Crear admin si no existe
    admin = User.query.filter_by(role="admin").first()
    if admin is None:
        nuevo_admin = User(
            username="admin",
            nombre="Administrador",
            direccion="N/A",
            role="admin"
        )
        nuevo_admin.set_password("admin123")  # cámbialo luego
        db.session.add(nuevo_admin)
        db.session.commit()
        print(">>> Admin creado con usuario: admin / admin123")

if __name__ == "__main__":
    app.run(debug=True)
