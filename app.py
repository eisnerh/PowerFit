from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, time, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import csv
import io
import os
from dotenv import load_dotenv
import secrets
import string

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)

# Configuración de seguridad
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///gimnasio.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Obtener el tiempo de sesión de forma segura
try:
    session_lifetime = int(os.getenv('PERMANENT_SESSION_LIFETIME', '3600'))
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=session_lifetime)
except (ValueError, TypeError):
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=3600)  # valor por defecto: 1 hora

# Configuración de correo
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modelo de Usuario
class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    nombre = db.Column(db.String(100), nullable=False)
    es_admin = db.Column(db.Boolean, default=False)
    reservas = db.relationship('Reserva', backref='usuario', lazy=True)

# Modelo de Reserva
class Reserva(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.Date, nullable=False)
    hora = db.Column(db.Time, nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    estado = db.Column(db.String(20), default='pendiente')  # pendiente, confirmada, cancelada, completada
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)

# Modelo de Configuración
class Configuracion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hora_apertura = db.Column(db.Time, default=time(6, 0))  # 6:00 AM
    hora_cierre = db.Column(db.Time, default=time(18, 0))    # 6:00 PM
    dias_activos = db.Column(db.String(100), default='1,2,3,4,5,6')  # 1=Lunes, 7=Domingo
    admin_email = db.Column(db.String(120), default='admin@gimnasio.com')  # Correo para notificaciones
    capacidad_maxima = db.Column(db.Integer, default=10)  # Capacidad máxima por hora

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# Función para enviar correos
def enviar_correo(destinatario, asunto, cuerpo):
    try:
        msg = Message(asunto, recipients=[destinatario])
        msg.body = cuerpo
        mail.send(msg)
        print(f"Correo enviado exitosamente a {destinatario}")
        return True
    except Exception as e:
        print(f"Error al enviar correo: {str(e)}")
        print(f"Configuración de correo actual:")
        print(f"MAIL_SERVER: {app.config['MAIL_SERVER']}")
        print(f"MAIL_PORT: {app.config['MAIL_PORT']}")
        print(f"MAIL_USE_TLS: {app.config['MAIL_USE_TLS']}")
        print(f"MAIL_USERNAME: {app.config['MAIL_USERNAME']}")
        print(f"MAIL_DEFAULT_SENDER: {app.config['MAIL_DEFAULT_SENDER']}")
        return False

# Rutas básicas
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = Usuario.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Credenciales inválidas')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.es_admin:
        config = Configuracion.query.first()
        reservas_pendientes = Reserva.query.filter_by(estado='pendiente').all()
        historial_reservas = Reserva.query.order_by(Reserva.fecha_creacion.desc()).all()
        # Obtener todos los usuarios excepto el administrador actual
        usuarios = Usuario.query.filter(Usuario.id != current_user.id).order_by(Usuario.nombre).all()
        return render_template('admin_dashboard.html', 
                             config=config,
                             reservas_pendientes=reservas_pendientes,
                             historial_reservas=historial_reservas,
                             usuarios=usuarios)
    
    config = Configuracion.query.first()
    
    # Obtener la fecha actual y calcular el inicio y fin de la semana
    hoy = datetime.now().date()
    inicio_semana = hoy - timedelta(days=hoy.weekday())
    fin_semana = inicio_semana + timedelta(days=6)
    
    # Obtener todas las reservas del usuario
    mis_reservas = Reserva.query.filter_by(usuario_id=current_user.id).order_by(Reserva.fecha.desc()).all()
    
    # Filtrar reservas de la semana actual
    reservas_semana = [r for r in mis_reservas if inicio_semana <= r.fecha <= fin_semana]
    
    # Generar horas disponibles
    horas_disponibles = []
    hora_actual = config.hora_apertura
    while hora_actual < config.hora_cierre:
        horas_disponibles.append(hora_actual.strftime('%H:%M'))
        # Convertir la hora actual a minutos, sumar 60 minutos y convertir de nuevo a time
        minutos = hora_actual.hour * 60 + hora_actual.minute + 60
        hora_actual = time(hour=minutos // 60, minute=minutos % 60)
    
    # Convertir días activos a nombres
    dias = {
        '1': 'Lunes',
        '2': 'Martes',
        '3': 'Miércoles',
        '4': 'Jueves',
        '5': 'Viernes',
        '6': 'Sábado',
        '7': 'Domingo'
    }
    dias_activos = [dias[dia] for dia in config.dias_activos.split(',')]
    
    return render_template('user_dashboard.html',
                         config=config,
                         mis_reservas=mis_reservas,
                         reservas_semana=reservas_semana,
                         inicio_semana=inicio_semana,
                         fin_semana=fin_semana,
                         horas_disponibles=horas_disponibles,
                         dias_activos=dias_activos)

def obtener_fechas_horas_disponibles(fecha_solicitada=None, hora_solicitada=None):
    """Obtiene las fechas y horas disponibles para reservas."""
    config = Configuracion.query.first()
    dias_activos = [int(dia) for dia in config.dias_activos.split(',')]
    
    # Obtener la fecha y hora actual
    ahora = datetime.now()
    fecha_actual = ahora.date()
    hora_actual = ahora.time()
    
    # Lista para almacenar las fechas y horas disponibles
    fechas_horas_disponibles = []
    
    # Buscar disponibilidad para los próximos 14 días
    for i in range(14):
        fecha = fecha_actual + timedelta(days=i)
        dia_semana = fecha.isoweekday()
        
        # Verificar si el día está activo
        if dia_semana in dias_activos:
            # Generar horas disponibles para este día
            hora_inicio = config.hora_apertura
            while hora_inicio < config.hora_cierre:
                # Si es el día actual, solo incluir horas futuras
                if fecha == fecha_actual and hora_inicio <= hora_actual:
                    # Avanzar a la siguiente hora
                    minutos = hora_inicio.hour * 60 + hora_inicio.minute + 60
                    hora_inicio = time(hour=minutos // 60, minute=minutos % 60)
                    continue
                
                # Verificar cuántas reservas hay para esta fecha y hora
                reservas_existentes = Reserva.query.filter_by(
                    fecha=fecha,
                    hora=hora_inicio,
                    estado='confirmada'
                ).count()
                
                # Si hay espacio disponible (menos reservas que capacidad máxima)
                if reservas_existentes < config.capacidad_maxima:
                    fechas_horas_disponibles.append({
                        'fecha': fecha,
                        'hora': hora_inicio,
                        'dia_semana': dia_semana,
                        'espacios_disponibles': config.capacidad_maxima - reservas_existentes
                    })
                
                # Avanzar una hora
                minutos = hora_inicio.hour * 60 + hora_inicio.minute + 60
                hora_inicio = time(hour=minutos // 60, minute=minutos % 60)
    
    # Si se proporcionó una fecha y hora específica, ordenar las sugerencias
    # para mostrar primero las más cercanas a la solicitada
    if fecha_solicitada and hora_solicitada:
        fecha_hora_solicitada = datetime.combine(fecha_solicitada, hora_solicitada)
        fechas_horas_disponibles.sort(
            key=lambda x: abs((datetime.combine(x['fecha'], x['hora']) - fecha_hora_solicitada).total_seconds())
        )
    
    return fechas_horas_disponibles

@app.route('/crear_reserva', methods=['POST'])
@login_required
def crear_reserva():
    fecha = datetime.strptime(request.form.get('fecha'), '%Y-%m-%d').date()
    hora = datetime.strptime(request.form.get('hora'), '%H:%M').time()
    
    # Verificar si la fecha y hora seleccionada es en el pasado
    fecha_hora_seleccionada = datetime.combine(fecha, hora)
    ahora = datetime.now()
    
    if fecha_hora_seleccionada <= ahora:
        # Obtener fechas y horas disponibles
        fechas_horas_disponibles = obtener_fechas_horas_disponibles()
        
        # Preparar mensaje con sugerencias
        dias_nombres = {
            1: 'Lunes', 2: 'Martes', 3: 'Miércoles', 4: 'Jueves',
            5: 'Viernes', 6: 'Sábado', 7: 'Domingo'
        }
        
        sugerencias = []
        for opcion in fechas_horas_disponibles[:5]:  # Mostrar solo las primeras 5 sugerencias
            sugerencias.append({
                'fecha': opcion['fecha'].strftime('%d/%m/%Y'),
                'hora': opcion['hora'].strftime('%H:%M'),
                'dia': dias_nombres[opcion['dia_semana']],
                'espacios_disponibles': opcion['espacios_disponibles']
            })
        
        flash(f'No puedes hacer una reserva en una fecha u hora que ya ha pasado. Aquí tienes algunas sugerencias:', 'warning')
        return render_template('sugerencias_reserva.html', 
                             sugerencias=sugerencias,
                             fecha_solicitada=fecha.strftime('%Y-%m-%d'),
                             hora_solicitada=hora.strftime('%H:%M'))
    
    config = Configuracion.query.first()
    dia_semana = fecha.isoweekday()
    dias_activos = [int(dia) for dia in config.dias_activos.split(',')]
    
    # Verificar si el día está activo
    if dia_semana not in dias_activos:
        # Obtener fechas y horas disponibles
        fechas_horas_disponibles = obtener_fechas_horas_disponibles(fecha, hora)
        
        # Preparar mensaje con sugerencias
        dias_nombres = {
            1: 'Lunes', 2: 'Martes', 3: 'Miércoles', 4: 'Jueves',
            5: 'Viernes', 6: 'Sábado', 7: 'Domingo'
        }
        
        sugerencias = []
        for opcion in fechas_horas_disponibles[:5]:  # Mostrar solo las primeras 5 sugerencias
            sugerencias.append({
                'fecha': opcion['fecha'].strftime('%d/%m/%Y'),
                'hora': opcion['hora'].strftime('%H:%M'),
                'dia': dias_nombres[opcion['dia_semana']],
                'espacios_disponibles': opcion['espacios_disponibles']
            })
        
        flash(f'El día seleccionado ({dias_nombres[dia_semana]}) no está disponible. Aquí tienes algunas sugerencias:', 'warning')
        return render_template('sugerencias_reserva.html', 
                             sugerencias=sugerencias,
                             fecha_solicitada=fecha.strftime('%Y-%m-%d'),
                             hora_solicitada=hora.strftime('%H:%M'))
    
    # Verificar si el usuario ya tiene una reserva para ese día
    reserva_existente_mismo_dia = Reserva.query.filter_by(
        usuario_id=current_user.id,
        fecha=fecha,
        estado='confirmada'
    ).first()
    
    if reserva_existente_mismo_dia:
        flash(f'Ya tienes una reserva confirmada para el día {fecha.strftime("%d/%m/%Y")}. No puedes tener múltiples reservas en el mismo día.', 'warning')
        return redirect(url_for('dashboard'))
    
    # Verificar la capacidad disponible
    reservas_existentes = Reserva.query.filter_by(
        fecha=fecha,
        hora=hora,
        estado='confirmada'
    ).count()
    
    if reservas_existentes >= config.capacidad_maxima:
        # Obtener fechas y horas disponibles
        fechas_horas_disponibles = obtener_fechas_horas_disponibles(fecha, hora)
        
        # Preparar mensaje con sugerencias
        dias_nombres = {
            1: 'Lunes', 2: 'Martes', 3: 'Miércoles', 4: 'Jueves',
            5: 'Viernes', 6: 'Sábado', 7: 'Domingo'
        }
        
        sugerencias = []
        for opcion in fechas_horas_disponibles[:5]:  # Mostrar solo las primeras 5 sugerencias
            sugerencias.append({
                'fecha': opcion['fecha'].strftime('%d/%m/%Y'),
                'hora': opcion['hora'].strftime('%H:%M'),
                'dia': dias_nombres[opcion['dia_semana']],
                'espacios_disponibles': opcion['espacios_disponibles']
            })
        
        flash(f'Lo sentimos, el gimnasio ya está lleno para esa hora (capacidad máxima: {config.capacidad_maxima} personas). Aquí tienes algunas sugerencias de horarios disponibles:', 'warning')
        return render_template('sugerencias_reserva.html', 
                             sugerencias=sugerencias,
                             fecha_solicitada=fecha.strftime('%Y-%m-%d'),
                             hora_solicitada=hora.strftime('%H:%M'))
    
    nueva_reserva = Reserva(
        fecha=fecha,
        hora=hora,
        usuario_id=current_user.id,
        estado='pendiente'
    )
    
    db.session.add(nueva_reserva)
    db.session.commit()
    
    # Enviar correo al administrador
    config = Configuracion.query.first()
    asunto = f'Nueva solicitud de reserva - {current_user.nombre}'
    cuerpo = f'''
    Se ha recibido una nueva solicitud de reserva:
    
    Usuario: {current_user.nombre}
    Email: {current_user.email}
    Fecha: {fecha.strftime('%d/%m/%Y')}
    Hora: {hora.strftime('%H:%M')}
    
    Por favor, revise el panel de administración para aprobar o rechazar esta solicitud.
    '''
    
    enviar_correo(config.admin_email, asunto, cuerpo)
    
    flash('Reserva creada exitosamente')
    return redirect(url_for('dashboard'))

@app.route('/cancelar_reserva/<int:id>', methods=['POST'])
@login_required
def cancelar_reserva(id):
    reserva = Reserva.query.get_or_404(id)
    if reserva.usuario_id != current_user.id:
        flash('No tienes permiso para cancelar esta reserva')
        return redirect(url_for('dashboard'))
    
    reserva.estado = 'cancelada'
    db.session.commit()
    
    flash('Reserva cancelada exitosamente')
    return redirect(url_for('dashboard'))

@app.route('/actualizar_reserva/<int:id>', methods=['POST'])
@login_required
def actualizar_reserva(id):
    if not current_user.es_admin:
        flash('No tienes permiso para realizar esta acción')
        return redirect(url_for('dashboard'))
    
    reserva = Reserva.query.get_or_404(id)
    accion = request.form.get('accion')
    
    if accion == 'aprobar':
        reserva.estado = 'confirmada'
        # Enviar correo al usuario
        asunto = 'Tu reserva ha sido aprobada'
        cuerpo = f'''
        Hola {reserva.usuario.nombre},
        
        Tu reserva para el día {reserva.fecha.strftime('%d/%m/%Y')} a las {reserva.hora.strftime('%H:%M')} ha sido aprobada por {current_user.nombre}.
        
        ¡Te esperamos en el gimnasio!
        
        Saludos,
        {current_user.nombre}
        Administrador del Gimnasio
        '''
        enviar_correo(reserva.usuario.email, asunto, cuerpo)
    elif accion == 'rechazar':
        reserva.estado = 'cancelada'
        # Enviar correo al usuario
        asunto = 'Tu reserva ha sido rechazada'
        cuerpo = f'''
        Hola {reserva.usuario.nombre},
        
        Tu reserva para el día {reserva.fecha.strftime('%d/%m/%Y')} a las {reserva.hora.strftime('%H:%M')} ha sido rechazada por {current_user.nombre}.
        
        Por favor, intenta con otra fecha u hora.
        
        Saludos,
        {current_user.nombre}
        Administrador del Gimnasio
        '''
        enviar_correo(reserva.usuario.email, asunto, cuerpo)
    
    db.session.commit()
    flash(f'Reserva {accion}da exitosamente')
    return redirect(url_for('dashboard'))

@app.route('/actualizar_configuracion', methods=['POST'])
@login_required
def actualizar_configuracion():
    if not current_user.es_admin:
        flash('No tienes permiso para realizar esta acción')
        return redirect(url_for('dashboard'))
    
    config = Configuracion.query.first()
    if not config:
        config = Configuracion()
        db.session.add(config)
    
    config.hora_apertura = datetime.strptime(request.form.get('hora_apertura'), '%H:%M').time()
    config.hora_cierre = datetime.strptime(request.form.get('hora_cierre'), '%H:%M').time()
    
    dias = request.form.getlist('dias')
    config.dias_activos = ','.join(dias)
    
    # Actualizar capacidad máxima
    try:
        capacidad = int(request.form.get('capacidad_maxima', 10))
        if capacidad < 1:
            flash('La capacidad máxima debe ser al menos 1')
            return redirect(url_for('dashboard'))
        config.capacidad_maxima = capacidad
    except ValueError:
        flash('La capacidad máxima debe ser un número válido')
        return redirect(url_for('dashboard'))
    
    db.session.commit()
    flash('Configuración actualizada exitosamente')
    return redirect(url_for('dashboard'))

def generar_contraseña_segura(longitud=12):
    """Genera una contraseña segura con letras, números y caracteres especiales."""
    caracteres = string.ascii_letters + string.digits + string.punctuation
    while True:
        contraseña = ''.join(secrets.choice(caracteres) for _ in range(longitud))
        if (any(c.islower() for c in contraseña)
                and any(c.isupper() for c in contraseña)
                and any(c.isdigit() for c in contraseña)
                and any(c in string.punctuation for c in contraseña)):
            return contraseña

def validar_contraseña(contraseña):
    """Valida que la contraseña cumpla con los requisitos mínimos de seguridad."""
    if len(contraseña) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"
    if not any(c.islower() for c in contraseña):
        return False, "La contraseña debe contener al menos una letra minúscula"
    if not any(c.isupper() for c in contraseña):
        return False, "La contraseña debe contener al menos una letra mayúscula"
    if not any(c.isdigit() for c in contraseña):
        return False, "La contraseña debe contener al menos un número"
    if not any(c in string.punctuation for c in contraseña):
        return False, "La contraseña debe contener al menos un carácter especial"
    return True, "Contraseña válida"

@app.route('/actualizar_perfil_admin', methods=['POST'])
@login_required
def actualizar_perfil_admin():
    if not current_user.es_admin:
        flash('No tienes permiso para realizar esta acción')
        return redirect(url_for('dashboard'))
    
    nombre = request.form.get('nombre')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    
    # Validar nombre
    if not nombre or len(nombre.strip()) == 0:
        flash('El nombre es requerido')
        return redirect(url_for('dashboard'))
    
    # Validar email
    if not email or '@' not in email:
        flash('Por favor, ingrese un correo electrónico válido')
        return redirect(url_for('dashboard'))
    
    # Verificar si el email ya está en uso por otro usuario
    otro_usuario = Usuario.query.filter_by(email=email).first()
    if otro_usuario and otro_usuario.id != current_user.id:
        flash('El correo electrónico ya está en uso')
        return redirect(url_for('dashboard'))
    
    # Actualizar nombre
    current_user.nombre = nombre.strip()
    
    # Actualizar email
    current_user.email = email
    
    # Actualizar contraseña si se proporciona
    if password:
        if password != confirm_password:
            flash('Las contraseñas no coinciden')
            return redirect(url_for('dashboard'))
        
        # Validar requisitos de la contraseña
        es_valida, mensaje = validar_contraseña(password)
        if not es_valida:
            flash(mensaje)
            return redirect(url_for('dashboard'))
        
        current_user.password = generate_password_hash(password)
        flash('Contraseña actualizada exitosamente')
    
    # Actualizar correo de notificaciones en la configuración
    config = Configuracion.query.first()
    if config:
        config.admin_email = email
    
    db.session.commit()
    flash('Perfil actualizado exitosamente')
    return redirect(url_for('dashboard'))

@app.route('/descargar_historial')
@login_required
def descargar_historial():
    if not current_user.es_admin:
        flash('No tienes permiso para realizar esta acción')
        return redirect(url_for('dashboard'))
    
    # Crear un archivo CSV en memoria
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Escribir encabezados
    writer.writerow(['ID', 'Usuario', 'Email', 'Fecha', 'Hora', 'Estado', 'Fecha de Creación'])
    
    # Obtener todas las reservas ordenadas por fecha
    reservas = Reserva.query.order_by(Reserva.fecha.desc()).all()
    
    # Escribir datos
    for reserva in reservas:
        writer.writerow([
            reserva.id,
            reserva.usuario.nombre,
            reserva.usuario.email,
            reserva.fecha.strftime('%d/%m/%Y'),
            reserva.hora.strftime('%H:%M'),
            reserva.estado,
            reserva.fecha_creacion.strftime('%d/%m/%Y %H:%M')
        ])
    
    # Preparar el archivo para descarga
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'historial_gimnasio_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        nombre = request.form.get('nombre')
        
        # Validaciones básicas
        if not email or not password or not confirm_password or not nombre:
            flash('Todos los campos son requeridos')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Las contraseñas no coinciden')
            return redirect(url_for('register'))
        
        # Validar requisitos de la contraseña
        es_valida, mensaje = validar_contraseña(password)
        if not es_valida:
            flash(mensaje)
            return redirect(url_for('register'))
        
        # Verificar si el email ya está registrado
        usuario_existente = Usuario.query.filter_by(email=email).first()
        if usuario_existente:
            flash('El correo electrónico ya está registrado')
            return redirect(url_for('register'))
        
        # Crear nuevo usuario
        nuevo_usuario = Usuario(
            email=email,
            password=generate_password_hash(password),
            nombre=nombre,
            es_admin=False
        )
        
        db.session.add(nuevo_usuario)
        db.session.commit()
        
        flash('Registro exitoso. Por favor, inicia sesión.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Función para crear un usuario administrador inicial y configuración
def crear_admin_inicial():
    with app.app_context():
        # Crear las tablas si no existen
        db.create_all()
        
        # Verificar si la columna capacidad_maxima existe
        inspector = db.inspect(db.engine)
        columnas = [col['name'] for col in inspector.get_columns('configuracion')]
        
        if 'capacidad_maxima' not in columnas:
            # Agregar la columna capacidad_maxima
            with db.engine.begin() as conn:
                conn.execute(db.text('ALTER TABLE configuracion ADD COLUMN capacidad_maxima INTEGER DEFAULT 10'))
        
        # Crear administrador si no existe
        admin = Usuario.query.filter_by(email='admin@gimnasio.com').first()
        if not admin:
            # Usar credenciales predeterminadas
            admin = Usuario(
                email='admin@gimnasio.com',
                password=generate_password_hash('admin123'),  # Contraseña predeterminada
                nombre='Administrador',
                es_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Usuario administrador creado con éxito")
            print("Email: admin@gimnasio.com")
            print("Contraseña: admin123")
            print("Por favor, cambie estas credenciales después de iniciar sesión")
        
        # Crear configuración inicial si no existe
        config = Configuracion.query.first()
        if not config:
            config = Configuracion(
                hora_apertura=time(6, 0),  # 6:00 AM
                hora_cierre=time(18, 0),   # 6:00 PM
                dias_activos='1,2,3,4,5,6',  # Lunes a Sábado
                admin_email='admin@gimnasio.com',  # Correo para notificaciones
                capacidad_maxima=10  # Capacidad máxima por hora
            )
            db.session.add(config)
            db.session.commit()
            print("Configuración inicial creada con éxito")

if __name__ == '__main__':
    with app.app_context():
        # Crear las tablas si no existen
        db.create_all()
        # Crear el administrador inicial si no existe
        crear_admin_inicial()
    app.run(debug=True) 