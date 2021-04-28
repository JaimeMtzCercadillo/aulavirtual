import json
from flask import Flask, render_template, request, redirect, url_for, flash
 
# Flask Extension to use Databases
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
 
# Flask Extension to use Encrypted Forms!
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Length, Email, EqualTo
 
from werkzeug.security import generate_password_hash, check_password_hash
 
from flask_login import LoginManager, login_required, UserMixin, login_user, logout_user, current_user
from flask_mail import Mail, Message
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
 
 
with open('configuration.json') as json_file:
    configuration = json.load(json_file)
 
 
#from paquete.codigo import objeto
#from carperta.codigopython import objeto
from module001.module001 import module001
from module002.module002 import module002
from module003.module003 import module003
 
app = Flask(__name__)
 
app.register_blueprint(module001, url_prefix="/module001")
app.register_blueprint(module002, url_prefix="/module002")
app.register_blueprint(module003, url_prefix="/module003")
 
# CONFIG- START
app.config['SECRET_KEY'] = configuration['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./database/user.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
 
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = configuration['gmail_username']
app.config['MAIL_PASSWORD'] = configuration['gmail_password']
 
app.config['FLASKY_MAIL_SUBJECT_PREFIX'] = '[Aula Virtual] '
app.config['FLASKY_MAIL_SENDER'] = 'Prof. Manoel Gadi'
 
mail = Mail(app)
 
def send_email(to, subject, template, url, newpassword, **kwargs):
    msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject, sender=app.config['FLASKY_MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs, base_url=url, newpassword=newpassword)
    msg.html = render_template(template + '.html', **kwargs, base_url=url, newpassword=newpassword)
    mail.send(msg)
 
# CONFIG- END
 
Bootstrap(app)
 
# ADMIN - START
class AdminView(AdminIndexView):
    def is_accessible(self):
        if current_user.is_authenticated and current_user.profile in ('admin'):
            return True
        else:
            return False
 
class ProtectedView(ModelView):
    def is_accessible(self):
        if current_user.is_authenticated and current_user.profile in ('admin'):
            return True
        else:
            return False
 
class UserAdmin(ProtectedView):
    column_exclude_list = ('password')
    form_excluded_columns = ('password')
    column_auto_select_related = True
    def scaffold_form(self):
        form_class = super(UserAdmin, self).scaffold_form()
        form_class.password2 = PasswordField('New Password')
        return form_class
    def on_model_change(self, form, model, is_created):
        if len(model.password2):
            model.password = generate_password_hash(model.password2,method='sha256')
    def is_accessible(self):
        return current_user.is_authenticated and current_user.profile in ('admin')
 
 
admin = Admin(template_mode="bootstrap3",index_view=AdminView())
admin.init_app(app)
 
# ADMIN - END
 
 
 
# VIEW - START
class RegisterForm(FlaskForm): # class RegisterForm extends FlaskForm
    email = StringField('Email',validators=[InputRequired(),Length(max=50),
                                            Email(message='Invalid email')])
    username = StringField('User Name',validators=[InputRequired(),Length(min=4,max=15)])
    password = PasswordField('Password',validators=[InputRequired(),Length(min=6,max=80)])
    confirm_password = PasswordField('Repeat Password',
                                     validators=[EqualTo('password',
                                                         message='Passwords must match')])
 
class LoginForm(FlaskForm): # class RegisterForm extends FlaskForm
    emailORusername = StringField('User name or Email',validators=[InputRequired()])
    password = PasswordField('Password',validators=[InputRequired()])
    remember = BooleanField('Remember me')
 
 
class ProfileForm(FlaskForm): # class RegisterForm extends FlaskForm
    email = StringField('Email')
    username = StringField('User Name')
    profile = StringField('Profile')
 
# VIEW - END
 
 
 
 
# MODEL - START
# ORM - Object Relational Mapping -Magico que se conecta a casi cualquiera base de datos.
db = SQLAlchemy(app) # class db extends app
 
 
 
 
class User(UserMixin,db.Model): # User extends db.Model
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50),unique=True)
    username = db.Column(db.String(15),unique=True)
    password = db.Column(db.String(80))
    profile = db.Column(db.String(10),default='student') # 'admin', 'staff', 'professor', 'student'
    confirmed = db.Column(db.Boolean(),default=False)
    userhash = db.Column(db.String(50))
    date_created  = db.Column(db.DateTime,  default=db.func.current_timestamp())
    date_modified = db.Column(db.DateTime,  default=db.func.current_timestamp(),
                                       onupdate=db.func.current_timestamp())
 
 
# MODEL - END
 
 
# MIGRATE - START
migrate = Migrate(app,db)
manager = Manager(app)
manager.add_command('db',MigrateCommand)
# MIGRATE - END
 
 
 
# LOGIN - START
login_manager = LoginManager() # Creando el objeto de la clase Login
login_manager.init_app(app) # Asociando el login a la app
login_manager.login_view = 'login' # Donde voy si no estoy loggeado
 
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id) # flask_login no tiene porque saber de la base de datos.
 
 
 
 
# LOGIN - END
 
 
# CONTROLLER  - START
 
@app.route('/profile',methods=['GET','POST'])
@login_required
def profile():
    form = ProfileForm(email=current_user.email,
                       username=current_user.username,
                       profile=current_user.profile)
    return render_template("profile.html",module="profile", form=form)
 
 
@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter(or_(User.email==form.emailORusername.data,
                                         User.username==form.emailORusername.data)).first()
            if not user or not check_password_hash(user.password, form.password.data):
                flash("Wrong user or Password!")
            elif user.confirmed:
                login_user(user, remember=form.remember.data)
                flash("Welcome back {}".format(current_user.username))
                return redirect(url_for('dashboard'))
            else:
                flash("User not confirmed. Please visit your email to confirm your user.")
 
 
    return render_template('login.html',module="login", form=form)
 
import random
@app.route('/signup',methods=['GET','POST'])
def signup():
    form = RegisterForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            # Ejercicio - juntar la dos partes!!! Coger del formulario y meter en base de datos!
            try:
                password_hashed=generate_password_hash(form.password.data,method="sha256")
                newuser = User(email=form.email.data,
                               username=form.username.data,
                               userhash=str(random.getrandbits(128)),
                               password=password_hashed)
                db.session.add(newuser)
                db.session.commit()
                send_email(newuser.email,'Please, confirm email / Por favor, confirmar correo.','mail/new_user',user=newuser,url=request.host, newpassword=password_hashed)
                flash("Great, your user was created successfully please visit your email {} to confirm your email / Muy bien, ahora visite su correo electrónico {} para confirmar el correo.".format(newuser.email,newuser.email))
                return redirect(url_for('login'))
            except:
                db.session.rollback()
                flash("Error creating user!")
    return render_template('signup.html',module="signup", form=form)
# CONTROLLER - END
 
@app.route('/confirmuser/<username>/<userhash>/',methods=['GET'])
def confirmuser(username,userhash):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('Invalid url.')
    elif userhash != user.userhash:
        flash('Invalid url.')
    elif user.confirmed:
        flash('Url already used.')
    else:
        try:
            flash('User confirmed successfully.')
            user.confirmed = 1
            db.session.commit()
        except:
            db.session.rollback()
            flash("Error confirming user!")
    return redirect(url_for('login'))
 
 
 
 
 
@app.route('/logout')
@login_required
def logout():
    flash("See you soon {}".format(current_user.username))
    logout_user()
    return redirect(url_for('index'))
 
 
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html',module="home")
 
 
@app.route('/')
def index():
    return render_template('index.html',module="home")
 
 
@app.errorhandler(500)
def internal_server_error(e):
    db.session.rollback()
    return render_template("500.html"), 500
 
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404
 
@app.errorhandler(403)
def access_denied(e):
    return render_template("403.html"), 403
 
# CREATING ADMIN MENU-BAR
from flask_admin.menu import MenuLink
admin.add_view(UserAdmin(User,db.session))
admin.add_link(MenuLink(name="Logout", url="/logout"))
admin.add_link(MenuLink(name="Go back", url="/"))
 
 
if __name__ == '__main__':
    manager.run()
 
