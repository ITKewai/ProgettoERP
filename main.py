import os
import time
from datetime import datetime
from flask import Flask, render_template, request, send_file, abort, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from sqlalchemy import desc
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, EqualTo
import waitress

app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@localhost/italianox?charset=utf8mb4'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"


# TODO: Clocking in and out times.
# TODO: Timesheets to keep track of your employees’ working hours.


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class Users(db.Model, UserMixin):
    # __tablename__ = 'Users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    group = db.Column(db.String(80), nullable=False, default='user')
    avatar = db.Column(db.String(80), nullable=False, default='/img/avatar.png')
    workingon = db.Column(db.Text, nullable=False, default='')

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'group': self.group,
            'avatar': self.avatar,
            'workingon': self.workingon,
        }


class WorkCode(db.Model):
    # __tablename__ = 'WorkCode'
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(80), nullable=False)

    # def to_dict(self):
    #     return {
    #         'id': self.id,
    #         'username': self.username,
    #         'group': self.group,
    #         'avatar': self.avatar,
    #         'workingon': self.workingon,
    #     }


class Clocking(db.Model):
    # __tablename__ = 'Clocking'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(Users.id))
    code = db.Column(db.Integer, db.ForeignKey(WorkCode.id))
    clockin = db.Column(db.String(80), default=datetime.now())
    clockout = db.Column(db.String(80))
    moreinfo = db.Column(db.Text)
    IP = db.Column(db.String(80))

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'code': self.code,
            'clockin': self.clockin,
            'clockout': self.clockout,
            'moreinfo': self.moreinfo,
            'IP': self.IP,
        }


class RegisterForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    #     InputRequired(), Length(min=8, max=20),
    # EqualTo('password_confirm', message='La password deve essere uguale!')], render_kw={"placeholder": "Password"})

    # password_confirm = PasswordField(validators=[
    #     InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Conferma Password"})

    submit = SubmitField('Registrati')

    def validate_username(self, username):
        existing_user_username = Users.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


with app.app_context():
    db.create_all()


# // instance


@app.context_processor
def inject_global_vars():
    return {
        'HosterName': '',
        'LeOpZioNi': {'uno': 'UNO', 'due': 'DUE'},
        'WorkCode': WorkCode,
    }


@app.route('/')
@login_required
def index():
    print()
    # return render_template('ClockInForm.html')
    return render_template('ClockTable.html')
    # return render_template('FormTutto.html')


@app.route('/a')
@login_required
def indexx():
    print()
    return render_template('ClockOutForm.html')
    # return render_template('FormTutto.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user, remember=True)
                return redirect(url_for('index'))
            else:
                flash("Password Errata - Riprova!")
        else:
            print(form.errors)
            flash("L'utente non esiste")
    return render_template('LoginForm.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = Users(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('RegisterForm.html', form=form, url_for=url_for)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/api/ClockInForm", methods=["POST"])
@login_required
def ClockInForm():
    obj = Clocking(
        user_id=current_user.id,
        code=request.form["Commessa"],
        IP=request.environ.get('REMOTE_ADDR'),
    )
    db.session.add(obj)
    db.session.commit()

    Users.query.filter_by(id=current_user.id).update(dict(workingon=request.form["Commessa"]))
    db.session.commit()

    return redirect(url_for('index'))


@app.route("/api/ClockOutForm", methods=["POST"])
@login_required
def ClockOutForm():
    data = Clocking.query.filter_by(user_id=current_user.id).order_by(desc(Clocking.clockin)).first()
    Clocking.query.filter_by(id=data.id).update(dict(
        clockout=datetime.now(),
        moreinfo=None if "InputOggetto1" not in request.form.keys() else request.form["InputOggetto1"]
    ))
    # data.clockout = datetime.now()
    # data.moreinfo = '' if "Commessa" not in request.form.keys() else request.form["Commessa"]
    db.session.commit()
    #
    # Users.query.filter_by(id=current_user.id).update(dict(workingon=''))
    # db.session.commit()

    return redirect(url_for('index'))


@app.route("/api/RegistroAssicurazioneSanitaria", methods=["POST", "GET"])
@app.route('/api/RegistroAssicurazioneSanitaria')
def TableRegistroAssicurazioneSanitaria():
    query = Clocking.query

    # search filter
    search = request.args.get('search[value]')
    if search:
        query = query.filter(db.or_(
            Clocking.id.like(f'%{search}%'),
            Clocking.user_id.like(f'%{search}%'),
            Clocking.code.like(f'%{search}%'),
            Clocking.clockin.like(f'%{search}%'),
            Clocking.clockout.like(f'%{search}%'),
            Clocking.moreinfo.like(f'%{search}%'),
            Clocking.IP.like(f'%{search}%'),
        ))
    total_filtered = query.count()

    # sorting
    order = []
    i = 0
    while True:
        col_index = request.args.get(f'order[{i}][column]')
        if col_index is None:
            break
        col_name = request.args.get(f'columns[{col_index}][data]')
        if col_name not in [
            'id',
            'user_id',
            'code',
            'clockin',
            'clockout',
            'moreinfo',
            'IP',
        ]:
            col_name = 'id'
        descending = request.args.get(f'order[{i}][dir]') == 'desc'
        col = getattr(Clocking, col_name)
        if descending:
            col = col.desc()
        order.append(col)
        i += 1
    if order:
        query = query.order_by(*order)

    # pagination
    start = request.args.get('start', type=int)
    length = request.args.get('length', type=int)
    query = query.offset(start).limit(length)

    # response
    return {
        'data': [user.to_dict() for user in query],
        'recordsFiltered': total_filtered,
        'recordsTotal': Clocking.query.count(),
        'draw': request.args.get('draw', type=int),
    }

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
    # waitress.serve(app, listen='0.0.0.0:80')
