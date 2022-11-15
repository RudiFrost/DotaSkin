from flask import Flask
from flask import make_response, jsonify
from flask import render_template, redirect
from flask_login import LoginManager, login_user, login_required, logout_user
from flask_login import current_user
from flask_restful import Api
from flask_wtf import FlaskForm
from wtforms import PasswordField, BooleanField, SubmitField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired

import news_resources
from data import db_session, news_api
from data.news import News
from data.users import User
from forms.user import RegisterForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
api = Api(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    db_sess = db_session.create_session()
    return db_sess.query(User).get(user_id)


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


@app.route('/')
def index():

    return render_template("index.html")


@app.route('/about')
def about_site():
    return render_template('about.html')


@app.route('/invoker')
def invoker_set():
    return render_template('invoker.html')


@app.route('/bloodseeker')
def bloodseeker_set():
    return render_template('bloodseeker.html')

@app.route('/earthshaker')
def earthshaker_set():
    return render_template('earthshaker.html')

@app.route('/enigma')
def enigma_set():
    return render_template('enigma.html')

@app.route('/phantom_lancer')
def phantom_lancer_set():
    return render_template('phantom_lancer.html')

@app.route('/')
def money():
    return redirect("/")


class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Submit')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.email == form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect("/")
        return render_template('login.html', message="Wrong username or password", form=form)
    return render_template('login.html', title='Authorization', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('register.html', title='Registration', form=form, message="Passwords don't match")
        db_sess = db_session.create_session()
        if db_sess.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', title='Registration', form=form,
                                   message="User already exist")
        user = User(
            name=form.name.data, email=form.email.data, about=form.about.data
        )
        user.set_password(form.password.data)
        db_sess.add(user)
        db_sess.commit()
        return redirect('/login')
    return render_template('register.html', title='Registration', form=form)


def main():
    app.run(debug=True)


if __name__ == '__main__':
    main()
