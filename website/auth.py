from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('login successful', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.index'))
            else:
                flash('login failed', category='error')
        else:
            flash('user not found', category='error')

    return render_template('login.html', user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('user already present', category ='error')
        elif len(email) < 4 :
            flash("Email is too short", category='error')
        elif len(fname) < 2 :
            flash("first name is too short", category='error')
        elif len(lname) < 2 :
            flash("last name is too short", category='error')
        elif len(password1) < 4 or len(password2) < 4 :
            flash("password 1 or password 2 is too short", category='error')
        elif password1 != password2:
            flash("password 1 and passsword 2 not matches",category='error')
        else:
            # add user to database
            newUser = User(email=email, first_name=fname, last_name=lname,password=generate_password_hash(password1, method = 'sha256'))
            db.session.add(newUser)
            db.session.commit()

            login_user(user, remember=True)
            flash("Account created", category='success')
            return redirect(url_for('views.index'))

    return render_template('signup.html', user=current_user)