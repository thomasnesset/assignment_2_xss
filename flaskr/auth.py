import functools
import pyotp

from flask import (
    Flask, Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash # for hashing passwords
from flaskr.db import get_db

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

bp = Blueprint('auth', __name__, url_prefix='/auth')
limiter = Limiter(
    get_remote_address,
    app=Flask(__name__),
    default_limits=["3 per minute"],
    storage_uri="memory://",
)

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        otp_key = pyotp.random_base32()
        
        db = get_db()
        error = None
        
        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
            
        if error is None:
            try:
                db.execute(
                    'INSERT INTO user (username, password, otp_key) VALUES (?, ?, ?)', 
                    (username, generate_password_hash(password), otp_key)
                )
                db.commit()
            except db.IntegrityError:
                error = 'User {} is already registered.'.format(username)
            else:
                qrcode = pyotp.totp.TOTP(otp_key).provisioning_uri(username, issuer_name="Mads Andre Vangen99 sin blogg")
                return render_template('auth/twofa_register.html', totp=qrcode)
            
        flash(error)
        
    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
@limiter.limit("3/minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        otp = request.form['otp']
        
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()
        
        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'
        elif not pyotp.TOTP(user['otp_key']).verify(otp):
            error = 'Incorrect OTP.'
            
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index', name=username))
        
        flash(error)
        
    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')
    
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()
        
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        
        return view(**kwargs)
    
    return wrapped_view

@bp.route('twofa_register')
def twofa_register():
    return render_template('auth/twofa_register.html')
