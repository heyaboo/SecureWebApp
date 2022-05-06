
import sqlite3
from datetime import datetime, timedelta
from passlib.hash import pbkdf2_sha256
from flask import request, g
import jwt

#SECRET like these are really safe because they are under levels of security unless heartbleed happens. 
SECRET = 'bfg28y7efg238re7r6t32gfo23vfy7237yibdyo238do2v3'

def get_user_with_credentials(email, password):
    try:
        con = sqlite3.connect('bank.db')
        cur = con.cursor()
        cur.execute('''
            SELECT email, name, password FROM users where email=?''',
            (email,))
        row = cur.fetchone()
        if row is None:
            return None
        email, name, hash = row
        if not pbkdf2_sha256.verify(password, hash):
            return None
        return {"email": email, "name": name, "token": create_token(email)}
    finally:
        con.close()

def logged_in():
    token = request.cookies.get('auth_token')
    try:
        data = jwt.decode(token, SECRET, algorithms=['HS256'])
        g.user = data['sub']
        return True
    except jwt.InvalidTokenError:
        return False

def create_token(email):
    now = datetime.utcnow()
    #'sub' = subject, 'iat' = time the token is activated, 'exp' = when the token expires
    payload = {'sub': email, 'iat': now, 'exp': now + timedelta(minutes=60)}
    #This is secure hashing, there is a website for you for encoding by going to jwt.io
    token = jwt.encode(payload, SECRET, algorithm='HS256')
    return token


