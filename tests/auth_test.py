"""This test the homepage"""
import logging
from flask import redirect
from flask_login import login_user, login_required, logout_user, current_user
from app import db
from app.db.models import User, Transactions
from faker import Faker


def test_user_regestration(client):
    assert db.session.query(User).count() == 0
    log = logging.getLogger("myApp")
    token = str(client.get('/register').data)
    start = token.find('name="csrf_token" type="hidden" value="')+len('name="csrf_token" type="hidden" value="')
    token = token[start:]
    end = token.find('"')
    token = token[:end]
    # log.info(token)
    data = {
        'email':'test@njit.edu',
        'password': 'qwerty1234',
        'confirm': 'qwerty1234',
        'csrf_token': token
    }
    response = client.post('/register', data=data)
    # log.info(response)
    user = User.query.filter_by(email='test@njit.edu').first()
    # log.info(user)
    assert user.email == 'test@njit.edu'
    assert db.session.query(User).count() == 1
    return user

def test_user_login(application, client):
    with application.app_context():
        token = str(client.get('/login').data)
        token = extract_csrf_token(token)
        # log.info(token)
        data = {
            'email':'test@njit.edu',
            'password': 'qwerty1234',
            'csrf_token': token
        }
        response = client.post('/login', data=data, follow_redirects=True)
        assert b'Welcome' in response.data


def test_user_login_access(application, client):
    with application.app_context():
        token = str(client.get('/login').data)
        token = extract_csrf_token(token)
        data = {
            'email':'test@njit.edu',
            'password': 'qwerty1234',
            'csrf_token': token
        }
        response = client.post('/login', data=data, follow_redirects=True)
        response = client.get('/users', follow_redirects=True)
        assert response.status_code == 200

def test_user_balance(application, client):
    with application.app_context():
        assert db.session.query(User).count() == 0
        log = logging.getLogger("myApp")
        token = str(client.get('/register').data)
        start = token.find('name="csrf_token" type="hidden" value="')+len('name="csrf_token" type="hidden" value="')
        token = token[start:]
        end = token.find('"')
        token = token[:end]
        # log.info(token)
        data = {
            'email':'test@njit.edu',
            'password': 'qwerty1234',
            'confirm': 'qwerty1234',
            'csrf_token': token
        }
        response = client.post('/register', data=data)
        # log.info(response)
        user = User.query.filter_by(email='test@njit.edu').first()
        # log.info(user)
        assert user.email == 'test@njit.edu'
        assert db.session.query(User).count() == 1
        token = str(client.get('/login').data)
        token = extract_csrf_token(token)
        data = {
            'email':'test@njit.edu',
            'password': 'qwerty1234',
            'csrf_token': token
        }
        response = client.post('/login', data=data, follow_redirects=True)
        response = client.get('/dashboard', follow_redirects=True)
        assert b'0$' in response.data
        print(data)
        assert response.status_code == 200

def test_unauthorized_users(application, client):
    with application.app_context():
        #logout if alredy logged in
        response = client.post('/logout', follow_redirects=True)
        response = client.get('/users', follow_redirects=True)
        assert b'Please log in to access this page.' in response.data

def test_unauthorized_profile(application, client):
    with application.app_context():
        #logout if alredy logged in
        response = client.post('/logout', follow_redirects=True)
        response = client.get('/profile', follow_redirects=True)
        assert b'Please log in to access this page.' in response.data

def test_unauthorized_dashboard(application, client):
    with application.app_context():
        #logout if alredy logged in
        response = client.post('/logout', follow_redirects=True)
        response = client.get('/dashboard', follow_redirects=True)
        assert b'Please log in to access this page.' in response.data
    
def test_authorized_register(application, client):
    with application.app_context():
        #logout if alredy logged in
        response = client.post('/logout', follow_redirects=True)
        response = client.get('/register', follow_redirects=True)
        assert response.status_code == 200

def test_unauthorized_upload(application, client):
    with application.app_context():
        #logout if alredy logged in
        response = client.post('/logout', follow_redirects=True)
        response = client.get('/transactions/upload', follow_redirects=True)
        assert b'Please log in to access this page.' in response.data


def test_page_not_found(application, client):
    with application.app_context():
        #logout if alredy logged in
        response = client.post('/testpage', follow_redirects=True)
        assert b'Oops! Looks like the page doesn\'t exist anymore' in response.data


def extract_csrf_token(page):
    start = page.find('name="csrf_token" type="hidden" value="')+len('name="csrf_token" type="hidden" value="')
    page = page[start:]
    end = page.find('"')
    page = page[:end]
    return page