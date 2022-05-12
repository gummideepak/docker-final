import logging
from flask import redirect
from flask_login import login_user, login_required, logout_user, current_user
from app import db
from app.db.models import User, Transactions
from faker import Faker

def test_adding_user(application):
    log = logging.getLogger("myApp")
    with application.app_context():
        assert db.session.query(User).count() == 0
        assert db.session.query(Transactions).count() == 0
        #showing how to add a record
        #create a record
        user = User('keith@webizly.com', 'testtest')
        #add it to get ready to be committed
        db.session.add(user)
        #call the commit
        #db.session.commit()
        #assert that we now have a new user
        #assert db.session.query(User).count() == 1
        #finding one user record by email
        user = User.query.filter_by(email='keith@webizly.com').first()
        log.info(user)
        #asserting that the user retrieved is correct
        assert user.email == 'keith@webizly.com'
        #this is how you get a related record ready for insert
        user.transactions= [Transactions("CREDIT",500,1),Transactions("CREDIT",500,1)]
        #commit is what saves the transactions
        db.session.commit()
        assert db.session.query(Transactions).count() == 2
        db.session.delete(user)
        assert db.session.query(User).count() == 0
        assert db.session.query(Transactions).count() == 0

    
def extract_csrf_token(page):
    start = page.find('name="csrf_token" type="hidden" value="')+len('name="csrf_token" type="hidden" value="')
    page = page[start:]
    end = page.find('"')
    page = page[:end]
    return page
