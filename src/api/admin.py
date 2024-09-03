import os
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from .models import db, Users, Mixes, Soundscapes, Binaural, Tutorials


def setup_admin(app):
    app.secret_key = os.environ.get('FLASK_APP_KEY', 'sample key')
    app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
    admin = Admin(app, name='4Geeks Admin', template_mode='bootstrap3')
    admin.add_view(ModelView(Users, db.session))
    admin.add_view(ModelView(Mixes, db.session))
    admin.add_view(ModelView(Soundscapes, db.session))
    admin.add_view(ModelView(Binaural, db.session))
    admin.add_view(ModelView(Tutorials, db.session))  # Add your models here, for example this is how we add a the User model to the admin
    # admin.add_view(ModelView(YourModelName, db.session))  # You can duplicate that line to add mew models
