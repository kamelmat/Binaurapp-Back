from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Enum

db = SQLAlchemy()

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    first_name = db.Column(db.String(120), unique=False, nullable=True)
    last_name = db.Column(db.String(120), unique=False, nullable=True)
    country = db.Column(db.String(120), unique=False, nullable=True)
    city = db.Column(db.String(120), unique=False, nullable=True)
    date_of_birth = db.Column(db.Date, unique=False, nullable=True)
    password = db.Column(db.String(80), unique=False, nullable=True)
    is_active = db.Column(db.Boolean(), unique=False, nullable=True)
    is_admin = db.Column(db.Boolean(), unique=False, nullable=True)

    def __repr__(self):
        return f'<Users {self.email}>'

    def serialize(self):
        return {'id': self.id,
                'email': self.email,
                'city': self.city,
                'password': self.password,
                'first_name': self.first_name,
                'last_name': self.last_name,
                'country': self.country,
                'date_of_birth': self.date_of_birth,
                'is_active': self.is_active,
                'is_admin': self.is_admin}
      

class Soundscapes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=False, nullable=False)
    duration = db.Column(db.Integer, unique=False, nullable=True)
    genre = db.Column(db.String(120), unique=False, nullable=True)
    url_jamendo = db.Column(db.String, unique=False, nullable=True)
    
    def __repr__(self):
        return f'<Soundscapes {self.name}>'

    def serialize(self):
        return {'id': self.id,
                'name': self.name,
                'duration': self.duration,
                'genre': self.genre,
                'url_jamendo': self.url_jamendo}
                


class Mixes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mix_title = db.Column(db.String(120), unique=True, nullable=False)
    user_id = db.Column(db.Integer)
    track_1_url = db.Column(db.String, unique=False, nullable=False)
    track_1_name = db.Column(db.String)    
    binaural_id = db.Column(db.String, unique=False, nullable=False)
    track_2_name = db.Column(db.String)
    date = db.Column(db.Date)
    acumulator_concurrency = db.Column(db.Integer)
    
    def __repr__(self):
        return f'<Mixes {self.mix_title}>'

    def serialize(self):
        return {'id': self.id,
                'mix_title': self.mix_title,
                'user_id': self.user_id,
                'track_1_url': self.track_1_url,
                'track_1_name': self.track_1_name,
                'binaural_id': self.binaural_id,
                'track_2_name': self.track_2_name,
                'date': self.date,
                'acumulator_concurrency': self.acumulator_concurrency}
             

class Binaural(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.Enum("Alpha", "Theta", "Delta", name="type"), unique=False )
    name = db.Column(db.String(120), unique=False, nullable=False)
    duration = db.Column(db.Integer, unique=False, nullable=True)
    description = db.Column(db.String, unique=False, nullable=True)
    track_url = db.Column(db.String, unique=False, nullable=True)
    date_publication = db.Column(db.Date, unique=False, nullable=True)
    # accumulator_concurrency = db.Column(db.Integer)
    
    def __repr__(self):
        return f'<Binaural {self.name}>'

    def serialize(self):
        return {'id': self.id,
                'type': self.type,
                'name': self.name,
                'duration': self.duration,
                'description': self.description,
                'track_url': self.track_url,
                'date_publication': self.date_publication}
                # 'accumulator_concurrency': self.accumulator_concurrency}              
                
class Tutorials(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    tutorials_type = db.Column(db.Enum("Meditation", "Sleep", "Focus", name="tutorials_type"))
    title = db.Column(db.String)
    body = db.Column(db.String)
    video_url = db.Column(db.String)
    audio_url = db.Column(db.String)
    last_modified = db.Column(db.Date)

    def __repr__(self):
        return f'<Tutorials {self.title}>'

    def serialize(self):
        return {'id': self.id,
                'user_id': self.user_id,
                'type': self.tutorials_type,
                'title': self.title,
                'body': self.body,
                'video_url': self.video_url,
                'audio_url': self.audio_url,
                'last_modified': self.last_modified}
