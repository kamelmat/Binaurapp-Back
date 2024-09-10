"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for, send_from_directory, session, redirect
from flask_migrate import Migrate
from flask_swagger import swagger
from api.utils import APIException, generate_sitemap
from api.routes import api
# from api.admin import setup_admin
# from api.commands import setup_commands
from api.models import db
from flask_jwt_extended import JWTManager


ENV = "development" if os.getenv("FLASK_DEBUG") == "1" else "production"
static_file_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../public/')
app = Flask(__name__)
app.url_map.strict_slashes = False
# Database condiguration
db_url = os.getenv("DATABASE_URL")
if db_url is not None:
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url.replace("postgres://", "postgresql://")
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:////tmp/test.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
MIGRATE = Migrate(app, db, compare_type=True)
db.init_app(app)
# Other configurations
# setup_admin(app) # Add the admin
# setup_commands(app)  # Add the admin
app.register_blueprint(api, url_prefix='/api')  # Add all endpoints form the API with a "api" prefix
# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")  # Change this!
jwt = JWTManager(app)

# Handle/serialize errors like a JSON object
"""
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code
"""

# Generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    if ENV == "development":
        return generate_sitemap(app)
    return send_from_directory(static_file_dir, 'index.html')

@app.route('/hola')
def hola():
	return jsonify({"message" : "Hola Mundo"}), 200

@app.route('/h1')
def h1():
	return "<h1>Hola Mundo</h1>"

# Any other endpoint will try to serve it like a static file
"""
@app.route('/<path:path>', methods=['GET'])
def serve_any_other_file(path):
    if not os.path.isfile(os.path.join(static_file_dir, path)):
        path = 'index.html'
    response = send_from_directory(static_file_dir, path)
    response.cache_control.max_age = 0  # avoid cache memory
    return response
"""

# set a random secret key to sign the cookie
# app.secret_key = 'os.getenv("CLIENT_SECRET")'

# set the key for the token info in the session dictionary
# TOKEN_INFO = 'token_info'

# This only runs if `$ python src/main.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 7081)) #cambie el puerto 3001 por el 8000 para gunicorn
    app.run(host='0.0.0.0', port=PORT, debug=False)
