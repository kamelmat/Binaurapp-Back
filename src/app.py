"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for, send_from_directory, session, redirect
from flask_migrate import Migrate
from flask_swagger import swagger
from api.utils import APIException, generate_sitemap
from api.routes import api
from api.admin import setup_admin
from api.commands import setup_commands
from api.models import db
# from models import Person
from flask_jwt_extended import JWTManager
# Spotify importations
import time
import spotipy
from spotipy.oauth2 import SpotifyOAuth
# from spotipy.cache_handler import FlaskSessionCacheHandler
# from google.cloud import storage


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
setup_admin(app) # Add the admin
setup_commands(app)  # Add the admin
app.register_blueprint(api, url_prefix='/api')  # Add all endpoints form the API with a "api" prefix
# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")  # Change this!
jwt = JWTManager(app)


""" # Config Spotify
cache_handler = FlaskSessionCacheHandler(session)
sp_oauth = SpotifyOAuth(
    cliend_id = os.getenv("CLIENT_ID"),
    client_secret = os.getenv("CLIENT_SECRET"),
    redirect_uri = os.getenv("REDIRECT_URI"),
    scope = os.getenv("SCOPE"),
    cache_handler = os.getenv("cache_handler"),
    show_dialog = True)

sp = Spotify(auth_manager = sp_oauth) """


# Todo lo referente al Google Cloud Storage
""" 
def authenticate_with_service_account(json_keyfile_path, project_id):
"""     """
Authenticate using a service account key file.
    """ """
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = json_keyfile_path
    storage_client = storage.Client(project=project_id)
    return storage_client

def list_blobs(bucket_name):
    
    Lists all the blobs in the bucket and returns a dictionary with file names and their URLs.
   
    storage_client = authenticate_with_service_account('path/to/your/service-account-file.json', 'your-project-id')

    bucket = storage_client.bucket(bucket_name)
    blobs = bucket.list_blobs()

    files_dict = {}
    for blob in blobs:
        files_dict[blob.name] = blob.generate_signed_url(expiration=3600)  # URL válida por una hora

    return files_dict
""" 
"""
# Especifica el nombre de tu bucket
bucket_name = "your-bucket-name"

# Llama a la función para listar los archivos y obtener sus URLs
files_dict = list_blobs(bucket_name)

# Imprime la lista de archivos y sus URLs
for file_name, url in files_dict.items():
    print(f"{file_name}: {url}")
     """

# Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code


# Generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    if ENV == "development":
        return generate_sitemap(app)
    return send_from_directory(static_file_dir, 'index.html')


# Any other endpoint will try to serve it like a static file
@app.route('/<path:path>', methods=['GET'])
def serve_any_other_file(path):
    if not os.path.isfile(os.path.join(static_file_dir, path)):
        path = 'index.html'
    response = send_from_directory(static_file_dir, path)
    response.cache_control.max_age = 0  # avoid cache memory
    return response
    
# set the name of the session cookie
app.config['SESSION_COOKIE_NAME'] = 'Spotify Cookie'

# set a random secret key to sign the cookie
app.secret_key = 'os.getenv("CLIENT_SECRET")'

# set the key for the token info in the session dictionary
TOKEN_INFO = 'token_info'

@app.route('/spotify-login')
def spotifyLogin():
    # create a SpotifyOAuth instance and get the authorization URL
    auth_url = create_spotify_oauth().get_authorize_url()
    # redirect the user to the authorization URL
    return redirect(auth_url)

# function to get the token info from the session
def get_token():
    token_info = session.get(TOKEN_INFO, None)
    if not token_info:
        # if the token info is not found, redirect the user to the login route
        redirect(url_for('login', _external=False))
    
    # check if the token is expired and refresh it if necessary
    now = int(time.time())

    is_expired = token_info['expires_at'] - now < 60
    if(is_expired):
        spotify_oauth = create_spotify_oauth()
        token_info = spotify_oauth.refresh_access_token(token_info['refresh_token'])

    return token_info

# route to handle the redirect URI after authorization
@app.route('/redirect')
def redirect_page():
    # clear the session
    session.clear()
    # get the authorization code from the request parameters
    code = request.args.get('code')
    # exchange the authorization code for an access token and refresh token
    token_info = create_spotify_oauth().get_access_token(code)
    # save the token info in the session
    session[TOKEN_INFO] = token_info
    # redirect the user to the save_discover_weekly route
    return redirect(url_for('save_discover_weekly',_external=True))


# route to save the Discover Weekly songs to a playlist
@app.route('/saveDiscoverWeekly')
def save_discover_weekly():
    try: 
        # get the token info from the session
        token_info = get_token()
    except:
        # if the token info is not found, redirect the user to the login route
        print('User not logged in')
        return redirect("/login")

    # create a Spotipy instance with the access token
    sp = spotipy.Spotify(auth=token_info['access_token'])

    # get the user's playlists
    current_playlists =  sp.current_user_playlists()['items']
    discover_weekly_playlist_id = None
    saved_weekly_playlist_id = None

    # find the Discover Weekly and Saved Weekly playlists
    for playlist in current_playlists:
        if(playlist['name'] == 'Discover Weekly'):
            discover_weekly_playlist_id = playlist['id']
        if(playlist['name'] == 'Saved Weekly'):
            saved_weekly_playlist_id = playlist['id']
    
    # if the Discover Weekly playlist is not found, return an error message
    if not discover_weekly_playlist_id:
        return 'Discover Weekly not found.'
    
    # get the tracks from the Discover Weekly playlist
    discover_weekly_playlist = sp.playlist_items(discover_weekly_playlist_id)
    song_uris = []
    for song in discover_weekly_playlist['items']:
        song_uri= song['track']['uri']
        song_uris.append(song_uri)
    
    # add the tracks to the Saved Weekly playlist
    sp.user_playlist_add_tracks(user_id, saved_weekly_playlist_id, song_uris, None)

    # return a success message
    return ('Discover Weekly songs added successfully')

def create_spotify_oauth():
    return SpotifyOAuth(
        client_id = os.environ.get(CLIENT_ID),
        client_secret = os.environ.get(CLIENT_SECRET),
        redirect_uri = url_for ('redirect', _external=True),
        scope = 'user-library-read playlist-modify-public playlist-modify-private'
    )

# This only runs if `$ python src/main.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3001))
    app.run(host='0.0.0.0', port=PORT, debug=True)
