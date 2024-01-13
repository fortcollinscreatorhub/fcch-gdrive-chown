#!/usr/bin/env python3
# -*- coding: utf-8 -*-

app_dir='/var/www/fcch-gdrive-chown'
fcch_creator_hub_public_folder='0BztS2sNeBoIFYXI0bVlncWswZmc'

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import os
import flask
import requests
import sqlite3
from werkzeug.middleware.proxy_fix import ProxyFix

os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = app_dir + "/client_secret.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = [
  'openid',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/drive',
]
API_SERVICE_NAME = 'drive'
API_VERSION = 'v2'

STATE_NONE = 'none'
STATE_LIST_FILES = 'list'
STATE_BUILD_TREE = 'build_tree'
STATE_CHOWN = 'chown'

def url_for(path):
  return script_name + '/' + path

def credentials_to_dict(credentials):
  return {
    'token': credentials.token,
    'refresh_token': credentials.refresh_token,
    'token_uri': credentials.token_uri,
    'client_id': credentials.client_id,
    'client_secret': credentials.client_secret,
    'scopes': credentials.scopes
  }

app = flask.Flask(__name__)
app.config['SESSION_COOKIE_NAME'] = 'fcch_gdrive_chown'
# Note: A secret key is included in the sample so that it works.
# If you use this code in your application, replace this with a truly secret
# key. See https://flask.palletsprojects.com/quickstart/#sessions.
app.secret_key = 'a3102d0ce0ce1f0b622b03b788cb788a0e66826778abe03b1a599ef3f0f5f42d'
# Reverse proxy configuration
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=0, x_host=0, x_prefix=0
)

def js_response(msg, data=None):
  js = {'message': str(msg)}
  if data is not None:
    js['data'] = data
  return flask.jsonify(js)

def exc_to_text(e):
  import traceback
  es = traceback.format_exception(e)
  return 'ERROR:\n' + '\n'.join(es)

def exc_to_html(e):
  import traceback
  es = traceback.format_exception(e)
  # FIXME: HTML-escape the lines...
  return 'ERROR:<br/>' + '<br/>'.join(es)

def get_db():
    dbcon = getattr(flask.g, '_dbcon', None)
    if dbcon is None:
      dbcon = flask.g._dbcon = sqlite3.connect(app_dir + "/var/db.db")
      dbcur = dbcon.cursor()
      dbcur.execute("CREATE TABLE IF NOT EXISTS files (user TEXT, id TEXT, title TEXT, isFolder INT, owner TEXT, reachable INT, disowned INT)")
      dbcur.execute("CREATE TABLE IF NOT EXISTS fileParents (user TEXT, id TEXT, parent TEXT)")
    return (dbcon, dbcur)

@app.teardown_appcontext
def close_connection(exception):
    dbcon = getattr(flask.g, '_dbcon', None)
    if dbcon is not None:
        dbcon.close()

@app.route('/')
def index():
  logged_in = 'credentials' in flask.session
  return flask.render_template('index.html', prefix=url_for(''), logged_in=logged_in)

@app.route('/test')
def test():
  if 'val' not in flask.session:
    val = -1
  else:
    val = int(flask.session['val'])
  val = val + 1
  flask.session['val'] = str(val)
  return js_response(val);

@app.route('/login')
def login():
  try:
    if 'credentials' in flask.session:
      raise Exception('Can\'t log in: Already logged in')

    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    # The URI created here must exactly match one of the authorized redirect URIs
    # for the OAuth 2.0 client, which you configured in the API Console. If this
    # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
    # error.
    flow.redirect_uri = oauth2callback_uri

    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true')

    # Store the state so the callback can verify the auth server response.
    flask.session['state'] = state

    return flask.redirect(authorization_url)
  except Exception as e:
    msg = 'ERROR: ' + exc_to_html(e)
    flask.flash(msg)
    return flask.redirect(url_for('/'))

@app.route('/oauth2callback')
def oauth2callback():
  try:
    # Specify the state when creating the flow in the callback so that it can
    # verified in the authorization server response.
    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = oauth2callback_uri

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials in the session.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    credentials = flow.credentials
    flask.session['credentials'] = credentials_to_dict(credentials)

    user_info_service = googleapiclient.discovery.build(
      serviceName='oauth2', version='v2', credentials=credentials)
    user_info = user_info_service.userinfo().get().execute()
    flask.session['email'] = user_info['email']

    msg = 'Log in succeeded'
  except Exception as e:
    msg = 'ERROR: ' + exc_to_html(e)

  flask.flash(msg)
  return flask.redirect(url_for('/'))

@app.route('/logout')
def logout():
  try:
    if 'credentials' not in flask.session:
      raise Exception('Can\'t log out: Not logged in')

    credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])
    revoke = requests.post('https://oauth2.googleapis.com/revoke',
        params={'token': credentials.token},
        headers = {'content-type': 'application/x-www-form-urlencoded'})
    revoke.raise_for_status()
    msg = 'Log out succeeded'
  except Exception as e:
    msg = 'ERROR: ' + exc_to_html(e)

  if 'credentials' in flask.session:
    del flask.session['credentials']

  flask.flash(msg)
  return flask.redirect(url_for('/'))

def raise_if_unauth():
  if 'credentials' not in flask.session:
    raise Exception('Not logged in')

@app.route('/get_drive_file_list')
def get_drive_file_list():
  try:
    raise_if_unauth()

    page_token = flask.request.args.get('page_token', None)

    if page_token is None:
      flask.session['count'] = str(0)
    count = int(flask.session['count'])

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    (dbcon, dbcur) = get_db()

    drive_service = googleapiclient.discovery.build(
      API_SERVICE_NAME, API_VERSION, credentials=credentials)

    response = drive_service.files().list(pageToken=page_token).execute()
    files = response.get("items", [])

    if page_token is None:
      dbcur.execute("DELETE FROM files WHERE user=?",
        (flask.session['email'], ))
      dbcur.execute("DELETE FROM fileParents WHERE user=?",
        (flask.session['email'], ))
    for file in files:
      file_id = file['id']
      file_title = file['title']
      file_owner = file['owners'][0]['emailAddress']
      file_reachable = 0
      file_disowned = 0

      file_type = file['mimeType']
      file_is_folder = file_type == 'application/vnd.google-apps.folder'
      if file_is_folder:
        file_parents = file['parents']
      else:
        file_parents = []

      dbcur.execute("INSERT INTO files (user, id, title, isFolder, owner, reachable, disowned) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (flask.session['email'], file_id, file_title, file_is_folder, file_owner, file_reachable, file_disowned))
      if file_is_folder:
        for file_parent in file_parents:
          dbcur.execute("INSERT INTO fileParents (user, id, parent) VALUES (?, ?, ?)",
            (flask.session['email'], file_id, file_parent['id']))

    fetched = len(files)
    count += fetched
    msg = f'Fetched {fetched} files (total now {count})'
    flask.session['count'] = str(count)

    page_token = response.get("nextPageToken", None)
    if page_token is None:
      msg = msg + '; fetch complete'
      data = {}
    else:
      msg = msg + '; continuing fetch'
      data = {'page_token': page_token}

    dbcon.commit()

    # Save credentials back to session in case access token was refreshed.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    flask.session['credentials'] = credentials_to_dict(credentials)
  except Exception as e:
    dbcon.rollback()
    msg = exc_to_text(e)
    data = None

  return js_response(msg, data)

def application(environ, start_response):
  global oauth2callback_uri
  strip_len = len(environ['PATH_INFO']) - 1
  oauth2callback_uri = environ['SCRIPT_URI'][:-strip_len] + 'oauth2callback'
  global script_name
  script_name = environ['SCRIPT_NAME']
  return app(environ, start_response)
