#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import os
import flask
import requests
import sqlite3
from werkzeug.middleware.proxy_fix import ProxyFix

# Configuration
app_dir = '/var/www/fcch-gdrive-chown'
fcch_creator_hub_public_folder = '0BztS2sNeBoIFYXI0bVlncWswZmc'
target_owner_email_by_domain = {
  None: ('stephen.r.warren@gmail.com', True),
  'gmail.com': ('stephen.r.warren@gmail.com', True),
  'fortcollinscreatorhub.org': ('stephen.warren@fortcollinscreatorhub.org', False),
}

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
# v3 API doesn't seem to work for consumer ownership transfers:-(
API_VERSION = 'v2'

REACHABLE_UNKNOWN = 0
REACHABLE_NO = 1
REACHABLE_YES = 2

CHOWN_UNKNOWN = 0
CHOWN_NO = 1
CHOWN_YES = 2
CHOWN_DONE = 3

PENDING_OWNER_NO = 0
PENDING_OWNER_YES = 1
PENDING_OWNER_DONE = 2

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
      dbcur.execute("CREATE TABLE IF NOT EXISTS files (user TEXT, id TEXT, title TEXT, isFolder INT, owner TEXT, reachable INT, needChown INT, doChown INT, pendingOwner INT)")
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
    return flask.redirect(url_for(''))

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
  return flask.redirect(url_for(''))

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
  return flask.redirect(url_for(''))

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
      file_type = file['mimeType']
      if file_type == 'application/vnd.google-apps.shortcut':
        continue
      file_is_folder = file_type == 'application/vnd.google-apps.folder'
      file_owner = file['owners'][0]['emailAddress']
      file_reachable = REACHABLE_UNKNOWN
      file_need_chown = CHOWN_UNKNOWN
      file_do_chown = CHOWN_UNKNOWN
      file_pending_owner = file['userPermission']['pendingOwner']
      file_parents = file.get('parents', [])

      dbcur.execute("INSERT INTO files (user, id, title, isFolder, owner, reachable, needChown, doChown, pendingOwner) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (flask.session['email'], file_id, file_title, file_is_folder, file_owner, file_reachable, file_need_chown, file_do_chown, file_pending_owner))
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

@app.route('/show_drive_file_list')
def show_drive_file_list():
  try:
    raise_if_unauth()

    (dbcon, dbcur) = get_db()
    dbres = dbcur.execute(
      "SELECT * FROM files WHERE user=?",
      (flask.session['email'], ))
    files = dbres.fetchall()
    dbres = dbcur.execute(
      "SELECT user, id, parent FROM fileParents WHERE user=?",
      (flask.session['email'], ))
    file_parents = dbres.fetchall()

    msg = ''
    msg += 'Files:\n'
    for file in files:
      msg += repr(file) + '\n'
    msg += 'File Parents:\n'
    for file_parent in file_parents:
      msg += repr(file_parent) + '\n'

    dbcon.commit()
  except Exception as e:
    dbcon.rollback()
    msg = exc_to_text(e)

  return js_response(msg)

@app.route('/calc_files_to_change_ownership')
def calc_files_to_change_ownership():
  try:
    raise_if_unauth()

    (dbcon, dbcur) = get_db()
    dbres = dbcur.execute(
      "SELECT id, isFolder, owner FROM files WHERE user=?",
      (flask.session['email'], ))
    files = dbres.fetchall()
    dbres = dbcur.execute(
      "SELECT id, parent FROM fileParents WHERE user=?",
      (flask.session['email'], ))
    file_parents = dbres.fetchall()

    file_data_of_file_id = {}
    for file_id, file_is_folder, file_owner in files:
      file_data_of_file_id[file_id] = (file_is_folder, file_owner)

    child_file_ids_of_parent = {}
    for file_id, file_parent in file_parents:
      child_file_ids = child_file_ids_of_parent.get(file_parent, [])
      child_file_ids.append(file_id)
      child_file_ids_of_parent[file_parent] = child_file_ids

    reachable_files = []
    need_chown_files = []
    do_chown_files = []
    parents_to_do = [fcch_creator_hub_public_folder]
    parents_done = {}

    target_owner_emails = [email for (email, use_pending) in target_owner_email_by_domain.values()]
    while parents_to_do:
      parent = parents_to_do.pop()
      child_file_ids = child_file_ids_of_parent.get(parent, [])
      for file_id in child_file_ids:
        file_is_folder, file_owner = file_data_of_file_id[file_id]
        if file_is_folder:
          if file_id not in parents_done:
            parents_done[file_id] = True
            parents_to_do.append(file_id)
        reachable_files.append(file_id)
        need_chown = file_owner not in target_owner_emails
        if need_chown:
          need_chown_files.append(file_id)
        if (file_owner == flask.session['email']) and need_chown:
          do_chown_files.append(file_id)

    dbcur.execute("UPDATE files SET reachable=? WHERE user=?",
      (REACHABLE_NO, flask.session['email']))
    rows = [(REACHABLE_YES, flask.session['email'], file_id) for file_id in reachable_files]
    dbcur.executemany("UPDATE files SET reachable=? WHERE user=? AND id=?", rows)

    dbcur.execute("UPDATE files SET needChown=? WHERE user=?",
      (CHOWN_NO, flask.session['email']))
    rows = [(CHOWN_YES, flask.session['email'], file_id) for file_id in need_chown_files]
    dbcur.executemany("UPDATE files SET needChown=? WHERE user=? AND id=?", rows)

    dbcur.execute("UPDATE files SET doChown=? WHERE user=?",
      (CHOWN_NO, flask.session['email']))
    rows = [(CHOWN_YES, flask.session['email'], file_id) for file_id in do_chown_files]
    dbcur.executemany("UPDATE files SET doChown=? WHERE user=? AND id=?", rows)

    msg = 'Calculation complete'

    dbcon.commit()
  except Exception as e:
    dbcon.rollback()
    msg = exc_to_text(e)

  return js_response(msg)

@app.route('/show_files_need_change_ownership')
def show_files_need_change_ownership():
  try:
    raise_if_unauth()

    (dbcon, dbcur) = get_db()
    dbres = dbcur.execute(
      "SELECT * FROM files WHERE user=? AND needChown=2",
      (flask.session['email'], ))
    files = dbres.fetchall()

    msg = ''
    msg += 'Files:\n'
    for file in files:
      msg += repr(file) + '\n'

    dbcon.commit()
  except Exception as e:
    dbcon.rollback()
    msg = exc_to_text(e)

  return js_response(msg)

@app.route('/show_files_to_change_ownership')
def show_files_to_change_ownership():
  try:
    raise_if_unauth()

    (dbcon, dbcur) = get_db()
    dbres = dbcur.execute(
      "SELECT * FROM files WHERE user=? AND doChown=2",
      (flask.session['email'], ))
    files = dbres.fetchall()

    msg = ''
    msg += 'Files:\n'
    for file in files:
      msg += repr(file) + '\n'

    dbcon.commit()
  except Exception as e:
    dbcon.rollback()
    msg = exc_to_text(e)

  return js_response(msg)

def get_owner_pend():
  cur_domain = flask.session['email'].split('@')[1]
  if cur_domain not in target_owner_email_by_domain:
    cur_domain = None
  target_owner, do_pending = target_owner_email_by_domain[cur_domain]
  return target_owner, do_pending

@app.route('/chown_files')
def chown_files():
  try:
    raise_if_unauth()

    init = flask.request.args.get('init', 'true')
    if init == 'true':
      flask.session['count'] = str(0)
    count = int(flask.session['count'])

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    target_owner, do_pending = get_owner_pend()
    permission = {
        'type': 'user',
        'value': target_owner,
    }
    if do_pending:
        permission['role'] = 'writer'
        permission['pendingOwner'] = True
    else:
        permission['role'] = 'owner'
        permission['transferOwnership'] = True

    (dbcon, dbcur) = get_db()

    drive_service = googleapiclient.discovery.build(
      API_SERVICE_NAME, API_VERSION, credentials=credentials)

    dbres = dbcur.execute(
      "SELECT id, title FROM files WHERE user=? AND reachable=? AND doChown=?",
      (flask.session['email'], REACHABLE_YES, CHOWN_YES))
    files = dbres.fetchall()

    msg = ''
    file_count = min(len(files), 10)
    more = file_count < len(files)
    for file_id, file_title in files[:file_count]:
      drive_service.permissions().insert(fileId=file_id, body=permission, sendNotificationEmails=False).execute()
      dbcur.execute("UPDATE files SET doChown=? WHERE user=? AND id=?",
        (CHOWN_DONE, flask.session['email'], file_id))
      msg += f'{file_id} ({file_title})\n'

    count += file_count
    flask.session['count'] = str(count)

    if more:
      cont = 'CONTINUING'
    else:
      cont = 'DONE'
    msg = f'Ownership transfered for {file_count} files (total now {count}) ({cont}):\n' + msg
    data = {'more': more}

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

@app.route('/show_pending_ownership')
def show_pending_ownership():
  try:
    raise_if_unauth()

    (dbcon, dbcur) = get_db()
    dbres = dbcur.execute(
      "SELECT * FROM files WHERE user=? AND reachable=? AND pendingOwner=?",
      (flask.session['email'], REACHABLE_YES, PENDING_OWNER_YES))
    files = dbres.fetchall()

    msg = ''
    msg += 'Files:\n'
    for file in files:
      msg += repr(file) + '\n'

    dbcon.commit()
  except Exception as e:
    dbcon.rollback()
    msg = exc_to_text(e)

  return js_response(msg)

@app.route('/accept_pending_ownership')
def accept_pending_ownership():
  try:
    raise_if_unauth()

    init = flask.request.args.get('init', 'true')
    if init == 'true':
      flask.session['count'] = str(0)
    count = int(flask.session['count'])

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    target_owner, do_pending = get_owner_pend()
    if not do_pending:
      msg = 'Not needed for GSuite accounts'
      return js_response(msg)
    permission = {
        'type': 'user',
        'value': target_owner,
        'role': 'owner',
        'transferOwnership': True,
    }

    (dbcon, dbcur) = get_db()

    drive_service = googleapiclient.discovery.build(
      API_SERVICE_NAME, API_VERSION, credentials=credentials)

    dbres = dbcur.execute(
      "SELECT id, title FROM files WHERE user=? AND reachable=? AND pendingOwner=?",
      (flask.session['email'], REACHABLE_YES, PENDING_OWNER_YES))
    files = dbres.fetchall()

    msg = ''
    file_count = min(len(files), 10)
    more = file_count < len(files)
    for file_id, file_title in files[:file_count]:
      drive_service.permissions().insert(fileId=file_id, body=permission).execute()
      dbcur.execute("UPDATE files SET pendingOwner=? WHERE user=? AND id=?",
        (PENDING_OWNER_DONE, flask.session['email'], file_id))
      msg += f'{file_id} ({file_title})\n'

    count += file_count
    flask.session['count'] = str(count)

    if more:
      cont = 'CONTINUING'
    else:
      cont = 'DONE'
    msg = f'Ownership accepted for {file_count} files (total now {count}) ({cont}):\n' + msg
    data = {'more': more}

    dbcon.commit()

    # Save credentials back to session in case access token was refreshed.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    flask.session['credentials'] = credentials_to_dict(credentials)
  except Exception as e:
    dbcon.rollback()
    msg = exc_to_text(e)

  return js_response(msg)

def application(environ, start_response):
  global oauth2callback_uri
  strip_len = len(environ['PATH_INFO']) - 1
  oauth2callback_uri = environ['SCRIPT_URI'][:-strip_len] + 'oauth2callback'
  global script_name
  script_name = environ['SCRIPT_NAME']
  return app(environ, start_response)
