# Installation instructions

```shell
mkdir -p /var/www/fcch-gdrive-chown/
cd  /var/www/fcch-gdrive-chown/
virtualenv -p python3 venv
. ./venv/bin/activate
pip install --upgrade google-api-python-client
pip install --upgrade google-auth google-auth-oauthlib google-auth-httplib2
pip install --upgrade flask
pip install --upgrade requests
```

Edit `/etc/apache2/sites-enabled/avon.wwwdotorg.org-ssl.conf` to add:

```
<VirtualHost *:443>
    ...
    WSGIDaemonProcess fcch python-home=/var/www/fcch-gdrive-chown/venv
    WSGIProcessGroup fcch
    WSGIScriptAlias /fcch-gdrive-chown /var/www/fcch-gdrive-chown/app.wsgi
</VirtualHost>
```

Change the ownership of `/var/www/fcch-gdrive-chown/` so the web server process
uid can read it.

Change the group ownership of `/var/www/fcch-gdrive-chown/var` so that the web
server process can write it. The best approach is to create a new group that
the web server is a member of, plus anyone who needs debug access to the
database file.

Now, access: https://avon.wwwdotorg.org/fcch-gdrive-chown/.
