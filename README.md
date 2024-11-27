# Py-AD-Principal

A Python package for authenticating users (more formally called *principals*) via a Microsoft Active Directory (AD) domain controller. This module supports **Linux-based** services and service  principals, and is tested against an AD controller configured as described in the official Samba 4 [documentation](https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller).

Prerequisites
=============

This module depends on the [Python GSSAPI](https://pypi.org/project/gssapi/) module for integration with the AD Key Distribution Center (KDC). It expects a pre-configured and operational Kerberos 5 environment tested against the intended AD domain. Please see the linked Samba documentation for detailed instructions.

Assuming you've met this requirement and Python GSSAPI is not already installed, `pip` will automatically install it as a dependency. When this occurs, it attempts to build a native wheel that links against the system's `gssapi`. *For this to succeed, `libkrb5`'s development package must be installed*. On Ubuntu 24.04 LTS, this may be done via apt as follows:

```bash
$ sudo apt install libkrb5-dev
```
On Fedora 40+, the equivalent command is:
```bash
$ sudo dnf install krb5-devel
```

If you've gotten this far, you are now be ready to install the package.

Installation
============

The easiest way to install package is via pip.

```bash
$ pip install py-ad-principal
```

Alternatively, you may clone the git repo and install from there. This method is only recommended for those interested in modifying the source or submitting pull requests.

```bash
$ git clone https://github.com/miscellanea-io/py-ad-principal.git
$ pip install .
```

Configuration
=============

This module is configured via a [TOML](https://toml.io/en/) file named `py_ad_principal.toml`. Place it in the directory 
from which the script is launched. You may specify an alternative name or location by providing an absolute path to it when initializing an instance of the `ActiveDirectoryConf` class.

An example file is provided below.
```toml
[krb5]
service = "HTTP"
hostname = "{Your AD domain controller's host name}"
keytab = "{absolute path to a keytab file containing your SPN's credentials}"

[ldap]
server = "{your AD domain controller's host name}"
use_tls = true
search_base = "{CN=Users,DC=Your,DC=Active Directory,DC=Domain}"
nested_groups = false
anonymous_bind = false
bind_user = "{Bind user account in sAMAccountName format (e.g., DOMAIN\\Account)}"
bind_password = "{Bind account password}"
```
You may also provide (or override) configuration values via environment variables. They must be named according to the following specification: `AD_{$TOML TABLE}_{$TOML KEY}`. For example, to disable TLS for LDAP (and switch from port TCP/636 to TCP/389) execute the following command prior to running your script:
```bash
$ export AD_LDAP_USE_TLS=False
```
Note that all names are converted to upper case when passed as environment variables!

Quick Start
===========
This module was developed to scratch an itch: a need to support browser-based SSO to a Flask application, hosted on Linux, within an Active Directory domain (managed by Samba 4 and hosted on a Raspberry Pi 4; yes, this is how I run my home lab; no, I am not interested in your judgment). The service was **not** strictly joined to the domain, but did have a `krb5.conf` file making it aware of the domain controller. While this experience (described in [RFC4559](https://www.rfc-editor.org/rfc/rfc4559), a Microsoft extension to [RFC4178](https://www.rfc-editor.org/rfc/rfc4178)) feels magical from a Windows client to Windows server within the domain, it is markedly less so should one be foolish enough to take a single step outside.

Let us assume, for the sake of argument, that you have a similar problem. Let us also assume that your project is structured the following way:

```
$APP_ROOT
├── app
│   ├── __init__.py
│   ├── static
│   ├── templates
│   ├── views.py
│   └── wsgi.py
├── app.keytab
├── config.py
├── LICENSE
├── py_ad_principal.toml
├── README.md
└── requirements.txt
```

Because you are using the [application factory pattern](https://flask.palletsprojects.com/en/stable/patterns/appfactories/), your Flask app is initialized in `$APP_ROOT/app/__init__.py`. We will also be paying special attention to x other files:
* `requirements.txt` where, in addition to Flask and this module, you've taken a dependency on `Flask-Login`
* `views.py`, where you write code to respond to HTTP actions (here, we care about those involved in logn)
* `app.keytab`, where you store pre-generated credentials for your Kerberos *service principal*. Microsoft provides instructions for creating keytab files on Windows server; the more adventurous will find Samba directions [here](https://wiki.samba.org/index.php/Generating_Keytabs).
* `py_ad_principal.toml`, where we store the module's configuration values.

For this example, `py_ad_principal.toml` has the following contents:
```toml
[krb5]
service = "HTTP"
hostname = "dc.domain.local"
keytab = "app.keytab"

[ldap]
server = "dc.domain.local"
use_tls = true
search_base = "CN=Users,DC=domain,DC=local"
nested_groups = false
anonymous_bind = false
bind_user = "DOMAIN\\HTTP"
bind_password = "MySecretPassword"
```

For simplicity's sake, we're going to create a global variable named `ad_auth_context` to hold a shared authentication context. We do this in `__init__.py` when we create out Flask app.

```python
# Declare any system imports
from py_ad_principal import AuthenticationContext, AuthenticationContextConfig
from flask_login import LoginManager
# Other 3rd party imports go here

# Flask app factory function; assume you've created a class named 'Config' to
# manage configuration values.
def create_app(config_class=Config):
    app = Flask(__name__)

    # Configure blueprints and extensions, and perform other setup tasks.

    # Read Python AD Principal configuration from the standard location and define
    # a global variable to store the shared authentication context.
    py_ad_config = AuthenticationContextConfig()
    global ad_auth_ctx = AuthenticationContext( py_ad_config )

    # Create a global LoginManager instance for use in our view methods
    global login_manager
    login_manager = LoginManager()
    login_manager.session_protection = "strong"
    login_manager.login_view = "login"
    login_manager.login_message_category = "info"    

    return app
```

In `views.py`, we use `ad_auth_ctx` to integrate our principal with a Flask-Login authentication handler. First, we define the mandatory `User` class to wrap the attributes provided by our AD principal.

```python
from flask import Response, redirect
from flask_login import UserMixin, login_required, login_user, logout_user
from py_ad_principal import ActiveDirectoryPrincipal, AuthenticationContext

from app import ad_auth_ctx, login_manager


# Define Flask-Login compatible user class to hold the principal's key attributes.
class User(UserMixin):
    def __init__(self, principal: ActiveDirectoryPrincipal):
        self._id = principal.principal_name
        self._username = principal.sam_account_name
        self._display_name = principal.display_name

    def __repr__(self):
        return f"<User {self._id}>"

    def __str__(self):
        return self._id

    def get_id(self):
        return self._id

    @property
    def username(self):
        return self._username

    @property
    def display_name(self):
        return self._display_name
    
    def to_dict(self):
        return {
            "id": self._id,
            "username": self._username,
            "display_name": self._display_name,
        }

    @staticmethod
    def from_dict(user_dict):
        return User(
            user_dict["id"], 
            user_dict["username"], 
            user_dict["display_name"],
        )
```

Next, we add the mandatory user management functions to `views.py`.

```python
@login_manager.user_loader
def user_loader(user_id):
    user_principal = session.get("user_principal")
    if user_principal:
        return User.from_dict(user_principal)

    return None


@login_manager.request_loader
def request_loader(request):
    # We do not support restoring the user's identity from a token passed in
    # the header of each request.
    return None
```

Finally, we implement a protected method and the requisite, SPNEGO-compatible login function.

```python
@app.route("/")
@login_required
def home():
    # Assume we have a Jinja2 template named "home.html"
    return render_template("home.html")

@app.route("/login", methods=["GET"])
def login():
    auth_header = request.headers.get("Authorization")

    # Yes, I'm asking for permission rather than forgiveness.
    if auth_header and ad_auth_ctx.is_valid_token(auth_header):
        # Strip out the 'Negotiate ' preamble present in HTTP-based SPNEGO
        # implementations.
        auth_token = auth_header[len("Negotiate ") :]

        # We are not resolving groups or mapping roles in this example.
        result = auth_context.authenticate_principal(auth_token)
        if result and result.principal:
            user = User(result.principal)
            login_user(user)
            session["user_principal"] = user.to_dict()
            return redirect(url_for("home"))
        elif result.server_token:
            # This shouldn't happen when authenticating with a KRB5 TGT. It's
            # shown in the interest of completion only!
            http_headers = {"WWW-Authenticate": f"Negotiate {result.server_token}"}
            return Response("Unauthorized", 401, http_headers)

    return Response("Unauthorized", 401, {"WWW-Authenticate": "Negotiate"})

@app.route("/logout", methods=["GET"])
def logout():
    logout_user()
    return redirect(url_for("home"))
```

Now, whenever the user attempts to access our (utterly useless) website, they are routed to the `login()` method which commences GSSAPI protocol negotiation by responding with HTTP 401 (unauthorized) and the `WWW-Authenticate` response header having the value `Negotiate`.

