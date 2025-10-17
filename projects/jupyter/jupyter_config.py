"""Jupyter configuration for Nemesis environment"""

import os

from jupyter_server.auth import passwd

# Server configuration
c.ServerApp.ip = "0.0.0.0"
c.ServerApp.port = 8888
c.ServerApp.open_browser = False
c.ServerApp.base_url = "/jupyter"
c.ServerApp.allow_origin = "*"
c.ServerApp.disable_check_xsrf = True
c.ServerApp.token = ""

# Set password from environment variable or generate random one
jupyter_password = os.getenv("JUPYTER_PASSWORD")
if jupyter_password:
    c.PasswordIdentityProvider.hashed_password = passwd(jupyter_password)
else:
    # Use a persistent random password stored in a temp file
    import secrets
    import string
    import tempfile

    password_file = os.path.join(tempfile.gettempdir(), 'jupyter_random_password')

    if os.path.exists(password_file):
        # Read existing password
        with open(password_file) as f:
            random_password = f.read().strip()
    else:
        # Generate new random password and save it
        alphabet = string.ascii_letters + string.digits
        random_password = ''.join(secrets.choice(alphabet) for _ in range(12))

        with open(password_file, 'w') as f:
            f.write(random_password)

        print("###########################################")
        print(f"# JUPYTER_PASSWORD: {random_password}")
        print("###########################################", flush=True)

    c.PasswordIdentityProvider.hashed_password = passwd(random_password)

# Content management
c.ContentsManager.allow_hidden = True

# Terminal configuration
c.ServerApp.terminals_enabled = True

# Notebook configuration
c.NotebookApp.allow_remote_access = True
