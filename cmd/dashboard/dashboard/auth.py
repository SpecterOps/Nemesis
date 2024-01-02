import os

import bcrypt
import streamlit as st
import streamlit_authenticator as stauth
from streamlit_cookies_manager import CookieManager

DASHBOARD_USER = os.environ.get("DASHBOARD_USER")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD")

# cache the data so we don't have to bcrypt every time
@st.cache_data
def get_credentials() -> dict:
    """Returns the credential dictionary needed by stauth.Authenticate()"""
    hashed_password = bcrypt.hashpw(DASHBOARD_PASSWORD.encode(), bcrypt.gensalt()).decode()
    credentials = {
        "usernames": {DASHBOARD_USER: {"email": f"{DASHBOARD_USER}@nemesis.local", "name": DASHBOARD_USER, "password": hashed_password}}
    }
    return credentials


def authenticate(function):
    """
    Reads in the necessary authentication information and checks the state
    versus the current user's cookies. Used at the top of every page.
    """

    if "ENVIRONMENT" in os.environ and os.environ["ENVIRONMENT"].lower() == "development":
        st.divider()
        st.markdown("### ***Development Environment***")
    st.divider()
    function("nemesis")

    # disabling explicit auth for now

    # authenticator = stauth.Authenticate(get_credentials(), "nemesis", "nemesis", 30)

    # name, authentication_status, username = authenticator.login("Login", "main")

    # if authentication_status:
    #     function(username)
    # elif authentication_status is False:
    #     st.error("Username/password is incorrect")
    #     return None
    # elif authentication_status is None:
    #     st.warning("Please enter your username and password")
    #     return None
