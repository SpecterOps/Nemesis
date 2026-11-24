"""The chatbot's read-only connection string must survive any characters in its password."""

import pytest
from agents.tasks.chatbot import ChatbotAgent
from psycopg.conninfo import conninfo_to_dict


def _conn(monkeypatch, password):
    monkeypatch.setenv("CHATBOT_DB_PASSWORD", password)
    monkeypatch.setenv("POSTGRES_HOST", "pgbouncer")
    # The method reads only env vars, so skip __init__ (it sets up the LLM client)
    agent = ChatbotAgent.__new__(ChatbotAgent)
    return conninfo_to_dict(agent._get_chatbot_connection_string())


@pytest.mark.parametrize("password", ["chatbot_pass_change_me", "p@ss:w/rd", "with space", "h#sh?x=1", "per%cent"])
def test_password_round_trips(monkeypatch, password):
    parsed = _conn(monkeypatch, password)
    assert parsed["password"] == password
    assert parsed["user"] == "chatbot_readonly"
    assert parsed["host"] == "pgbouncer"


def test_default_password(monkeypatch):
    monkeypatch.delenv("CHATBOT_DB_PASSWORD", raising=False)
    agent = ChatbotAgent.__new__(ChatbotAgent)
    assert conninfo_to_dict(agent._get_chatbot_connection_string())["password"] == "chatbot_pass_change_me"
