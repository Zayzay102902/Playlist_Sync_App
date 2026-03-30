import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_create_user_duplicate():
    response = client.post("/create_user", json={"username": "testuser", "password": "testpass"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Username already taken, please try another one."

def test_google_auth_redirect():
    response = client.get("/google_auth?user_id=1", follow_redirects=False)
    assert response.status_code == 307
    assert "accounts.google.com" in response.headers["location"]

def test_spotify_auth_redirect():
    response = client.get("/spotify_auth?user_id=1", follow_redirects=False)
    assert response.status_code == 307
    assert "accounts.spotify.com" in response.headers["location"]