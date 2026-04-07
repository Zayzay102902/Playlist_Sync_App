import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.chdir(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from main import app
import psycopg2
import json
from dotenv import load_dotenv

load_dotenv()
test_db = psycopg2.connect(os.getenv("DATABASE_URL"))
client = TestClient(app)


def setup_playlist(user_id, playlist_name, platform="both"):
    cursor = test_db.cursor()
    try:
        cursor.execute(
            "INSERT INTO playlists (user_id, playlist_name, platform, songs) VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
            (user_id, playlist_name, platform, "[]"),
        )
        test_db.commit()
    except Exception:
        test_db.rollback()
    finally:
        cursor.close()


def cleanup_playlist(user_id, playlist_name):
    cursor = test_db.cursor()
    cursor.execute(
        "DELETE FROM playlists WHERE user_id = %s AND playlist_name = %s",
        (user_id, playlist_name),
    )
    test_db.commit()
    cursor.close()


def test_create_user_duplicate():
    response = client.post(
        "/create_user", json={"username": "testuser", "password": "testpass"}
    )
    assert response.status_code == 400
    assert (
        response.json()["detail"] == "Username already taken, please try another one."
    )


def test_login_wrong_username():
    response = client.post(
        "/login", json={"username": "nobody", "password": "testpass"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Wrong username or password."


def test_login_wrong_password():
    response = client.post(
        "/login", json={"username": "testuser", "password": "wrongpass"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Wrong username or password."


def test_google_auth_redirect():
    response = client.get("/google_auth?user_id=1", follow_redirects=False)
    assert response.status_code == 307
    assert "accounts.google.com" in response.headers["location"]


def test_spotify_auth_redirect():
    response = client.get("/spotify_auth?user_id=1", follow_redirects=False)
    assert response.status_code == 307
    assert "accounts.spotify.com" in response.headers["location"]


def test_create_playlist_already_exists():
    setup_playlist(11, "My Playlist")
    with patch("main.get_valid_youtube_token", return_value="fake_yt_token"), patch(
        "main.get_valid_spotify_token", return_value="fake_sp_token"
    ):
        response = client.post(
            "/create_playlist",
            json={"name": "My Playlist", "user_id": 11, "platform": "both"},
        )
        assert response.status_code == 400
        assert (
            response.json()["detail"]
            == "Playlist already exists. Please use 'Copy Playlist' instead."
        )
    cleanup_playlist(11, "My Playlist")


def test_create_playlist_no_token():
    response = client.post(
        "/create_playlist",
        json={"name": "New Playlist", "user_id": 999, "platform": "both"},
    )
    assert response.status_code == 401
    assert (
        response.json()["detail"]
        == "No YouTube refresh token found. Please re-authenticate."
    )


def test_copy_playlist_not_found():
    with patch("main.get_valid_youtube_token", return_value="fake_yt_token"), patch(
        "main.get_valid_spotify_token", return_value="fake_sp_token"
    ):
        response = client.post(
            "/copy_playlist",
            json={
                "name": "Nonexistent Playlist",
                "platform": "youtube",
                "user_id": 11,
                "sync": False,
            },
        )
        assert response.status_code == 404
        assert (
            response.json()["detail"]
            == "Playlist not found. Please add it first using /add_playlist."
        )


def test_copy_playlist_already_on_both():
    setup_playlist(11, "My Playlist", "both")
    with patch("main.get_valid_youtube_token", return_value="fake_yt_token"), patch(
        "main.get_valid_spotify_token", return_value="fake_sp_token"
    ):
        response = client.post(
            "/copy_playlist",
            json={
                "name": "My Playlist",
                "platform": "youtube",
                "user_id": 11,
                "sync": False,
            },
        )
        assert response.status_code == 400
        assert (
            response.json()["detail"]
            == "Sorry, this playlist already exists on both platforms."
        )
    cleanup_playlist(11, "My Playlist")


def test_sync_playlist_not_found():
    with patch("main.get_valid_youtube_token", return_value="fake_yt_token"), patch(
        "main.get_valid_spotify_token", return_value="fake_sp_token"
    ):
        response = client.post(
            "/sync_playlist",
            json={
                "name": "Nonexistent Playlist",
                "user_id": 11,
                "override_platform": "youtube",
            },
        )
        assert response.status_code == 404
        assert (
            response.json()["detail"]
            == "This playlist is not synced. Please try again."
        )


def test_add_playlist_already_exists():
    setup_playlist(11, "My Playlist", "spotify")
    with patch("main.get_valid_youtube_token", return_value="fake_yt_token"), patch(
        "main.get_valid_spotify_token", return_value="fake_sp_token"
    ):
        response = client.post(
            "/add_playlist",
            json={"name": "My Playlist", "platform": "spotify", "user_id": 11},
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "Playlist already exists in your account."
    cleanup_playlist(11, "My Playlist")


def test_add_playlist_no_token():
    response = client.post(
        "/add_playlist",
        json={"name": "Some Playlist", "platform": "spotify", "user_id": 999},
    )
    assert response.status_code == 401
    assert (
        response.json()["detail"]
        == "No YouTube refresh token found. Please re-authenticate."
    )


def test_delete_account_not_found():
    response = client.delete("/delete_account?user_id=999")
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found."
