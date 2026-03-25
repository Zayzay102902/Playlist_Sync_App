import os, psycopg2, json, base64
import bcrypt
from enum import Enum
from typing import List
from fastapi import FastAPI, HTTPException, Request, requests
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, constr
from datetime import datetime, timedelta
from psycopg2 import errors
from dotenv import load_dotenv
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
import requests as http_requests

app = FastAPI()

load_dotenv()
db_url = psycopg2.connect(os.getenv("DATABASE_URL"))


class Platform(str, Enum):
    SPOTIFY = "spotify"
    YOUTUBE = "youtube"
    BOTH = "both"


class User_Input(BaseModel):
    username: constr(min_length=2)  # type: ignore
    password: constr(min_length=1)  # type: ignore


class Playlist_Input(BaseModel):
    name: constr(min_length=1)  # type: ignore
    user_id: int
    platform: Platform


class Copy_Playlist_Input(BaseModel):
    playlist_name: constr(min_length=1)  # type: ignore
    platform: Platform
    user_id: int
    sync: bool = False


class Sync_Playlist_Input(BaseModel):
    playlist_name: constr(min_length=1)  # type: ignore
    user_id: int
    override_platform: Platform


def get_valid_youtube_token(user_id: int):
    open_to_db = db_url.cursor()
    open_to_db.execute(
        "SELECT youtube_access_token, youtube_refresh_token, youtube_token_expiry FROM users WHERE id = %s",
        (user_id,),
    )
    token_info = open_to_db.fetchone()

    if not token_info or not token_info[1]:
        open_to_db.close()
        raise HTTPException(
            status_code=401,
            detail="No YouTube refresh token found. Please re-authenticate.",
        )

    access_token, refresh_token, expiry = token_info
    now = datetime.now()

    if not access_token or not expiry or expiry < now + timedelta(minutes=5):
        try:
            cred = Credentials(
                token=access_token,
                refresh_token=refresh_token,
                token_uri="https://oauth2.googleapis.com/token",
                client_id=os.getenv("GOOGLE_CLIENT_ID"),
                client_secret=os.getenv("GOOGLE_CLIENT_SECRET_KEY"),
            )
            cred.refresh(GoogleRequest())
            access_token = cred.token
            expiry = cred.expiry

            open_to_db.execute(
                "UPDATE users SET youtube_access_token = %s, youtube_token_expiry = %s WHERE id = %s",
                (access_token, expiry, user_id),
            )
            db_url.commit()
        except Exception:
            open_to_db.close()
            raise HTTPException(
                status_code=401,
                detail="YouTube token refresh failed. Please re-authenticate.",
            )

    open_to_db.close()
    return access_token


def get_valid_spotify_token(user_id: int) -> str:
    open_to_db = db_url.cursor()
    open_to_db.execute(
        "SELECT spotify_access_token, spotify_refresh_token, spotify_token_expiry FROM users WHERE id = %s",
        (user_id,),
    )
    token_info = open_to_db.fetchone()

    if not token_info or not token_info[1]:
        open_to_db.close()
        raise HTTPException(
            status_code=401,
            detail="No Spotify refresh token found. Please re-authenticate.",
        )

    access_token, refresh_token, expiry = token_info
    now = datetime.now()

    if not access_token or not expiry or expiry < now + timedelta(minutes=5):
        try:
            response = http_requests.post(
                "https://accounts.spotify.com/api/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": os.getenv("SPOTIFY_CLIENT_ID"),
                    "client_secret": os.getenv("SPOTIFY_CLIENT_SECRET"),
                },
            )
            token_data = response.json()
            access_token = token_data["access_token"]
            expiry = datetime.now() + timedelta(seconds=token_data["expires_in"])
            new_refresh_token = token_data.get("refresh_token", refresh_token)

            open_to_db.execute(
                "UPDATE users SET spotify_access_token = %s, spotify_refresh_token = %s, spotify_token_expiry = %s WHERE id = %s",
                (access_token, new_refresh_token, expiry, user_id),
            )
            db_url.commit()
        except Exception:
            open_to_db.close()
            raise HTTPException(
                status_code=401,
                detail="Spotify token refresh failed. Please re-authenticate.",
            )

    open_to_db.close()
    return access_token


@app.post("/create_user")
def create_user(user: User_Input):
    open_to_db = db_url.cursor()
    open_to_db.execute(
        "SELECT username FROM users WHERE username = %s", (user.username,)
    )
    check_user = open_to_db.fetchone()

    if check_user:
        open_to_db.close()
        raise HTTPException(
            status_code=400, detail="Username already taken, please try another one."
        )

    password_bytes = user.password.encode("utf-8")
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

    user_query = "INSERT INTO users (username, password) VALUES (%s, %s)"
    user_values = (user.username, hashed_password)
    open_to_db.execute(user_query, user_values)

    user_r = open_to_db.execute(
        "SELECT id FROM users WHERE username = %s", (user.username,)
    )
    user_r = open_to_db.fetchone()
    user_id = user_r[0]
    open_to_db.execute("INSERT INTO playlists (user_id) VALUES (%s)", user_id)
    db_url.commit()
    open_to_db.close()
    return RedirectResponse(url=f"/google_auth?user_id={user_id}", status_code=303)


@app.post("/login")
def login(user: User_Input):
    cursor = db_url.cursor()

    cursor.execute(
        "SELECT id, password, youtube_token_expiry, spotify_token_expiry FROM users WHERE username = %s",
        (user.username,),
    )
    user_info = cursor.fetchone()
    cursor.close()

    if not user_info:
        raise HTTPException(status_code=401, detail="Wrong username or password.")

    user_id, h_pass, yt_expiry, sp_expiry = user_info

    if not bcrypt.checkpw(
        user.password.encode("utf-8"),
        h_pass.encode("utf-8") if isinstance(h_pass, str) else h_pass,
    ):
        raise HTTPException(status_code=401, detail="Wrong username or password.")

    now = datetime.now()

    if not yt_expiry or yt_expiry < now:
        return RedirectResponse(url=f"/google_auth?user_id={user_id}", status_code=303)

    if not sp_expiry or sp_expiry < now:
        return RedirectResponse(url=f"/spotify_auth?user_id={user_id}", status_code=303)

    return {"message": "Login successful.", "user_id": user_id}


@app.get("/google_auth")
def google_login(user_id: int):
    client_config = {
        "web": {
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET_KEY"),
            "redirect_uris": [os.getenv("GOOGLE_REDIRECT_URL")],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }

    state_json = json.dumps({"user_id": user_id})
    state = base64.urlsafe_b64encode(state_json.encode()).decode()
    flow = Flow.from_client_config(
        client_config,
        scopes=["https://www.googleapis.com/auth/youtube.force-ssl"],
        redirect_uri=os.getenv("GOOGLE_REDIRECT_URI"),
    )
    auth_url, _ = flow.authorization_url(
        state=state, access_type="offline", prompt="consent"
    )

    return RedirectResponse(auth_url)


@app.post("/create_playlist")
def create_playlist(data: Playlist_Input):
    cursor = db_url.cursor()

    cursor.execute(
        "SELECT id FROM playlists WHERE playlist_name = %s AND user_id = %s",
        (data.playlist_name, data.user_id),
    )
    if cursor.fetchone():
        cursor.close()
        raise HTTPException(
            status_code=400,
            detail="Playlist already exists. Please use 'Copy Playlist' instead.",
        )
    yt_access_token = get_valid_youtube_token(data.user_id)
    sp_access_token = get_valid_spotify_token(data.user_id)

    url = "https://www.googleapis.com/youtube/v3/playlists?part=snippet&status&id"

    headers = {"Authorization": yt_access_token, "Content-Type": "application/json"}

    body = {"snippet": {"title": data.name}, "status": {"privacyStatus": "private"}}

    response = requests.post(
        "https://www.googleapis.com/youtube/v3/playlists?part=snippet&status&id",
        headers={"Authorization": yt_access_token, "Content-Type": "application/json"},
        json={"snippet": {"title": data.name}, "status": {"privacyStatus": "private"}},
    )
    y_j_data = response.json()

    yt_playlist_id = y_j_data["id"]
    response = http_requests.post(
        "https://api.spotify.com/v1/me/playlists",
        headers={
            "Authorization": f"Bearer {sp_access_token}",
            "Content-Type": "application/json",
        },
        json={"name": data.name, "public": False, "collaborative": True},
    )
    sp_data = response.json()

    yt_playlist_id = y_j_data["id"]
    sp_playlist_id = sp_data["id"]

    try:
        cursor.execute(
            """UPDATE playlists 
               SET playlist_name = %s, platform = %s, songs = %s, youtube_playlist_id = %s, spotify_playlist_id = %s
               WHERE user_id = %s AND playlist_name IS NULL""",
            (
                data.playlist_name,
                Platform.BOTH,
                json.dumps([]),
                yt_playlist_id,
                sp_playlist_id,
                data.user_id,
            ),
        )
        db_url.commit()
    except Exception as e:
        db_url.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()

    return {
        "message": f"Playlists created and synced successfully for user {data.user_id}."
    }


@app.post("/copy_playlist")
def copy_playlist(data: Copy_Playlist_Input):
    open_to_db = db_url.cursor()

    open_to_db.execute(
        "SELECT id, platform, songs, youtube_playlist_id, spotify_playlist_id FROM playlists WHERE playlist_name = %s AND user_id = %s",
        (data.playlist_name, data.user_id),
    )
    playlist_info = open_to_db.fetchone()

    if not playlist_info:
        open_to_db.close()
        raise HTTPException(
            status_code=404,
            detail="Playlist does not exist on this platform. Try again.",
        )

    pl_id, current_platform, songs, yt_id, sp_id = playlist_info

    if current_platform == Platform.BOTH:
        open_to_db.close()
        raise HTTPException(
            status_code=400,
            detail="Sorry, this playlist already exists on both platforms.",
        )

    if data.platform != current_platform:
        open_to_db.close()
        raise HTTPException(
            status_code=400,
            detail=f"Playlist does not exist on {data.platform}. Try again.",
        )

    target_platform = (
        Platform.SPOTIFY if data.platform == Platform.YOUTUBE else Platform.YOUTUBE
    )

    yt_access_token = get_valid_youtube_token(data.user_id)
    sp_access_token = get_valid_spotify_token(data.user_id)

    if target_platform == Platform.SPOTIFY:
        dsd
    else:
        sdsd


@app.get("/google_auth/callback")
def get_google_tokens(state: str, code: str):
    state_json = base64.urlsafe_b64encode(state_json.encode()).decode()
    state_data = json.loads(state_json)
    user_id = state_data.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=400, detail="Missing state parameter: Missing User ID!"
        )
    client_config = {
        "web": {
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET_KEY"),
            "redirect_uris": [os.getenv("GOOGLE_REDIRECT_URL")],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }
    flow = Flow.from_client_config(
        client_config,
        scopes=["https://www.googleapis.com/auth/youtube.force-ssl"],
        redirect_uri=os.getenv("GOOGLE_REDIRECT_URI"),
    )

    flow.fetch_token(code=code)
    cred = flow.credentials

    access_token_you = cred.token
    refresh_token = cred.refresh_token
    exp_time = cred.expiry

    cursor = db_url.cursor()
    try:
        cursor.execute(
            "UPDATE users SET youtube_refresh_token = %s, youtube_access_token = %s, youtube_token_expiry = %s WHERE id = %s,",
            (refresh_token, access_token_you, exp_time, user_id),
        )

        cursor.execute(
            "SELECT spotify_refresh_token FROM users WHERE id = %s", (user_id,)
        )
        sp_token = cursor.fetchone()
        db_url.commit()
    except Exception as e:
        db_url.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()

    if not sp_token or not sp_token[0]:
        return RedirectResponse(url=f"/spotify_auth?user_id={user_id}", status_code=303)

    return {"message": "Google re-authentication successful.", "user_id": user_id}


@app.get("/spotify_auth")
def spotify_login(user_id: int):
    state_json = json.dumps({"user_id": user_id})
    state = base64.urlsafe_b64encode(state_json.encode()).decode()
    what_I_want = "playlist-read-private playlist-modify-private playlist-modify-public playlist-read-collaborative"
    auth_url = "https://accounts.spotify.com/authorize?" + "&".join(
        [
            f"client_id={os.getenv('SPOTIFY_CLIENT_ID')}",
            f"response_type=code",
            f"redirect_uri={os.getenv('SPOTIFY_REDIRECT_URI')}",
            f"state={state}",
            f"scope={what_I_want}",
        ]
    )

    return RedirectResponse(auth_url)


@app.get("/api/spotify/callback")
def get_spotify_token(state: str, code: str):
    state_json = base64.urlsafe_b64decode(state.encode()).decode()
    state_data = json.loads(state_json)
    user_id = state_data.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=400, detail="Missing state parameter: Missing User ID!"
        )
    credentials = base64.b64encode(
        f"{os.getenv('SPOTIFY_CLIENT_ID')}:{os.getenv('SPOTIFY_CLIENT_SECRET')}".encode()
    ).decode()

    response = http_requests.post(
        "https://accounts.spotify.com/api/token",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {credentials}",
        },
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": os.getenv("SPOTIFY_REDIRECT_URI"),
        },
    )
    token_data = response.json()

    access_token = token_data["access_token"]
    expires_in = datetime.now() + timedelta(seconds=token_data["expires_in"])
    refresh_token = token_data["refresh_token"]
    cursor = db_url.cursor()
    try:
        cursor.execute(
            "UPDATE users SET spotify_access_token = %s, spotify_refresh_token = %s, spotify_token_expiry = %s WHERE id = %s",
            (access_token, refresh_token, expires_in, user_id),
        )

        db_url.commit()
    except Exception as e:
        db_url.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()

    return {"message": "Spotify re-authentication successful.", "user_id": user_id}
