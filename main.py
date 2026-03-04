import os, psycopg2, json, base64
import bcrypt
from enum import Enum
from typing import List
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, constr
from datetime import datetime
from psycopg2 import errors
from dotenv import load_dotenv
from google_auth_oauthlib.flow import Flow

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
    playlist_name: constr(min_length=1)  # type: ignore
    user_id: int
    platform: Platform




@app.post("/create_user")
def create_user(user: User_Input):
    add_to_db = db_url.cursor()
    add_to_db.execute("SELECT username FROM users WHERE username = %s", (user.username,)) # col and table name
    check_user = add_to_db.fetchone()

    if check_user: 
        add_to_db.close()
        raise HTTPException(status_code=400, detail="Username already taken, please try another one.")

    password_bytes = user.password.encode('utf-8')
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

    user_query = "INSERT INTO users (username, password) VALUES (%s, %s)"
    user_values = (user.username, hashed_password)  
    add_to_db.execute(user_query, user_values)

    user_r = add_to_db.execute("SELECT id FROM users WHERE username = %s", (user.username,))
    user_r = add_to_db.fetchone()
    user_id = user_r[0]
    add_to_db.execute("INSERT INTO playlists (user_id) VALUES (%s)", user_id)
    db_url.commit()
    add_to_db.close()
    return RedirectResponse(url=f"/google_auth?user_id={user_id}", status_code=303)

@app.post("/login")
def login(user: User_Input):
    cursor = db_url.cursor()

    cursor.execute(
        "SELECT id, password, youtube_token_expiry, spotify_token_expiry FROM users WHERE username = %s",
        (user.username,)
    )
    user_info = cursor.fetchone()
    cursor.close()

    if not user_info:
        raise HTTPException(status_code=401, detail="Wrong username or password.")

    user_id, h_pass, yt_expiry, sp_expiry = user_info

    if not bcrypt.checkpw(user.password.encode("utf-8"), h_pass.encode("utf-8") if isinstance(h_pass, str) else h_pass):
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
        (data.playlist_name, data.user_id)
    )
    if cursor.fetchone():
        cursor.close()
        raise HTTPException(status_code=400, detail="Playlist already exists. Please use 'Copy Playlist' instead.")
    
    


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
            (refresh_token, access_token_you, exp_time, user_id)
        )

        cursor.execute("SELECT spotify_refresh_token FROM users WHERE id = %s", (user_id,))
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

    
