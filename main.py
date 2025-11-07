import os, psycopg2, json, base64
from typing import List
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, constr
from datetime import datetime
from psycopg2 import errors
from dotenv import load_dotenv
from google_auth_oauthlib.flow import Flow, InstalledAppFlow
from starlette.responses import RedirectResponse

app = FastAPI()

load_dotenv()
db_url = psycopg2.connect(os.getenv("DATABASE_URL"))


class Song(BaseModel):
    title: str
    artist: str


class Playlist(BaseModel):
    title: str
    songs: List[Song] = []


class User_Input(BaseModel):
    username: constr(min_length=2)  # type: ignore
    password: constr(min_length=1)  # type: ignore


class User_Output(BaseModel):
    username: constr(min_length=2)  # type: ignore
    playlists: List[Playlist] = []


@app.post("/create_user")
def create_user(user: User_Input):
    add_to_db = db_url.cursor()
    # hased password add a salt into the database
    user_query = "INSERT INTO users (username, password) VALUES (%s, %s)"
    user_values = (user.username, user.password)  # change the user.pass to hashed

    try:
        add_to_db.execute(user_query, user_values)
        db_url.commit()
        return {"message": "User created successfully"}

    except psycopg2.errors.UniqueViolation:
        db_url.rollback()
        raise HTTPException(status_code=400, detail="Username already exists")

    except Exception as e:
        db_url.rollback()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        add_to_db.close()


@app.get("/login")
def login(username: str, password: str):
    get_from_db = db_url.cursor()
    user_query = "SELECT username, password FROM users WHERE username = %s"
    user_value = (username,)

    try:
        get_from_db.execute(user_query, user_value)
        results = get_from_db.fetchone()

        if results is None:
            raise HTTPException(
                status_code=400, detail="Username or Password are incorrect!"
            )
        db_username, db_password = results

        if db_password != password:
            raise HTTPException(
                status_code=400, detail="Username or Password are incorrect!"
            )

        user = User_Output(username=db_username, playlists=[])
        return user

    except Exception as e:
        db_url.rollback()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        get_from_db.close()


@app.get("/google_auth")
def google_login(username: str):
    client_config = {
        "web": {
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET_KEY"),
            "redirect_uris": [os.getenv("GOOGLE_REDIRECT_URL")],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }
    # change below
    state_json = json.dumps({"username": username})
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


@app.get("/google_auth/callback")
def get_tokens(state: str, code: str):
    state_json = base64.urlsafe_b64encode(state_json.encode()).decode()
    state_data = json.loads(state_json)
    username = state_data.get("username")
    if not username:
        raise HTTPException(
            status_code=400, detail="Missing state parameter: Missing Username!"
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

    access_token = cred.token
    refresh_token = cred.refresh_token
    expired = datetime.now().timestamp() + cred.expiry

    add_to_db = db_url.cursor()
    user_query = "INSERT INTO users (youtube_access_token, youtube_refresh_token, youtube_token_expiry) VALUES (%s, %s, %s)"
    user_values = (access_token, refresh_token, expired)

    try:
        add_to_db.execute(user_query, user_values)
        db_url.commit()
        return {"message": "Google Tokens created successfully"}
    except Exception as e:
        db_url.rollback()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        add_to_db.close()
