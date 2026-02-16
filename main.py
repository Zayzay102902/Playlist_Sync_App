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


class User_Input(BaseModel):
    username: constr(min_length=2)  # type: ignore
    password: constr(min_length=1)  # type: ignore




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
    db_url.commit()
    add_to_db.close()
    return RedirectResponse(url=f"/google_auth?user_id={user_id}", status_code=303)

@app.post("/login")
def login(user: User_Input):
    add_to_db = db_url.cursor()

    add_to_db.execute("SELECT id, password FROM users WHERE username = %s", (user.username,)) # col and table name
    user_info = add_to_db.fetchone()

    if not user_info:
        add_to_db.close()
        raise HTTPException(status_code=401, detail="Wrong username or password.")
    
    user_id, h_pass = user_info

    if not bcrypt.checkpw(user.password.encode('utf-8'), h_pass.encode('utf-8') if isinstance(h_pass, str) else h_pass):
        add_to_db.close()
        raise HTTPException(status_code=401, detail="Wrong username or password.")
    

   


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
def get_google_tokens(state: str, code: str):
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
