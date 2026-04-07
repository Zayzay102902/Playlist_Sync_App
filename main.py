import os, psycopg2, json, base64, re
import bcrypt
import requests
from enum import Enum
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, constr
from datetime import datetime, timedelta
from dotenv import load_dotenv
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest

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
    name: constr(min_length=1)  # type: ignore
    platform: Platform
    user_id: int
    sync: bool = False


class Sync_Playlist_Input(BaseModel):
    name: constr(min_length=1)  # type: ignore
    user_id: int
    override_platform: Platform


class Delete_Playlist_Input(BaseModel):
    name: constr(min_length=1)  # type: ignore
    platform: Platform
    user_id: int


class Add_Playlist_Input(BaseModel):
    name: constr(min_length=1)  # type: ignore
    platform: Platform
    user_id: int


def check_youtube_playlist_exists(name: str, yt_access_token: str):
    response = requests.get(
        "https://www.googleapis.com/youtube/v3/playlists?part=snippet&mine=true",
        headers={"Authorization": f"Bearer {yt_access_token}"},
    )
    names = [p["snippet"]["title"] for p in response.json().get("items", [])]
    return name in names


def check_spotify_playlist_exists(name: str, sp_access_token: str):
    response = requests.get(
        "https://api.spotify.com/v1/me/playlists",
        headers={"Authorization": f"Bearer {sp_access_token}"},
    )
    names = [p["name"] for p in response.json().get("items", [])]
    return name in names


def get_youtube_playlist_id(name: str, yt_access_token: str):
    response = requests.get(
        "https://www.googleapis.com/youtube/v3/playlists?part=snippet&mine=true",
        headers={"Authorization": f"Bearer {yt_access_token}"},
    )
    for p in response.json().get("items", []):
        if p["snippet"]["title"] == name:
            return p["id"]
    return None


def get_spotify_playlist_id(name: str, sp_access_token: str):
    response = requests.get(
        "https://api.spotify.com/v1/me/playlists",
        headers={"Authorization": f"Bearer {sp_access_token}"},
    )
    for p in response.json().get("items", []):
        if p["name"] == name:
            return p["id"]
    return None


def get_youtube_songs(yt_id: str, yt_access_token: str):
    response = requests.get(
        f"https://www.googleapis.com/youtube/v3/playlistItems?part=snippet&playlistId={yt_id}",
        headers={"Authorization": f"Bearer {yt_access_token}"},
    )
    songs = []
    for item in response.json().get("items", []):
        parsed = parse_youtube_title(
            item["snippet"]["title"], item["snippet"]["videoOwnerChannelTitle"]
        )
        songs.append(parsed)
    return songs


def get_spotify_songs(sp_id: str, sp_access_token: str):
    response = requests.get(
        f"https://api.spotify.com/v1/playlists/{sp_id}/tracks",
        headers={"Authorization": f"Bearer {sp_access_token}"},
    )
    songs = []
    for item in response.json().get("items", []):
        songs.append(
            {
                "title": item["track"]["name"],
                "artist": item["track"]["artists"][0]["name"],
            }
        )
    return songs


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
            response = requests.post(
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


def parse_youtube_title(title: str, channel_title: str):

    if channel_title.endswith("- Topic"):
        artist = channel_title.replace("- Topic", "").strip()
        return {"title": title.strip(), "artist": artist}

    title = re.sub(r"\(.*?\)|\[.*?\]", "", title).strip()

    if " - " in title:
        parts = title.split(" - ", 1)

        if (
            channel_title.lower() in parts[0].lower()
            or parts[0].lower() in channel_title.lower()
        ):
            return {"title": parts[1].strip(), "artist": parts[0].strip()}
        elif (
            channel_title.lower() in parts[1].lower()
            or parts[1].lower() in channel_title.lower()
        ):
            return {"title": parts[0].strip(), "artist": parts[1].strip()}
        else:
            return {"title": parts[1].strip(), "artist": parts[0].strip()}

    return {"title": title.strip(), "artist": channel_title.strip()}


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

    try:
        open_to_db.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            (user.username, hashed_password.decode("utf-8")),
        )
        open_to_db.execute("SELECT id FROM users WHERE username = %s", (user.username,))
        user_r = open_to_db.fetchone()
        user_id = user_r[0]
        open_to_db.execute("INSERT INTO playlists (user_id) VALUES (%s)", (user_id,))
        db_url.commit()
    except Exception as e:
        db_url.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        open_to_db.close()

    return RedirectResponse(url=f"/google_auth?user_id={user_id}", status_code=303)


@app.post("/login")
def login(user: User_Input):
    open_to_db = db_url.cursor()

    open_to_db.execute(
        "SELECT id, password, youtube_token_expiry, spotify_token_expiry FROM users WHERE username = %s",
        (user.username,),
    )
    user_info = open_to_db.fetchone()
    open_to_db.close()

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


@app.post("/create_playlist")
def create_playlist(data: Playlist_Input):
    open_to_db = db_url.cursor()

    open_to_db.execute(
        "SELECT id FROM playlists WHERE playlist_name = %s AND user_id = %s",
        (data.name, data.user_id),
    )
    if open_to_db.fetchone():
        open_to_db.close()
        raise HTTPException(
            status_code=400,
            detail="Playlist already exists. Please use 'Copy Playlist' instead.",
        )

    yt_access_token = get_valid_youtube_token(data.user_id)
    sp_access_token = get_valid_spotify_token(data.user_id)

    if data.platform == Platform.YOUTUBE:
        if check_youtube_playlist_exists(data.name, yt_access_token):
            open_to_db.close()
            raise HTTPException(
                status_code=400, detail="Playlist already exists on YouTube."
            )

        response = requests.post(
            "https://www.googleapis.com/youtube/v3/playlists?part=snippet,status",
            headers={
                "Authorization": f"Bearer {yt_access_token}",
                "Content-Type": "application/json",
            },
            json={
                "snippet": {"title": data.name},
                "status": {"privacyStatus": "private"},
            },
        )
        yt_playlist_id = response.json()["id"]

        try:
            open_to_db.execute(
                """UPDATE playlists 
                   SET playlist_name = %s, platform = %s, songs = %s, youtube_playlist_id = %s
                   WHERE user_id = %s AND playlist_name IS NULL""",
                (
                    data.name,
                    Platform.YOUTUBE,
                    json.dumps([]),
                    yt_playlist_id,
                    data.user_id,
                ),
            )
            db_url.commit()
        except Exception as e:
            db_url.rollback()
            raise HTTPException(status_code=500, detail=str(e))
        finally:
            open_to_db.close()

        return {
            "message": f"YouTube playlist '{data.name}' created successfully for user {data.user_id}."
        }

    elif data.platform == Platform.SPOTIFY:
        if check_spotify_playlist_exists(data.name, sp_access_token):
            open_to_db.close()
            raise HTTPException(
                status_code=400, detail="Playlist already exists on Spotify."
            )

        response = requests.post(
            "https://api.spotify.com/v1/me/playlists",
            headers={
                "Authorization": f"Bearer {sp_access_token}",
                "Content-Type": "application/json",
            },
            json={"name": data.name, "public": False, "collaborative": False},
        )
        sp_playlist_id = response.json()["id"]

        try:
            open_to_db.execute(
                """UPDATE playlists 
                   SET playlist_name = %s, platform = %s, songs = %s, spotify_playlist_id = %s
                   WHERE user_id = %s AND playlist_name IS NULL""",
                (
                    data.name,
                    Platform.SPOTIFY,
                    json.dumps([]),
                    sp_playlist_id,
                    data.user_id,
                ),
            )
            db_url.commit()
        except Exception as e:
            db_url.rollback()
            raise HTTPException(status_code=500, detail=str(e))
        finally:
            open_to_db.close()

        return {
            "message": f"Spotify playlist '{data.name}' created successfully for user {data.user_id}."
        }

    else:
        if check_youtube_playlist_exists(data.name, yt_access_token):
            open_to_db.close()
            raise HTTPException(
                status_code=400, detail="Playlist already exists on YouTube."
            )

        if check_spotify_playlist_exists(data.name, sp_access_token):
            open_to_db.close()
            raise HTTPException(
                status_code=400, detail="Playlist already exists on Spotify."
            )

        yt_response = requests.post(
            "https://www.googleapis.com/youtube/v3/playlists?part=snippet,status",
            headers={
                "Authorization": f"Bearer {yt_access_token}",
                "Content-Type": "application/json",
            },
            json={
                "snippet": {"title": data.name},
                "status": {"privacyStatus": "private"},
            },
        )
        yt_playlist_id = yt_response.json()["id"]

        sp_response = requests.post(
            "https://api.spotify.com/v1/me/playlists",
            headers={
                "Authorization": f"Bearer {sp_access_token}",
                "Content-Type": "application/json",
            },
            json={"name": data.name, "public": False, "collaborative": False},
        )
        sp_playlist_id = sp_response.json()["id"]

        try:
            open_to_db.execute(
                """UPDATE playlists 
                   SET playlist_name = %s, platform = %s, songs = %s, youtube_playlist_id = %s, spotify_playlist_id = %s
                   WHERE user_id = %s AND playlist_name IS NULL""",
                (
                    data.name,
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
            open_to_db.close()

        return {
            "message": f"Playlists created and synced successfully for user {data.user_id}."
        }


@app.post("/copy_playlist")
def copy_playlist(data: Copy_Playlist_Input):
    open_to_db = db_url.cursor()

    open_to_db.execute(
        "SELECT id, platform, songs, youtube_playlist_id, spotify_playlist_id FROM playlists WHERE playlist_name = %s AND user_id = %s",
        (data.name, data.user_id),
    )
    playlist_info = open_to_db.fetchone()

    if not playlist_info:
        open_to_db.close()
        raise HTTPException(
            status_code=404,
            detail="Playlist not found. Please add it first using /add_playlist.",
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
        songs = get_youtube_songs(yt_id, yt_access_token)

        track_uris = []
        for song in songs:
            search_response = requests.get(
                "https://api.spotify.com/v1/search",
                headers={"Authorization": f"Bearer {sp_access_token}"},
                params={
                    "q": f"track:{song['title']} artist:{song['artist']}",
                    "type": "track",
                    "limit": 1,
                },
            )
            search_data = search_response.json()
            if search_data["tracks"]["items"]:
                track_uris.append(search_data["tracks"]["items"][0]["uri"])

        sp_response = requests.post(
            "https://api.spotify.com/v1/me/playlists",
            headers={
                "Authorization": f"Bearer {sp_access_token}",
                "Content-Type": "application/json",
            },
            json={"name": data.name, "public": False, "collaborative": False},
        )
        new_platform_id = sp_response.json()["id"]

        if track_uris:
            requests.post(
                f"https://api.spotify.com/v1/playlists/{new_platform_id}/tracks",
                headers={
                    "Authorization": f"Bearer {sp_access_token}",
                    "Content-Type": "application/json",
                },
                json={"uris": track_uris},
            )

    else:
        songs = get_spotify_songs(sp_id, sp_access_token)

        yt_response = requests.post(
            "https://www.googleapis.com/youtube/v3/playlists?part=snippet,status",
            headers={
                "Authorization": f"Bearer {yt_access_token}",
                "Content-Type": "application/json",
            },
            json={
                "snippet": {"title": data.name},
                "status": {"privacyStatus": "private"},
            },
        )
        new_platform_id = yt_response.json()["id"]

        for song in songs:
            search_response = requests.get(
                "https://www.googleapis.com/youtube/v3/search",
                headers={"Authorization": f"Bearer {yt_access_token}"},
                params={
                    "part": "snippet",
                    "q": f"{song['title']} {song['artist']}",
                    "type": "video",
                    "videoCategoryId": "10",
                    "maxResults": 1,
                },
            )
            search_data = search_response.json()
            if search_data.get("items"):
                video_id = search_data["items"][0]["id"]["videoId"]
                requests.post(
                    "https://www.googleapis.com/youtube/v3/playlistItems?part=snippet",
                    headers={
                        "Authorization": f"Bearer {yt_access_token}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "snippet": {
                            "playlistId": new_platform_id,
                            "resourceId": {
                                "kind": "youtube#video",
                                "videoId": video_id,
                            },
                        }
                    },
                )

    new_platform = Platform.BOTH if data.sync else target_platform

    try:
        if data.platform == Platform.YOUTUBE:
            open_to_db.execute(
                "UPDATE playlists SET platform = %s, spotify_playlist_id = %s, songs = %s WHERE id = %s",
                (new_platform, new_platform_id, json.dumps(songs), pl_id),
            )
        else:
            open_to_db.execute(
                "UPDATE playlists SET platform = %s, youtube_playlist_id = %s, songs = %s WHERE id = %s",
                (new_platform, new_platform_id, json.dumps(songs), pl_id),
            )
        db_url.commit()
    except Exception as e:
        db_url.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        open_to_db.close()

    return {
        "message": f"Playlist '{data.name}' copied from {data.platform} to {target_platform}.",
        "synced": data.sync,
    }


@app.post("/sync_playlist")
def sync_playlist(data: Sync_Playlist_Input):
    open_to_db = db_url.cursor()

    open_to_db.execute(
        "SELECT id, platform, youtube_playlist_id, spotify_playlist_id FROM playlists WHERE playlist_name = %s AND user_id = %s",
        (data.name, data.user_id),
    )
    playlist_info = open_to_db.fetchone()

    if not playlist_info:
        open_to_db.close()
        raise HTTPException(
            status_code=404, detail="This playlist is not synced. Please try again."
        )

    pl_id, current_platform, yt_id, sp_id = playlist_info

    if current_platform != Platform.BOTH:
        open_to_db.close()
        raise HTTPException(
            status_code=400, detail="This playlist is not synced. Please try again."
        )

    yt_access_token = get_valid_youtube_token(data.user_id)
    sp_access_token = get_valid_spotify_token(data.user_id)
    open_to_db.close()

    if data.override_platform == Platform.YOUTUBE:
        songs = get_youtube_songs(yt_id, yt_access_token)

        track_uris = []
        for song in songs:
            search_response = requests.get(
                "https://api.spotify.com/v1/search",
                headers={"Authorization": f"Bearer {sp_access_token}"},
                params={
                    "q": f"track:{song['title']} artist:{song['artist']}",
                    "type": "track",
                    "limit": 1,
                },
            )
            search_data = search_response.json()
            if search_data["tracks"]["items"]:
                track_uris.append(search_data["tracks"]["items"][0]["uri"])

        if track_uris:
            requests.put(
                f"https://api.spotify.com/v1/playlists/{sp_id}/tracks",
                headers={
                    "Authorization": f"Bearer {sp_access_token}",
                    "Content-Type": "application/json",
                },
                json={"uris": track_uris},
            )

    else:
        songs = get_spotify_songs(sp_id, sp_access_token)

        yt_items_response = requests.get(
            f"https://www.googleapis.com/youtube/v3/playlistItems?part=id&playlistId={yt_id}",
            headers={"Authorization": f"Bearer {yt_access_token}"},
        )
        for item in yt_items_response.json().get("items", []):
            requests.delete(
                f"https://www.googleapis.com/youtube/v3/playlistItems?id={item['id']}",
                headers={"Authorization": f"Bearer {yt_access_token}"},
            )

        for song in songs:
            search_response = requests.get(
                "https://www.googleapis.com/youtube/v3/search",
                headers={"Authorization": f"Bearer {yt_access_token}"},
                params={
                    "part": "snippet",
                    "q": f"{song['title']} {song['artist']}",
                    "type": "video",
                    "videoCategoryId": "10",
                    "maxResults": 1,
                },
            )
            search_data = search_response.json()
            if search_data.get("items"):
                video_id = search_data["items"][0]["id"]["videoId"]
                requests.post(
                    "https://www.googleapis.com/youtube/v3/playlistItems?part=snippet",
                    headers={
                        "Authorization": f"Bearer {yt_access_token}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "snippet": {
                            "playlistId": yt_id,
                            "resourceId": {
                                "kind": "youtube#video",
                                "videoId": video_id,
                            },
                        }
                    },
                )

    open_to_db = db_url.cursor()
    try:
        open_to_db.execute(
            "UPDATE playlists SET songs = %s WHERE id = %s",
            (json.dumps(songs), pl_id),
        )
        db_url.commit()
    except Exception as e:
        db_url.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        open_to_db.close()

    return {
        "message": f"Playlist '{data.name}' synced successfully using {data.override_platform} as source of truth."
    }


@app.post("/add_playlist")
def add_playlist(data: Add_Playlist_Input):
    open_to_db = db_url.cursor()

    open_to_db.execute(
        "SELECT id FROM playlists WHERE playlist_name = %s AND user_id = %s",
        (data.name, data.user_id),
    )
    if open_to_db.fetchone():
        open_to_db.close()
        raise HTTPException(
            status_code=400, detail="Playlist already exists in your account."
        )

    yt_access_token = get_valid_youtube_token(data.user_id)
    sp_access_token = get_valid_spotify_token(data.user_id)

    if data.platform == Platform.YOUTUBE:
        playlist_id = get_youtube_playlist_id(data.name, yt_access_token)
        if not playlist_id:
            open_to_db.close()
            raise HTTPException(
                status_code=404, detail="Playlist not found on YouTube."
            )

        songs = get_youtube_songs(playlist_id, yt_access_token)

        try:
            open_to_db.execute(
                """INSERT INTO playlists (user_id, playlist_name, platform, songs, youtube_playlist_id)
                   VALUES (%s, %s, %s, %s, %s)""",
                (
                    data.user_id,
                    data.name,
                    Platform.YOUTUBE,
                    json.dumps(songs),
                    playlist_id,
                ),
            )
            db_url.commit()
        except Exception as e:
            db_url.rollback()
            raise HTTPException(status_code=500, detail=str(e))
        finally:
            open_to_db.close()

    else:
        playlist_id = get_spotify_playlist_id(data.name, sp_access_token)
        if not playlist_id:
            open_to_db.close()
            raise HTTPException(
                status_code=404, detail="Playlist not found on Spotify."
            )

        songs = get_spotify_songs(playlist_id, sp_access_token)

        try:
            open_to_db.execute(
                """INSERT INTO playlists (user_id, playlist_name, platform, songs, spotify_playlist_id)
                   VALUES (%s, %s, %s, %s, %s)""",
                (
                    data.user_id,
                    data.name,
                    Platform.SPOTIFY,
                    json.dumps(songs),
                    playlist_id,
                ),
            )
            db_url.commit()
        except Exception as e:
            db_url.rollback()
            raise HTTPException(status_code=500, detail=str(e))
        finally:
            open_to_db.close()

    return {
        "message": f"Playlist '{data.name}' added successfully from {data.platform}."
    }


@app.delete("/delete_playlist")
def delete_playlist(data: Delete_Playlist_Input):
    open_to_db = db_url.cursor()

    if data.platform == Platform.BOTH:
        open_to_db.execute(
            "SELECT id, platform, youtube_playlist_id, spotify_playlist_id FROM playlists WHERE playlist_name = %s AND user_id = %s",
            (data.name, data.user_id),
        )
    elif data.platform == Platform.YOUTUBE:
        open_to_db.execute(
            "SELECT id, platform, youtube_playlist_id, spotify_playlist_id FROM playlists WHERE playlist_name = %s AND user_id = %s AND platform = %s",
            (data.name, data.user_id, Platform.YOUTUBE),
        )
    else:
        open_to_db.execute(
            "SELECT id, platform, youtube_playlist_id, spotify_playlist_id FROM playlists WHERE playlist_name = %s AND user_id = %s AND platform = %s",
            (data.name, data.user_id, Platform.SPOTIFY),
        )

    playlist_info = open_to_db.fetchone()

    if not playlist_info:
        open_to_db.close()
        return {"message": f"Playlist '{data.name}' not found. Nothing to delete."}

    pl_id, current_platform, yt_id, sp_id = playlist_info

    yt_access_token = get_valid_youtube_token(data.user_id)
    sp_access_token = get_valid_spotify_token(data.user_id)

    if current_platform in (Platform.YOUTUBE, Platform.BOTH) and yt_id:
        requests.delete(
            f"https://www.googleapis.com/youtube/v3/playlists?id={yt_id}",
            headers={"Authorization": f"Bearer {yt_access_token}"},
        )

    if current_platform in (Platform.SPOTIFY, Platform.BOTH) and sp_id:
        requests.delete(
            f"https://api.spotify.com/v1/playlists/{sp_id}/followers",
            headers={"Authorization": f"Bearer {sp_access_token}"},
        )

    try:
        open_to_db.execute("DELETE FROM playlists WHERE id = %s", (pl_id,))
        db_url.commit()
    except Exception as e:
        db_url.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        open_to_db.close()

    return {
        "message": f"Playlist '{data.name}' deleted successfully from {current_platform}."
    }


@app.delete("/delete_account")
def delete_account(user_id: int):
    open_to_db = db_url.cursor()

    open_to_db.execute("SELECT id FROM users WHERE id = %s", (user_id,))
    if not open_to_db.fetchone():
        open_to_db.close()
        raise HTTPException(status_code=404, detail="User not found.")

    try:
        open_to_db.execute("DELETE FROM users WHERE id = %s", (user_id,))
        db_url.commit()
    except Exception as e:
        db_url.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        open_to_db.close()

    return {"message": "Account deleted successfully."}


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


@app.get("/google_auth/callback")
def get_google_tokens(state: str, code: str):
    state_json = base64.urlsafe_b64decode(state.encode()).decode()
    state_data = json.loads(state_json)
    user_id = state_data.get("user_id")
    user_id = int(user_id)
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

    open_to_db = db_url.cursor()
    try:
        open_to_db.execute(
            "UPDATE users SET youtube_refresh_token = %s, youtube_access_token = %s, youtube_token_expiry = %s WHERE id = %s",
            (refresh_token, access_token_you, exp_time, user_id),
        )

        open_to_db.execute(
            "SELECT spotify_refresh_token FROM users WHERE id = %s", (user_id,)
        )
        sp_token = open_to_db.fetchone()
        db_url.commit()
    except Exception as e:
        db_url.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        open_to_db.close()

    if not sp_token or not sp_token[0]:
        return RedirectResponse(url=f"/spotify_auth?user_id={user_id}", status_code=303)

    return {"message": "Google re-authentication successful.", "user_id": user_id}


@app.get("/spotify_auth")
def spotify_login(user_id: int):
    state_json = json.dumps({"user_id": user_id})
    user_id = int(user_id)
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

    response = requests.post(
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
    open_to_db = db_url.cursor()
    try:
        open_to_db.execute(
            "UPDATE users SET spotify_access_token = %s, spotify_refresh_token = %s, spotify_token_expiry = %s WHERE id = %s",
            (access_token, refresh_token, expires_in, user_id),
        )

        db_url.commit()
    except Exception as e:
        db_url.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        open_to_db.close()

    return {"message": "Spotify re-authentication successful.", "user_id": user_id}
