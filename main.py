import os
import hashlib
import base64
import re
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

import jwt  # PyJWT
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr

from database import db

# Crypto/hash helpers
from passlib.hash import bcrypt as bcrypt_hasher
try:
    from argon2 import PasswordHasher as Argon2Hasher
    from argon2.exceptions import VerifyMismatchError
    ARGON2_AVAILABLE = True
except ModuleNotFoundError:
    Argon2Hasher = None  # type: ignore
    VerifyMismatchError = Exception  # type: ignore
    ARGON2_AVAILABLE = False

# YouTube (optional import so server can still start if missing)
try:
    from yt_dlp import YoutubeDL
    YTDLP_AVAILABLE = True
except ModuleNotFoundError:
    YoutubeDL = None  # type: ignore
    YTDLP_AVAILABLE = False


app = FastAPI(title="Ternak Lele API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------------
# Auth/JWT utilities
# -------------------------------------------------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "supersecret-ternak-lele")
JWT_EXPIRE_MIN = int(os.getenv("JWT_EXPIRE_MIN", "60"))
security = HTTPBearer()
argon2_hasher = Argon2Hasher() if ARGON2_AVAILABLE else None


def create_jwt(payload: dict, minutes: int = JWT_EXPIRE_MIN) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=minutes)
    to_encode = {**payload, "iat": int(now.timestamp()), "exp": int(exp.timestamp())}
    token = jwt.encode(to_encode, JWT_SECRET, algorithm="HS256")
    return token


def decode_jwt(token: str) -> dict:
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # type: ignore[arg-type]
        return data
    except jwt.ExpiredSignatureError:  # type: ignore[attr-defined]
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:  # type: ignore[attr-defined]
        raise HTTPException(status_code=401, detail="Invalid token")


# -------------------------------------------------------------------
# Models
# -------------------------------------------------------------------
class RegisterIn(BaseModel):
    name: str
    email: EmailStr
    password: str
    algo: str = Field("bcrypt", pattern="^(bcrypt|argon2)$")


class AuthOut(BaseModel):
    token: str
    name: str
    email: EmailStr


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class BlogCreateIn(BaseModel):
    title: str
    content: str
    tags: List[str] = []


class BlogOut(BaseModel):
    id: str
    title: str
    slug: str
    content: str
    author: str
    tags: List[str] = []
    published: bool = True
    published_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


class HashIn(BaseModel):
    text: str


class EncodeIn(BaseModel):
    text: str


class DecodeIn(BaseModel):
    data: str


YOUTUBE_URL_RE = re.compile(r"^(https?://)?(www\.)?(youtube\.com|youtu\.be)/")


# -------------------------------------------------------------------
# Root + hit counters
# -------------------------------------------------------------------
@app.get("/")
def root():
    # increment total hit counter
    if db is not None:
        db["hit"].update_one({"key": "total"}, {"$inc": {"count": 1}}, upsert=True)
        total = db["hit"].find_one({"key": "total"})
        count = total.get("count", 0) if total else 0
    else:
        count = 0
    return {"app": "Ternak Lele API", "status": "ok", "hits": count}


@app.head("/")
def root_head():
    # Explicit HEAD route for health checks
    return {}


@app.get("/stats")
def stats():
    total = db["hit"].find_one({"key": "total"}) if db is not None else None
    return {"hits": (total.get("count", 0) if total else 0)}


# -------------------------------------------------------------------
# Auth endpoints
# -------------------------------------------------------------------
@app.post("/auth/register", response_model=AuthOut)
def register(data: RegisterIn):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    if db["user"].find_one({"email": data.email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    if data.algo == "bcrypt" or not ARGON2_AVAILABLE:
        pwd_hash = bcrypt_hasher.hash(data.password)
        algo_used = "bcrypt"
    else:
        pwd_hash = argon2_hasher.hash(data.password)  # type: ignore[union-attr]
        algo_used = "argon2"

    user_doc = {
        "name": data.name,
        "email": data.email,
        "password_hash": pwd_hash,
        "algo": algo_used,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    db["user"].insert_one(user_doc)

    token = create_jwt({"sub": str(user_doc.get("_id", "")), "email": data.email, "name": data.name})
    return {"token": token, "name": data.name, "email": data.email}


@app.post("/auth/login", response_model=AuthOut)
def login(data: LoginIn):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    user = db["user"].find_one({"email": data.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    algo = user.get("algo", "bcrypt")
    pwd_hash = user.get("password_hash")

    ok = False
    if algo == "bcrypt" or not ARGON2_AVAILABLE:
        try:
            ok = bcrypt_hasher.verify(data.password, pwd_hash)
        except Exception:
            ok = False
    else:
        try:
            ok = argon2_hasher.verify(pwd_hash, data.password)  # type: ignore[union-attr]
        except Exception:
            ok = False

    if not ok:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_jwt({"sub": str(user.get("_id", "")), "email": user["email"], "name": user["name"]})
    return {"token": token, "name": user["name"], "email": user["email"]}


@app.get("/me")
def me(credentials: HTTPAuthorizationCredentials = Depends(security)):
    data = decode_jwt(credentials.credentials)
    email = data.get("email")
    user = db["user"].find_one({"email": email}) if db is not None else None
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    total = db["hit"].find_one({"key": "total"}) if db is not None else None
    return {
        "name": user.get("name"),
        "email": user.get("email"),
        "avatar_url": user.get("avatar_url"),
        "bio": user.get("bio"),
        "total_hits": (total.get("count", 0) if total else 0),
    }


# -------------------------------------------------------------------
# Blog endpoints
# -------------------------------------------------------------------

def slugify(title: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9\s-]", "", title).strip().lower()
    s = re.sub(r"[\s-]+", "-", s)
    return s


@app.post("/blog", response_model=BlogOut)
def create_blog(data: BlogCreateIn, credentials: HTTPAuthorizationCredentials = Depends(security)):
    user_data = decode_jwt(credentials.credentials)
    email = user_data.get("email")
    user = db["user"].find_one({"email": email}) if db is not None else None
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    slug = slugify(data.title)
    doc = {
        "title": data.title,
        "slug": slug,
        "content": data.content,
        "author_id": str(user.get("_id")),
        "author": user.get("name"),
        "tags": data.tags,
        "published": True,
        "published_at": datetime.now(timezone.utc),
        "created_at": datetime.now(timezone.utc),
    }
    res = db["blogpost"].insert_one(doc)
    return {
        "id": str(res.inserted_id),
        "title": doc["title"],
        "slug": doc["slug"],
        "content": doc["content"],
        "author": doc["author"],
        "tags": doc["tags"],
        "published": doc["published"],
        "published_at": doc["published_at"],
        "created_at": doc["created_at"],
    }


@app.get("/blog", response_model=List[BlogOut])
def list_blogs(limit: int = Query(20, ge=1, le=100)):
    items = db["blogpost"].find({}).sort("created_at", -1).limit(limit) if db is not None else []
    out: List[BlogOut] = []
    for b in items:
        out.append(
            BlogOut(
                id=str(b.get("_id")),
                title=b.get("title"),
                slug=b.get("slug"),
                content=b.get("content"),
                author=b.get("author"),
                tags=b.get("tags", []),
                published=b.get("published", True),
                published_at=b.get("published_at"),
                created_at=b.get("created_at"),
            )
        )
    return out


@app.get("/blog/{slug}", response_model=BlogOut)
def get_blog(slug: str):
    b = db["blogpost"].find_one({"slug": slug}) if db is not None else None
    if not b:
        raise HTTPException(status_code=404, detail="Not found")
    return BlogOut(
        id=str(b.get("_id")),
        title=b.get("title"),
        slug=b.get("slug"),
        content=b.get("content"),
        author=b.get("author"),
        tags=b.get("tags", []),
        published=b.get("published", True),
        published_at=b.get("published_at"),
        created_at=b.get("created_at"),
    )


# -------------------------------------------------------------------
# Hashing + encode/decode utilities
# -------------------------------------------------------------------
@app.post("/hash/md5")
def md5_hash(data: HashIn):
    return {"algo": "md5", "hash": hashlib.md5(data.text.encode()).hexdigest()}


@app.post("/hash/sha256")
def sha256_hash(data: HashIn):
    return {"algo": "sha256", "hash": hashlib.sha256(data.text.encode()).hexdigest()}


@app.post("/hash/bcrypt")
def bcrypt_hash(data: HashIn):
    return {"algo": "bcrypt", "hash": bcrypt_hasher.hash(data.text)}


@app.post("/hash/argon2")
def argon2_hash(data: HashIn):
    if not ARGON2_AVAILABLE:
        raise HTTPException(status_code=400, detail="argon2 module not installed")
    return {"algo": "argon2", "hash": argon2_hasher.hash(data.text)}  # type: ignore[union-attr]


@app.post("/encode/base64")
def encode_base64(data: EncodeIn):
    encoded = base64.b64encode(data.text.encode()).decode()
    return {"encoding": "base64", "result": encoded}


@app.post("/decode/base64")
def decode_base64(data: DecodeIn):
    try:
        decoded = base64.b64decode(data.data.encode()).decode()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 data")
    return {"encoding": "base64", "result": decoded}


@app.post("/encode/hex")
def encode_hex(data: EncodeIn):
    return {"encoding": "hex", "result": data.text.encode().hex()}


@app.post("/decode/hex")
def decode_hex(data: DecodeIn):
    try:
        result = bytes.fromhex(data.data).decode()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid hex data")
    return {"encoding": "hex", "result": result}


# -------------------------------------------------------------------
# YouTube: ytmp3 / ytmp4 (returns direct media URLs)
# -------------------------------------------------------------------

@app.get("/yt/info")
def yt_info(url: str = Query(...)):
    if not YTDLP_AVAILABLE:
        raise HTTPException(status_code=500, detail="yt-dlp not installed on server")
    if not YOUTUBE_URL_RE.search(url):
        raise HTTPException(status_code=400, detail="Invalid YouTube URL")
    ydl_opts: Dict[str, Any] = {"quiet": True, "skip_download": True}
    with YoutubeDL(ydl_opts) as ydl:  # type: ignore[misc]
        info = ydl.extract_info(url, download=False)
    formats = info.get("formats", [])
    audio = None
    video = None
    for f in formats:
        if not audio and f.get("acodec") != "none" and f.get("vcodec") == "none":
            audio = f
        if not video and f.get("ext") == "mp4" and f.get("vcodec") != "none" and f.get("acodec") != "none":
            video = f
    return {
        "id": info.get("id"),
        "title": info.get("title"),
        "thumbnail": info.get("thumbnail"),
        "uploader": info.get("uploader"),
        "duration": info.get("duration"),
        "audio_url": audio.get("url") if audio else None,
        "audio_ext": audio.get("ext") if audio else None,
        "video_url": video.get("url") if video else None,
        "video_ext": video.get("ext") if video else None,
    }


@app.get("/yt/mp3")
def yt_mp3(url: str = Query(...)):
    return yt_info(url)


@app.get("/yt/mp4")
def yt_mp4(url: str = Query(...)):
    return yt_info(url)


# -------------------------------------------------------------------
# Health
# -------------------------------------------------------------------
@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
