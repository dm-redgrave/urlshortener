import os
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import RedirectResponse
from datetime import timedelta
import secrets
import string
import socket
import threading, time
from diskcache import Cache
from passlib.context import CryptContext
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db_models import *
from schemas import *

LinkDefaultExpiration = 30 # days

app = FastAPI(title="URL Shortener")

engine = create_engine("sqlite:///shortener.db", connect_args={"check_same_thread": False})
Base.metadata.create_all(bind=engine)
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
cache = Cache(".cache")

LOCAL_DOMAIN = os.getenv("PUBLIC_DOMAIN")
print("LOCAL_DOMAIN:", LOCAL_DOMAIN)

def generate_short_code(length=6):
    letters = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(letters) for _ in range(length))

def generate_password(length=8):
    letters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(letters) for _ in range(length))

def authenticate_user(email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return None
    if not pwd_context.verify(password, user.password_hash):
        return None
    return user

def remove_expired_links():
    now = datetime.now()
    links = db.query(Link).all()
    for link in links:
        if link.expires_at and link.expires_at < now:
            db.delete(link)
            cache.delete(f"popularity:{link.short_code}")
            continue
        if link.last_accessed_at:
            if (now - link.last_accessed_at) > timedelta(days=LinkDefaultExpiration):
                db.delete(link)
                cache.delete(f"popularity:{link.short_code}")
        elif (now - link.created_at) > timedelta(days=LinkDefaultExpiration):
            db.delete(link)
            cache.delete(f"popularity:{link.short_code}")
    db.commit()

def schedule_remove_expired_links():
    while True:
        time.sleep(LinkDefaultExpiration * 24 * 3600)
        remove_expired_links()

def startup_scheduled_remove():
    t = threading.Thread(target=schedule_remove_expired_links, daemon=True)
    t.start()

app.add_event_handler("startup", startup_scheduled_remove)

# Endpoint for render.com health check.
@app.get("/")
def root():
    return {"status": "ok"}

@app.post("/config/set_expiration", include_in_schema=False)
def set_expiration(days: int, access_token: str):
    if access_token != os.getenv("ADMIN_TOKEN"):
        raise HTTPException(status_code=403, detail="Access denied")
    global LinkDefaultExpiration
    LinkDefaultExpiration = days
    return {"message": f"Default expiration changed to {LinkDefaultExpiration}"}

@app.post("/auth/register")
def register_user(reg_req: RegisterRequest):
    existing = db.query(User).filter(User.email == reg_req.email).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User with this email already exists")
    plain_password = generate_password()
    user = User(email=reg_req.email, password_hash=pwd_context.hash(plain_password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "User created", "generated_password": plain_password}

@app.post("/links/shorten")
def create_short_link(link_data: ShortenRequest, email: str = "", password: str = ""):
    user = None
    if email or password:
        user = authenticate_user(email, password)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    short_code = link_data.custom_alias
    if short_code:
        exists = db.query(Link).filter(Link.short_code == short_code).first()
        if exists:
            raise HTTPException(status_code=400, detail="Alias already in use")
    else:
        while True:
            generated_sc = generate_short_code()
            if not db.query(Link).filter(Link.short_code == generated_sc).first():
                short_code = generated_sc
                break

    link = Link(
        short_code=short_code,
        original_url=link_data.url,
        user_id=user.id if user else None,
        expires_at=link_data.expires_at
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return {"short_url": f"https://{LOCAL_DOMAIN}/links/{link.short_code}", "short_code": short_code}

@app.get("/links/search")
def search_by_original_url(url: str):
    link = db.query(Link).filter(Link.original_url == url).first()
    if not link:
        raise HTTPException(status_code=404, detail="Not found")
    return {"short_code": link.short_code, "original_url": link.original_url}

@app.get("/links/{short_code}")
def redirect_to_original(short_code: str):
    link = db.query(Link).filter(Link.short_code == short_code).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    if link.expires_at and link.expires_at < datetime.now():
        raise HTTPException(status_code=410, detail="Link has expired")

    link.click_count += 1
    link.last_accessed_at = datetime.now()
    db.commit()
    key = f"popularity:{short_code}"
    cache.set(key, cache.get(key, default=0) + 1)
    return RedirectResponse(link.original_url)

@app.get("/links/{short_code}/stats", response_model=LinkInfo)
def get_link_stats(short_code: str):
    link = db.query(Link).filter(Link.short_code == short_code).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    return LinkInfo(
        original_url=link.original_url,
        created_at=link.created_at,
        last_accessed_at=link.last_accessed_at,
        click_count=link.click_count,
        expires_at=link.expires_at
    )

@app.delete("/links/{short_code}")
def delete_link(short_code: str, email: str, password: str):
    if not email or not password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials")
    user = authenticate_user(email, password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    link = db.query(Link).filter(Link.short_code == short_code).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    if link.user_id != user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    db.delete(link)
    db.commit()
    cache.delete(f"popularity:{link.short_code}")
    return {"message": "Link deleted"}

@app.put("/links/{short_code}")
def update_link(short_code: str, new_short_code: str, email: str, password: str):
    if not email or not password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials")
    user = authenticate_user(email, password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    link = db.query(Link).filter(Link.short_code == short_code).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    if link.user_id != user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    if db.query(Link).filter(Link.short_code == new_short_code).first():
        raise HTTPException(status_code=400, detail="New short code is already in use")

    cache.delete(f"popularity:{short_code}")
    link.short_code = new_short_code
    db.commit()
