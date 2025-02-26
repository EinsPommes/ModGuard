from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import json
import aiosqlite
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import secrets
import hashlib

# Load environment variables
load_dotenv()

app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")
security = HTTPBasic()

# Admin credentials (in production, use proper password hashing and database storage)
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")

def get_password_hash(password: str) -> str:
    """Generate password hash"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    """Verify user credentials"""
    is_username_correct = secrets.compare_digest(credentials.username, ADMIN_USERNAME)
    is_password_correct = secrets.compare_digest(
        get_password_hash(credentials.password),
        get_password_hash(ADMIN_PASSWORD)
    )
    
    if not (is_username_correct and is_password_correct):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

async def get_warnings(days: int = 7):
    async with aiosqlite.connect('modguard.db') as db:
        db.row_factory = aiosqlite.Row
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        async with db.execute(
            'SELECT * FROM warnings WHERE timestamp > ? ORDER BY timestamp DESC',
            (cutoff_date.isoformat(),)
        ) as cursor:
            return await cursor.fetchall()

async def init_db():
    async with aiosqlite.connect('modguard.db') as db:
        await db.execute('''
            CREATE TABLE IF NOT EXISTS warnings (
                user_id INTEGER,
                guild_id INTEGER,
                warning_level TEXT,
                reason TEXT,
                timestamp DATETIME,
                message_content TEXT
            )
        ''')
        await db.commit()

@app.on_event("startup")
async def startup_event():
    await init_db()

def load_config():
    with open('config.json', 'r') as f:
        return json.load(f)

def save_config(config):
    with open('config.json', 'w') as f:
        json.dump(config, f, indent=4)

async def get_statistics():
    """Get moderation statistics"""
    async with aiosqlite.connect('modguard.db') as db:
        db.row_factory = aiosqlite.Row
        
        # Total warnings
        total_warnings = await db.execute('SELECT COUNT(*) as count FROM warnings')
        total_warnings = await total_warnings.fetchone()
        
        # Warnings by level
        warnings_by_level = await db.execute('''
            SELECT warning_level, COUNT(*) as count 
            FROM warnings 
            GROUP BY warning_level
        ''')
        warnings_by_level = await warnings_by_level.fetchall()
        
        # Recent warnings
        recent_warnings = await db.execute('''
            SELECT * FROM warnings 
            ORDER BY timestamp DESC 
            LIMIT 5
        ''')
        recent_warnings = await recent_warnings.fetchall()
        
        return {
            'total_warnings': total_warnings['count'],
            'warnings_by_level': {row['warning_level']: row['count'] for row in warnings_by_level},
            'recent_warnings': recent_warnings
        }

@app.get("/")
async def home(request: Request, username: str = Depends(verify_credentials)):
    warnings = await get_warnings()
    stats = await get_statistics()
    config = load_config()
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "warnings": warnings,
            "config": config,
            "stats": stats,
            "username": username
        }
    )

@app.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    if username == ADMIN_USERNAME and get_password_hash(password) == get_password_hash(ADMIN_PASSWORD):
        response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
        return response
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Ungültige Anmeldedaten"},
        status_code=status.HTTP_401_UNAUTHORIZED
    )

@app.post("/update_config")
async def update_config(
    mild_threshold: float = Form(...),
    moderate_threshold: float = Form(...),
    severe_threshold: float = Form(...),
    timeout_duration: int = Form(...),
    log_channel: str = Form(...),
    username: str = Depends(verify_credentials)
):
    config = load_config()
    config['warning_levels']['mild']['threshold'] = mild_threshold
    config['warning_levels']['moderate']['threshold'] = moderate_threshold
    config['warning_levels']['severe']['threshold'] = severe_threshold
    config['timeout_duration'] = timeout_duration
    config['log_channel_name'] = log_channel
    save_config(config)
    return RedirectResponse(url="/", status_code=303)

@app.get("/api/warnings")
async def api_warnings(username: str = Depends(verify_credentials)):
    warnings = await get_warnings()
    return {"warnings": [dict(w) for w in warnings]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
