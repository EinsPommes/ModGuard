from fastapi import FastAPI, Request, Form
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import json
import aiosqlite
from datetime import datetime, timedelta
import os

app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

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

@app.get("/")
async def home(request: Request):
    warnings = await get_warnings()
    config = load_config()
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "warnings": warnings, "config": config}
    )

@app.post("/update_config")
async def update_config(
    mild_threshold: float = Form(...),
    moderate_threshold: float = Form(...),
    severe_threshold: float = Form(...),
    timeout_duration: int = Form(...),
    log_channel: str = Form(...),
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
async def api_warnings():
    warnings = await get_warnings()
    return {"warnings": [dict(w) for w in warnings]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
