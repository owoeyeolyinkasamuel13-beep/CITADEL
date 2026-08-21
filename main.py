from fastapi import FastAPI
from app.routes.records import router as records_router

from app.database.connection import engine
from app.routes.users import router as users_router

app = FastAPI(
    title="CITADEL API",
    description="Classified Information and Tiered Access Defense Environment",
    version="1.0.0"
)


app.include_router(users_router)
app.include_router(records_router)

@app.get("/")
def root():
    return {
        "system": "CITADEL",
        "status": "online",
        "message": "CITADEL backend is running"
    }


@app.get("/health")
def health_check():
    try:
        with engine.connect():
            return {
                "system": "CITADEL",
                "api": "online",
                "database": "connected"
            }
    except Exception:
        return {
            "system": "CITADEL",
            "api": "online",
            "database": "disconnected"
        }