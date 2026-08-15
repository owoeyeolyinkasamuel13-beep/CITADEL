from fastapi import FastAPI
from app.database.connection import engine

app = FastAPI(
    title="CITADEL API",
    description="Classified Information and Tiered Access Defense Environment",
    version="1.0.0"
)


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