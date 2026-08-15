from fastapi import FastAPI

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