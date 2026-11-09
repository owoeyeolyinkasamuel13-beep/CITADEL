from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from app.routes.auth import router as auth_router
from app.routes.records import router as records_router

from app.database.connection import engine
from app.routes.users import router as users_router

app = FastAPI(
    title="CITADEL API",
    description="Classified Information and Tiered Access Defense Environment",
    version="1.0.0"
)


@app.exception_handler(RequestValidationError)
async def redact_validation_errors(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Return validation locations and types without echoing submitted data."""
    return JSONResponse(
        status_code=422,
        content={
            "detail": [
                {
                    "loc": error.get("loc", ()),
                    "msg": "Invalid value",
                    "type": error.get("type", "validation_error"),
                }
                for error in exc.errors()
            ]
        },
    )


app.include_router(users_router)
app.include_router(records_router)
app.include_router(auth_router)

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
