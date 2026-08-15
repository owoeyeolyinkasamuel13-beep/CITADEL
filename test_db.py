from app.database.connection import engine

try:
    with engine.connect() as connection:
        print("CITADEL database connection successful.")
except Exception as error:
    print("CITADEL database connection failed.")
    print(error)