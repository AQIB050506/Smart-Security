# main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
# other imports...
from fastapi import Depends
import uvicorn

app = FastAPI(title="NextGen Smart Security - API")

# DEVELOPMENT: allow your frontend origins here.
# Replace / add your frontend origin(s) when deployed.
origins = [
    "http://localhost:3000",   # React dev
    "http://127.0.0.1:3000",
    "http://localhost:8080",   # Flutter web often runs here
    "http://127.0.0.1:8080",
    "http://localhost:5000",
    "http://localhost:62808",
    "http://localhost:51719"   # if any other dev ports
    # "http://your-deployed-frontend.com"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,      # <-- list specific origins in production
    allow_credentials=True,     # allow cookies/Authorization header
    allow_methods=["*"],
    allow_headers=["*"],
)

# Example auth route (simplified)
from pydantic import BaseModel
class LoginIn(BaseModel):
    email: str
    password: str

@app.post("/auth/login")
async def login(payload: LoginIn):
    # your authentication logic...
    return {"access_token": "fake-token-for-demo", "token_type": "bearer"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
