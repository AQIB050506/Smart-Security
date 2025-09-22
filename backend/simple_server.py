from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="Security System API")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "Security System API is running!"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.post("/auth/signup")
async def signup():
    return {"message": "Signup endpoint working", "access_token": "test-token"}

@app.post("/auth/login")
async def login():
    return {"message": "Login endpoint working", "access_token": "test-token"}

@app.post("/auth/anonymous")
async def anonymous():
    return {"message": "Anonymous endpoint working", "access_token": "test-token"}

@app.get("/auth/me")
async def me():
    return {"id": 1, "email": "test@example.com", "hashed_id": "test-hash"}

@app.post("/reports/")
async def create_report():
    return {"id": 1, "message": "Report created successfully"}

@app.get("/reports/")
async def get_reports():
    return {"reports": [], "total": 0, "page": 1, "size": 10}

@app.post("/reports/scan-link")
async def scan_link():
    return {"url": "test.com", "is_safe": True, "confidence": 0.8}

@app.post("/reports/analyze-text")
async def analyze_text():
    return {"classification": "safe", "confidence": 0.8}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
