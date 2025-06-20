from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/analyze")
async def analyze(request: Request):
    data = await request.json()
    text = data.get("text", "")
    # TODO: Integrate Cybersecurity-BaronLLM here
    result = f"[LLM analysis placeholder] Input length: {len(text)} chars"
    return JSONResponse({"result": result})

# TODO: Add /analyze endpoint for LLM integration 