from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# LLM model setup (BaronLLM via llama-cpp-python)
llm = None
llm_load_error = None
try:
    from llama_cpp import Llama
    # Path to your GGUF model file (update as needed)
    GGUF_PATH = os.environ.get("BARONLLM_GGUF", "baronllm-llama3.1-v1-q6_k.gguf")
    llm = Llama.from_pretrained(
        repo_id="AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF",
        filename=GGUF_PATH,
    )
except Exception as e:
    llm_load_error = str(e)

@app.get("/health")
def health():
    if llm is not None:
        return {"status": "ok", "llm": "ready"}
    return {"status": "error", "llm": llm_load_error or "not loaded"}

@app.post("/analyze")
async def analyze(request: Request):
    data = await request.json()
    text = data.get("text", "")
    if not text:
        return JSONResponse({"error": "No input text provided"}, status_code=400)
    if llm is None:
        return JSONResponse({"error": f"LLM not loaded: {llm_load_error}"}, status_code=500)
    try:
        # Use chat completion for BaronLLM
        response = llm.create_chat_completion(
            messages=[{"role": "user", "content": text}]
        )
        result = response["choices"][0]["message"]["content"]
    except Exception as e:
        return JSONResponse({"error": f"LLM error: {str(e)}"}, status_code=500)
    return JSONResponse({"result": result})

# TODO: Add /analyze endpoint for LLM integration 