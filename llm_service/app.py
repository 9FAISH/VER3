from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from huggingface_hub import hf_hub_download
from llama_cpp import Llama
import logging
import os

# --- Basic Setup ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class LLMRequest(BaseModel):
    text: str

# --- Model Loading ---
llm = None
try:
    model_name = "TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF"
    model_file = "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
    model_path = hf_hub_download(model_name, filename=model_file)
    
    logger.info(f"Loading GGUF model from: {model_path}")
    llm = Llama(
        model_path=model_path,
        n_ctx=4096,  # Max context size
        n_gpu_layers=-1, # Offload all layers to GPU if available
        verbose=True,
    )
    logger.info("Successfully loaded LLM.")
except Exception as e:
    logger.error(f"FATAL: Failed to load LLM: {e}", exc_info=True)

@app.post("/analyze")
async def analyze(request: LLMRequest):
    if not llm:
        raise HTTPException(status_code=500, detail="LLM not available.")

    prompt_template = """<|system|>
You are a security expert. Your task is to analyze the provided security scan findings and generate a concise, actionable summary for a developer.
- Summarize the key vulnerabilities.
- Suggest potential attack vectors.
- Provide clear, developer-friendly remediation advice.
- Structure the output as a bulleted list.
</s>
<|user|>
Please analyze these findings:
{findings_text}
</s>
<|assistant|>
"""
    
    try:
        prompt = prompt_template.format(findings_text=request.text)
        
        logger.info("Generating LLM analysis...")
        output = llm.create_chat_completion(
            messages=[
                {"role": "system", "content": "You are a security expert. Your task is to analyze the provided security scan findings and generate a concise, actionable summary for a developer. Summarize key vulnerabilities, suggest potential attack vectors, and provide clear, developer-friendly remediation advice. Structure the output as a bulleted list."},
                {"role": "user", "content": f"Please analyze these findings: {request.text}"}
            ],
            max_tokens=512,
            temperature=0.7,
        )
        
        analysis = output['choices'][0]['message']['content']
        logger.info("Successfully generated analysis.")
        return {"result": analysis}
        
    except Exception as e:
        logger.error(f"Error during analysis: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health():
    return {"status": "ok" if llm else "error"}

@app.get("/")
def read_root():
    return {"message": "SentinelSecure LLM Service is running."}

# The user removed the main block to run the server. I am adding it back.
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)