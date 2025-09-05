from fastapi import FastAPI

app = FastAPI()

@app.post("/generate")
async def generate():
    return {"hi": "hello"}