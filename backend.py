from fastapi import FastAPI
import chromadb
from chromadb import DEFAULT_TENANT, DEFAULT_DATABASE, Settings
import uuid
from pydantic import BaseModel, Field

app = FastAPI()

class ThreatLogEntry(BaseModel):
    date: str = Field(..., description="Date of the threat event", example="2024-01-15 10:30:45")
    IP: str = Field(..., description="IP address involved in the threat", example="192.168.1.100")
    threat: str = Field(..., description="Description of the threat", example="SQL Injection Attempt")
    origin: str = Field(..., description="Origin of the threat", example="External")
    dest: str = Field(..., description="Destination/target of the threat", example="Web Server")

@app.post("/add_logs")
async def add_logs(log_data: ThreatLogEntry):

    client = chromadb.HttpClient(
        host = "chromaDB",
        port = 8000,
        settings = Settings(allow_reset=True, anonymized_telemetry=False),
        headers=None,
        tenant = DEFAULT_TENANT,
        database = DEFAULT_DATABASE,
    )

    collection = client.get_or_create_collection(
        name="dspm_logs",
        metadata={"hnsw:space": "cosine", "description": "Storage for threat logs"} 
    )

    log_id = f"log_{uuid.uuid4().hex}"

    content = f"Date: {log_data.date}, IP: {log_data.IP}, Threat: {log_data.threat}, origin: {log_data.origin}, dest: {log_data.dest}"

    metadata = {
        "date": log_data.date,       # Now you can filter by exact date
        "IP": log_data.IP,           # Now you can filter by 
        "threat": log_data.threat,   
        "origin": log_data.origin,
        "dest": log_data.dest,
    }
    collection.add(
        documents=[content],      
        metadatas=[metadata],     
        ids=[log_id]              
        )
    


    return {"Sucessfully added DSPM Query": content}