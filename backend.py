from fastapi import FastAPI
import uuid
from pydantic import BaseModel, Field
from contextlib import asynccontextmanager
import json
import asyncpg
from openai import AsyncOpenAI
from typing import Optional, List
from datetime import datetime
from openai.types.chat import ChatCompletionToolParam
from fastapi.responses import StreamingResponse



dspm_tool = {
    "type": "function",
    "function": {
        "name": "parse_dspm_query",
        "description": """Parse ANY natural language request about DSPM logs into structured fields for data retrieval. 
        
        This tool should be used for ALL requests involving DSPM logs, including:
        - Direct queries: "show me logs from IP X"
        - Analysis requests: "analyze logs for IP X" 
        - Report generation: "write a summary report of logs from IP X"
        - Comparisons: "compare logs between IP X and Y"
        - Investigations: "investigate suspicious activity from IP X"
        
        CRITICAL: If the user mentions ANY IP addresses, time ranges, users, or other DSPM log attributes 
        in their request (regardless of whether they want a report, analysis, or simple query), 
        this tool MUST be used to extract those parameters first.""",
        "parameters": {
            "type": "object", 
            "properties": {
                "severity_list": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of severity types: low, medium, high, critical"
                },
                "event_type_list": {
                    "type": "array", 
                    "items": {"type": "string"},
                    "description": "List of event types to filter by"
                },
                "user_email_list": {
                    "type": "array",
                    "items": {"type": "string"}, 
                    "description": "List of user email addresses mentioned"
                },
                "source_ip_list": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "CRITICALLY IMPORTANT: Extract ALL IP addresses mentioned ANYWHERE in the user query. This includes IPs mentioned in any context - comparisons, examples, filters, etc. If the user says 'from 192.168.1.1 and 10.0.0.1' or '192.168.1.1 or 10.0.0.1' or mentions multiple IPs in any way, include ALL of them. Example inputs and expected outputs: 'logs from 192.168.1.1 and 10.0.0.1' -> ['192.168.1.1', '10.0.0.1'], 'compare 1.1.1.1 with 2.2.2.2' -> ['1.1.1.1', '2.2.2.2']"
                },
                "threat_type_list": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Threat types: ransomware, anomalous_access, misconfiguration, insider_threat, data_exfiltration_attempt"
                },
                "request_type": {
                    "type": "string",
                    "enum": ["query", "report", "analysis", "comparison", "investigation"],
                    "description": "Type of request: 'query' for simple data retrieval, 'report' for summary reports, 'analysis' for detailed analysis, 'comparison' for comparing data, 'investigation' for security investigations"
                },
                "system": {"type": "string"},
                "data_asset": {"type": "string"},
                "data_classification": {"type": "string"},
                "sensitivity_score": {"type": "integer"},
                "location": {"type": "string"},
                "action": {"type": "string"},
                "status": {"type": "string"},
                "role": {"type": "string"},
                "device": {"type": "string"},
                "policy_triggered": {"type": "string"},
                "risk_score": {
                    "type": "integer",
                    "description": "Risk score 0-100"
                },
                "start": {
                    "type": "string",
                    "description": "Start timestamp in ISO 8601 format with timezone, e.g. 2025-09-08T02:06:48.800843+00:00"
                },
                "end": {
                    "type": "string", 
                    "description": "End timestamp in ISO 8601 format with timezone, e.g. 2025-09-08T02:06:48.800843+00:00"
                }
            }
        }
    }
}

client = AsyncOpenAI(api_key="OPENAPI KEY")  


def format_hybrid(log: dict) -> str:
    """Format DSPM log entry into hybrid format for embeddings."""
    natural_text = (
        f"On {log['timestamp']}, system {log['system']} detected a {log['severity']} "
        f"event involving data asset {log['data_asset']} classified as {log['data_classification']}. "
        f"The action '{log['action']}' by user_email {log['user']} (role {log['role']}) "
        f"from IP {log['source_ip']} on device {log['device']} was {log['status']}. "
        f"Policy triggered: {log['policy_triggered']}. "
        f"Risk score: {log['risk_score']}, Threat type: {log['threat_type']}."
    )

    structured_json = json.dumps(log, ensure_ascii=False)
    return f"{natural_text}\n[Structured: {structured_json}]"


async def get_embedding(text: str) -> list[float]:
    """Generate embeddings using OpenAI API"""
    response = await client.embeddings.create(
        model="text-embedding-3-small",
        input=text
    )
    return response.data[0].embedding


async def get_db_pool():
    """Create async database connection pool"""
    return await asyncpg.create_pool(
        database="ragdb",
        user="postgres",
        password="postgres",
        host="postgres",
        port=5432,
        min_size=5,
        max_size=20,
        command_timeout=60
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool

    db_pool = await get_db_pool()

    async with db_pool.acquire() as conn:

        await conn.execute("CREATE EXTENSION IF NOT EXISTS vector;")
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id bigserial PRIMARY KEY,
                log_id UUID,
                timestamp TIMESTAMPTZ,
                system TEXT,
                severity TEXT,
                data_asset TEXT,
                data_classification TEXT,
                sensitivity_score INT,
                location TEXT,
                event_type TEXT,
                action TEXT,
                status TEXT,
                user_email TEXT,
                role TEXT,
                source_ip TEXT,
                device TEXT,
                policy_triggered TEXT,
                risk_score INT,
                threat_type TEXT,
                content TEXT,
                embedding vector(1536)
            );
        """)

        await conn.execute("""
            CREATE INDEX IF NOT EXISTS documents_embedding_hnsw_idx
            ON documents
            USING hnsw (embedding vector_cosine_ops);
        """)

        await conn.execute("CREATE INDEX IF NOT EXISTS documents_timestamp_idx ON documents (timestamp);")
        await conn.execute("CREATE INDEX IF NOT EXISTS documents_ip_idx ON documents (source_ip);")



# ##### Dummy Data ######

    # with open("dspm_logs.json", "r") as f:
    #     logs = json.load(f)


    # for log in logs:
    #     content = format_hybrid(log)
    #     embedding = await get_embedding(content)
    #     async with db_pool.acquire() as conn:
    #         await conn.execute(
    #             """
    #             INSERT INTO documents (
    #                 log_id, timestamp, system, severity, data_asset, data_classification,
    #                 sensitivity_score, location, event_type, action, status, user_email, role,
    #                 source_ip, device, policy_triggered, risk_score, threat_type, content, embedding
    #             )
    #             VALUES (
    #                 $1, $2::timestamptz, $3, $4, $5, $6,
    #                 $7, $8, $9, $10, $11, $12, $13,
    #                 $14, $15, $16, $17, $18, $19, $20::vector
    #             )
    #             """,
    #             log["log_id"],
    #             datetime.fromisoformat(log["timestamp"].replace("Z", "+00:00")),
    #             log["system"],
    #             log["severity"],
    #             log["data_asset"],
    #             log["data_classification"],
    #             log["sensitivity_score"],
    #             log["location"],
    #             log["event_type"],
    #             log["action"],
    #             log["status"],
    #             log["user"],
    #             log["role"],
    #             log["source_ip"],
    #             log["device"],
    #             log["policy_triggered"],
    #             log["risk_score"],
    #             log["threat_type"],
    #             content,
    #             str(embedding)
    #         )



##### Dummy Data ######


    yield
    if db_pool:
        await db_pool.close()


app = FastAPI(lifespan=lifespan)


class DSPMLogEntry(BaseModel):
    log_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str
    system: str
    severity: str
    data_asset: str
    data_classification: str
    sensitivity_score: int
    location: str
    event_type: str
    action: str
    status: str
    user: str
    role: str
    source_ip: str
    device: str
    policy_triggered: str
    risk_score: int
    threat_type: str


@app.post("/add_logs")
async def add_logs(log_data: DSPMLogEntry):
    log_dict = log_data.dict()
    content = format_hybrid(log_dict)
    embedding = await get_embedding(content)



    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO documents (
                log_id, timestamp, system, severity, data_asset, data_classification,
                sensitivity_score, location, event_type, action, status, user_email, role,
                source_ip, device, policy_triggered, risk_score, threat_type, content, embedding
            )
            VALUES (
                $1, $2::timestamptz, $3, $4, $5, $6,
                $7, $8, $9, $10, $11, $12, $13,
                $14, $15, $16, $17, $18, $19, $20::vector
            )
            """,
            log_dict["log_id"],
            datetime.fromisoformat(log_dict["timestamp"].replace("Z", "+00:00")),
            log_dict["system"],
            log_dict["severity"],
            log_dict["data_asset"],
            log_dict["data_classification"],
            log_dict["sensitivity_score"],
            log_dict["location"],
            log_dict["event_type"],
            log_dict["action"],
            log_dict["status"],
            log_dict["user"],
            log_dict["role"],
            log_dict["source_ip"],
            log_dict["device"],
            log_dict["policy_triggered"],
            log_dict["risk_score"],
            log_dict["threat_type"],
            content,
            str(embedding)
        )

    return {"Successfully added DSPM Log": log_dict["log_id"]}



@app.get("/ask")
async def ask(query: str, limit: int = 100, rag: bool=False):
    response = await client.chat.completions.create(
        model="gpt-4o-mini",  
        messages=[
            {
                "role": "system", 
                "content": """You are a DSPM log analysis assistant. For ANY request involving DSPM logs, 
                you MUST first use the parse_dspm_query tool to extract relevant parameters, 
                even if the user is asking for reports, analysis, or summaries. 
                
                The tool should be used for ALL these request types:
                - "show me logs..." 
                - "write a report about..."
                - "analyze logs from..."
                - "summarize activity for..."
                - "investigate..." 
                - "compare logs between..."
                
                Always use the tool first to get the data, then provide the appropriate response format."""
            },
            {"role": "user", "content": query}],
        tools=[dspm_tool],
        tool_choice="auto",
    )
    if not response.choices[0].message.tool_calls:
        return {"error": "No valid information for postgress query"}
    tool_call = response.choices[0].message.tool_calls[0]
    parsed = json.loads(tool_call.function.arguments)


    print(parsed)
    return await pg_query(
        query=query,
        limit=limit,
        start=parsed.get("start"),
        end=parsed.get("end"),
        source_ip_list=parsed.get("source_ip_list"),
        user_email_list=parsed.get("user_email_list"),
        event_type_list = parsed.get("event_type_list"),
        threat_type_list = parsed.get("threat_type_list"),
        severity_list = parsed.get("severity_list"),
        rag=rag
    )



async def pg_query(
    query: str,
    limit: int = 100, 
    start: Optional[str] = None,       
    end: Optional[str] = None,
    source_ip_list: Optional[List[str]] = None, 
    user_email_list: Optional[List[str]] = None,
    event_type_list: Optional[List[str]] = None,
    threat_type_list: Optional[List[str]] = None,
    severity_list:  Optional[List[str]] = None,
    rag: bool=False
):
    #2025-09-08T02:06:48.800843+00:00

    query_embedding = await get_embedding(query)
    filters = []
    params = [limit]
    idx = 2
    if source_ip_list:
        if len(source_ip_list) == 1:
            filters.append(f"source_ip = ${idx}")
            params.append(source_ip_list[0])
            idx += 1
        else:
            placeholders = ", ".join([f"${idx + i}" for i in range(len(source_ip_list))])
            filters.append(f"source_ip IN ({placeholders})")
            params.extend(source_ip_list)
            idx += len(source_ip_list)
    if user_email_list:
        if len(user_email_list) == 1:
            filters.append(f"user_email = ${idx}")
            params.append(user_email_list[0])
            idx += 1
        else:
            placeholders = ", ".join([f"${idx + i}" for i in range(len(user_email_list))])
            filters.append(f"user_email IN ({placeholders})")
            params.extend(user_email_list)
            idx += len(user_email_list)

    if event_type_list:
        if len(event_type_list)==1:
            filters.append(f"event_type = ${idx}")
            params.append(event_type_list[0])
            idx += 1
        else:
            placeholders = ", ".join([f"${idx + i}" for i in range(len(event_type_list))])
            filters.append(f"event_type IN ({placeholders})")
            params.extend(event_type_list)
            idx += len(event_type_list)
    if threat_type_list:
        if len(threat_type_list)==1:
            filters.append(f"threat_type = ${idx}")
            params.append(threat_type_list[0])
            idx += 1
        else:
            placeholders = ", ".join([f"${idx + i}" for i in range(len(threat_type_list))])
            filters.append(f"threat_type IN ({placeholders})")
            params.extend(threat_type_list)
            idx += len(threat_type_list)
    if severity_list:
        if len(severity_list)==1:
            filters.append(f"severity = ${idx}")
            params.append(severity_list[0])
            idx += 1
        else:
            placeholders = ", ".join([f"${idx + i}" for i in range(len(severity_list))])
            filters.append(f"severity IN ({placeholders})")
            params.extend(severity_list)
            idx += len(severity_list)


    if start and end:
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
        filters.append(f"timestamp BETWEEN ${idx}::timestamptz AND ${idx+1}::timestamptz")
        params.extend([start_dt, end_dt])
        idx += 2
    elif start:
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        filters.append(f"timestamp >= ${idx}::timestamptz")
        params.append(start_dt)
        idx += 1
    elif end:
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
        filters.append(f"timestamp <= ${idx}::timestamptz")
        params.append(end_dt)
        idx += 1


    where_clause = " AND ".join(filters)
    if where_clause:
        where_clause = "WHERE " + where_clause
    sql = f"""
        SELECT id, log_id, content
        FROM documents
        {where_clause}
        ORDER BY timestamp DESC
        LIMIT $1;
    """
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(sql, *params)

    if not rag:
        return [r for r in rows]




    # sql = f"""
    #     SELECT id, log_id, content, embedding <-> $1::vector AS distance
    #     FROM documents
    #     {where_clause}
    #     ORDER BY embedding <-> $1::vector
    #     LIMIT $2;
    # """


    prompt = f"""
**Task**: Analyze the provided DSPM log entries and respond to the user's query based strictly on observable data patterns and factual log content.
Do not make any assumptions that may mislead the user. Use the observable data to suggest answers to the user's query.
**Analysis Approach**: Evidence-based analysis using only the provided log data

**Instructions:**
1. Extract factual information directly from the log entries
3. Identify observable, quantifiable(if possible) patterns in the data
4. Construct an answer to the user based of the observed data
5. Cite specific log entries at the end of the response
6. Avoid speculation beyond what the data directly demonstrates

**DSPM Log Entries for Analysis ({len(rows)} total):**
"""

    for i, row in enumerate(rows, 1):
        prompt += f"\n-------\n{str(row)}\n"

    prompt += f"""

    **User Query:**
    {query}

    Please provide a response that addresses the query directly without speculation and cites relevant log evidence at the end.
    """
    print(prompt)

    async def event_generator():
        stream = await client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            stream=True,
        )
        async for event in stream:
            if event.choices[0].delta.content is not None:
                yield event.choices[0].delta.content

    return StreamingResponse(event_generator(), media_type="text/plain")

        



    #53.39.183.237
    #206.159.153.98