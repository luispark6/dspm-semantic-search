from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base, Mapped, mapped_column
from sqlalchemy import select, Index, text, and_
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP, TEXT, INTEGER
from datetime import datetime
from typing import Optional, List
from openai import AsyncOpenAI
import json
import os
import uuid
import io

import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt

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
        
        CRITICAL: If the user mentions ANY IP addresses, time ranges, users, or other DSPM log attributes in their request (regardless of whether they want a report, analysis, or simple query), this tool MUST be used to extract those parameters first.
        
        """,
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

                "graph_type": {
                    "type": "string",
                    "enum": ["scatter_plot", "bar_graph", "pie_chart"],
                    "description": "If the user desires a graph of some sort, set graph_type to one of the following: [scatter_plot, bar_graph, pie_chart]"
                },


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



OPENAPI_KEY = os.environ["OPENAPI_KEY"]
client = AsyncOpenAI(api_key=OPENAPI_KEY)



Base = declarative_base()

class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    log_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    system: Mapped[str] = mapped_column(TEXT, nullable=True)
    severity: Mapped[str] = mapped_column(TEXT, nullable=True)
    data_asset: Mapped[str] = mapped_column(TEXT, nullable=True)
    data_classification: Mapped[str] = mapped_column(TEXT, nullable=True)
    sensitivity_score: Mapped[int] = mapped_column(INTEGER, nullable=True)
    location: Mapped[str] = mapped_column(TEXT, nullable=True)
    event_type: Mapped[str] = mapped_column(TEXT, nullable=True)
    action: Mapped[str] = mapped_column(TEXT, nullable=True)
    status: Mapped[str] = mapped_column(TEXT, nullable=True)
    user_email: Mapped[str] = mapped_column(TEXT, nullable=True)
    role: Mapped[str] = mapped_column(TEXT, nullable=True)
    source_ip: Mapped[str] = mapped_column(TEXT, nullable=True)
    device: Mapped[str] = mapped_column(TEXT, nullable=True)
    policy_triggered: Mapped[str] = mapped_column(TEXT, nullable=True)
    risk_score: Mapped[int] = mapped_column(INTEGER, nullable=True)
    threat_type: Mapped[str] = mapped_column(TEXT, nullable=True)
    content: Mapped[str] = mapped_column(TEXT, nullable=False)
    embedding: Mapped[str] = mapped_column(TEXT, nullable=False)  

    __table_args__ = (
        Index("documents_timestamp_idx", "timestamp"),
        Index("documents_ip_idx", "source_ip"),

    )

POSTGRES_USER = os.environ["POSTGRES_USER"]
POSTGRES_PASSWORD = os.environ["POSTGRES_PASSWORD"]
engine = create_async_engine(
    f"postgresql+asyncpg://{POSTGRES_USER}:{POSTGRES_PASSWORD}@postgres:5432/ragdb",
    echo=True,
    future=True,
)

# High Level ORM use
async_session = sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


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









@asynccontextmanager
async def lifespan(app: FastAPI):
    #dont use async session because low level creation
    async with engine.begin() as conn:
        await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector;"))
        await conn.run_sync(Base.metadata.create_all)
        # ##### Dummy Data ######

        # Insert dummy data using a proper async session
    # async with AsyncSession(engine) as session:
    #     with open("dspm_logs.json", "r") as f:
    #         logs = json.load(f)

    #     for log in logs:
    #         content = format_hybrid(log)
    #         embedding = await get_embedding(content)
            
    #         # Use proper parameter binding with named parameters
    #         await session.execute(
    #             text("""
    #             INSERT INTO documents (
    #                 log_id, timestamp, system, severity, data_asset, data_classification,
    #                 sensitivity_score, location, event_type, action, status, user_email, role,
    #                 source_ip, device, policy_triggered, risk_score, threat_type, content, embedding
    #             )
    #             VALUES (
    #                 :log_id, :timestamp, :system, :severity, :data_asset, :data_classification,
    #                 :sensitivity_score, :location, :event_type, :action, :status, :user_email, :role,
    #                 :source_ip, :device, :policy_triggered, :risk_score, :threat_type, :content, :embedding
    #             )
    #             """),
    #             {
    #                 "log_id": log["log_id"],
    #                 "timestamp": datetime.fromisoformat(log["timestamp"].replace("Z", "+00:00")),
    #                 "system": log["system"],
    #                 "severity": log["severity"],
    #                 "data_asset": log["data_asset"],
    #                 "data_classification": log["data_classification"],
    #                 "sensitivity_score": log["sensitivity_score"],
    #                 "location": log["location"],
    #                 "event_type": log["event_type"],
    #                 "action": log["action"],
    #                 "status": log["status"],
    #                 "user_email": log["user"],  # Assuming this maps to user_email
    #                 "role": log["role"],
    #                 "source_ip": log["source_ip"],
    #                 "device": log["device"],
    #                 "policy_triggered": log["policy_triggered"],
    #                 "risk_score": log["risk_score"],
    #                 "threat_type": log["threat_type"],
    #                 "content": content,
    #                 "embedding": str(embedding)  
    #             }
    #         )
        
    #     await session.commit()






    
    yield
    await engine.dispose()


app = FastAPI(lifespan=lifespan)


def create_scatter_plot(scatter_json):
    plt.figure(figsize=(10, 6))
    plt.scatter(scatter_json['x_values'], scatter_json['y_values'])
    plt.xlabel(scatter_json['x_name'])
    plt.ylabel(scatter_json['y_name'])
    plt.title(scatter_json['title'])
    plt.xticks(rotation=45)
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=100)
    buf.seek(0)
    plt.close()
    return buf



def create_pie_chart(pie_json):
    plt.figure(figsize=(10, 6))
    plt.pie(pie_json['values'], labels=pie_json['labels'], autopct='%1.1f%%')
    
    if 'title' in pie_json:
        plt.title(pie_json['title'])
    
    # Ensure the chart is properly laid out
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=100)
    buf.seek(0)
    plt.close()
    return buf


    




def create_bar_graph(bar_json):
    plt.figure(figsize=(10, 6))
    plt.bar(bar_json['x_values'], bar_json['y_values'])
    plt.xlabel(bar_json['x_name'])
    plt.ylabel(bar_json['y_name'])
    plt.title(bar_json['title'])
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=100)
    buf.seek(0)
    plt.close()
    return buf
    

    



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

    new_doc = Document(
        log_id=uuid.UUID(log_dict["log_id"]),
        timestamp=datetime.fromisoformat(log_dict["timestamp"].replace("Z", "+00:00")),
        system=log_dict["system"],
        severity=log_dict["severity"],
        data_asset=log_dict["data_asset"],
        data_classification=log_dict["data_classification"],
        sensitivity_score=log_dict["sensitivity_score"],
        location=log_dict["location"],
        event_type=log_dict["event_type"],
        action=log_dict["action"],
        status=log_dict["status"],
        user_email=log_dict["user"],
        role=log_dict["role"],
        source_ip=log_dict["source_ip"],
        device=log_dict["device"],
        policy_triggered=log_dict["policy_triggered"],
        risk_score=log_dict["risk_score"],
        threat_type=log_dict["threat_type"],
        content=content,
        embedding=str(embedding),
    )

    async with async_session() as session:
        session.add(new_doc)
        await session.commit()

    return {"Successfully added DSPM Log": log_dict["log_id"]}




@app.get("/ask")
async def ask(query: str, limit: int = 100, rag: bool=False):
    try:
        response = await client.chat.completions.create(
            model="gpt-4.1",  
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
    except Exception as e:
        return {"Error": "Failed to parse queries: {e}"}

    if not response.choices[0].message.tool_calls:
        return {"error": "No valid information for postgress query"}
    tool_call = response.choices[0].message.tool_calls[0]
    try:
        parsed = json.loads(tool_call.function.arguments)
    except Exception as e:
        return {"Error": "Arguments are not in valid json format: {e}"}

        



    return await pg_query(
        query=query,
        limit=limit,
        start=parsed.get("start"),
        end=parsed.get("end"),
        graph_type = parsed.get("graph_type"),
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
    graph_type: Optional[str] = None,
    source_ip_list: Optional[List[str]] = None,
    user_email_list: Optional[List[str]] = None,
    event_type_list: Optional[List[str]] = None,
    threat_type_list: Optional[List[str]] = None,
    severity_list: Optional[List[str]] = None,
    rag: bool = False,
):
    filters = []

    if source_ip_list: #source_ip in list of ips
        filters.append(Document.source_ip.in_(source_ip_list))
    if user_email_list:
        filters.append(Document.user_email.in_(user_email_list))
    if event_type_list:
        filters.append(Document.event_type.in_(event_type_list))
    if threat_type_list:
        filters.append(Document.threat_type.in_(threat_type_list))
    if severity_list:
        filters.append(Document.severity.in_(severity_list))

    if start and end:
        filters.append(Document.timestamp.between(
            datetime.fromisoformat(start.replace("Z", "+00:00")),
            datetime.fromisoformat(end.replace("Z", "+00:00"))
        ))
    elif start:
        filters.append(Document.timestamp >= datetime.fromisoformat(start.replace("Z", "+00:00")))
    elif end:
        filters.append(Document.timestamp <= datetime.fromisoformat(end.replace("Z", "+00:00")))

    #* parses to individual args
    stmt = (
        select(Document)
        .where(and_(*filters)) if filters else select(Document)
    )
    stmt = stmt.order_by(Document.timestamp.desc()).limit(limit)

    try:
        async with async_session() as session:
            result = await session.execute(stmt)
            rows = result.scalars().all()
    except Exception as e:
        return {"Error": "Failed to get pg queries: {e}"}


    if not rag:
        return [row.__dict__ for row in rows]

    if not graph_type:
        prompt = f"""
**Task**: Analyze the provided DSPM log entries and respond to the user's query.
CRITICAL, avoid speculation and cite specific logs. 

**DSPM Log Entries ({len(rows)} total):**
"""
        for i, row in enumerate(rows, 1):
            prompt += f"\n-------\n{row.content}\n"

        prompt += f"\n**User Query:** {query}\n"

        async def event_generator(prompt: str):
            try:
                stream = await client.chat.completions.create(
                    model="gpt-4.1",
                    messages=[{"role": "user", "content": prompt}],
                    stream=True,
                )

                async for event in stream:
                    try:
                        if event.choices[0].delta.content is not None:
                            yield event.choices[0].delta.content
                    except Exception as e:
                        # Handle unexpected issues in individual events
                        yield f"\n[Error parsing event: {str(e)}]\n"

            except Exception as e:
                # Handle connection / API errors gracefully
                yield f"\n[Streaming error: {str(e)}]\n"

        

        return StreamingResponse(event_generator(), media_type="text/plain")


    if graph_type == "bar_graph":
        prompt ="""
**Role:** You are a data parsing expert specializing in DSPM (Data Security Posture Management) log analysis.

**Task:** Extract specific data from provided DSPM log entries to construct a bar graph based on a user's request.

**Input:**
1.  `dspm_logs`: A list of DSPM log entries (JSON objects).
2.  `user_prompt`: A natural language description of what to plot (e.g., "Show me failed logins by user" or "Graph data accesses per resource type").

**Output Format:** Return **only** a valid JSON object in this exact structure:
{
    'x_values': ['CategoryA', 'CategoryB', 'CategoryC'],
    'x_name': 'Descriptive X-Axis Label',
    'y_values': [10, 15, 7],
    'y_name': 'Descriptive Y-Axis Label'
    'title': 'title of the graph'
}



"""


        for i, row in enumerate(rows, 1):
            prompt += f"\n-------\n{row.content}\n"
        prompt += f"\n**User Query:** {query}\n"

        try:
            response = await client.chat.completions.create(
                model="gpt-4.1",
                messages=[{"role": "user", "content": prompt}],
                temperature=0 
            )
        except Exception as e:
            return {"Error": "Failed to call model: {e}"}


        try:
            bar_json = json.loads(response.choices[0].message.content)
            required_keys = ['x_values', 'x_name', 'y_values', 'y_name']
            if not all(key in bar_json for key in required_keys):
                raise ValueError("Invalid graph JSON structure")
            
            if 'title' not in bar_json:
                bar_json['title'] = f"DSPM Analysis: {query[:50]}..."
            image_buffer = create_bar_graph(bar_json)
            # Return the image as a streaming response
            return StreamingResponse(
                content=image_buffer,
                media_type="image/png",
                headers={
                    "Content-Disposition": f"attachment; filename=dspm_graph_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                }
            )
        except json.JSONDecodeError:
                return {"error": "Failed to parse graph specification from AI"}
        except Exception as e:
            return {"error": f"Failed to create graph: {bar_json}"}

    if graph_type == "scatter_plot":

        prompt= """
**Role:** You are a data parsing expert specializing in DSPM (Data Security Posture Management) log analysis.

**Task:** Extract specific data from provided DSPM log entries to construct a scatter plot based on a user's request.

**Input:**
1.  `dspm_logs`: A list of DSPM log entries (JSON objects).
2.  `user_prompt`: A natural language description of what to plot (e.g., "Show me failed logins by user" or "Graph data accesses per resource type").

**Output Format:** Return **only** a valid JSON object in this exact structure:
{
    'x_values': [9, 7, 3],
    'x_name': 'Descriptive X-Axis Label',
    'y_values': [10, 15, 7],
    'y_name': 'Descriptive Y-Axis Label'
    'title': 'title of the graph'
}
"""
        for i, row in enumerate(rows, 1):
            prompt += f"\n-------\n{row.content}\n"
        prompt += f"\n**User Query:** {query}\n"

        try:
            response = await client.chat.completions.create(
                model="gpt-4.1",
                messages=[{"role": "user", "content": prompt}],
                temperature=0 
            )
        except Exception as e:
            return {"Error": "Failed to call model: {e}"}


        try:
            scatter_json = json.loads(response.choices[0].message.content)
            required_keys = ['x_values', 'x_name', 'y_values', 'y_name']
            if not all(key in scatter_json for key in required_keys):
                raise ValueError("Invalid graph JSON structure")
            
            if 'title' not in scatter_json:
                scatter_json['title'] = f"DSPM Analysis: {query[:50]}..."
            image_buffer = create_scatter_plot(scatter_json)
            # Return the image as a streaming response
            return StreamingResponse(
                content=image_buffer,
                media_type="image/png",
                headers={
                    "Content-Disposition": f"attachment; filename=dspm_graph_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                }
            )
        except json.JSONDecodeError:
                return {"error": "Failed to parse graph specification from AI"}
        except Exception as e:
            return {"error": f"Failed to create graph: {str(e)}"}







    if graph_type == "pie_chart":

        prompt= """
**Role:** You are a data parsing expert specializing in DSPM (Data Security Posture Management) log analysis.

**Task:** Extract specific data from provided DSPM log entries to construct a pie chart based on a user's request.

**Input:**
1.  `dspm_logs`: A list of DSPM log entries (JSON objects).
2.  `user_prompt`: A natural language description of what to plot (e.g., "Show me failed logins by user" or "Graph data accesses per resource type").

**Output Format:** Return **only** a valid JSON object in this exact structure:
{
    'labels': ['section1', 'section2', 'section3'],
    'values': [10, 15, 7],
    'title': 'title of the pie chart'
}
"""
        for i, row in enumerate(rows, 1):
            prompt += f"\n-------\n{row.content}\n"
        prompt += f"\n**User Query:** {query}\n"

        try:
            response = await client.chat.completions.create(
                model="gpt-4.1",
                messages=[{"role": "user", "content": prompt}],
                temperature=0 
            )
        except Exception as e:
            return {"Error": "Failed to call model: {e}"}


        try:
            pie_json = json.loads(response.choices[0].message.content)
            required_keys = ['values', 'labels', 'title']
            if not all(key in pie_json for key in required_keys):
                raise ValueError("Invalid graph JSON structure")
            
            if 'title' not in pie_json:
                pie_json['title'] = f"DSPM Analysis: {query[:50]}..."
            image_buffer = create_pie_chart(pie_json)
            # Return the image as a streaming response
            return StreamingResponse(
                content=image_buffer,
                media_type="image/png",
                headers={
                    "Content-Disposition": f"attachment; filename=dspm_graph_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                }
            )
        except json.JSONDecodeError:
                return {"error": "Failed to parse graph specification from AI"}
        except Exception as e:
            return {"error": f"Failed to create graph: {str(e)}"}








