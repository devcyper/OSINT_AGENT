from langgraph.store.postgres import PostgresStore
from langgraph.graph import StateGraph
from state import OSINTState
from dataclasses import dataclass

@dataclass
class Context:
    user_id: str

DB_URI = "postgresql://postgres:postgres@localhost:5442/postgres?sslmode=disable"


    