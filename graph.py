import asyncio

from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph, END , START
from memory import Context
from state import OSINTState
from agents.nodes import dns_node ,whois_agent_node, shodan_agent_node, email_agent_node, social_agent_node
from langchain.chat_models import init_chat_model
from langgraph.types import Send
from langgraph.store.postgres import PostgresStore
from dataclasses import dataclass
from langgraph.store.postgres.aio import AsyncPostgresStore  
from langgraph.runtime import Runtime 
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
import uuid
import argparse

llm = init_chat_model("qwen3:latest",model_provider="ollama",base_url="http://localhost:11434")


def supervisor_node(state: OSINTState) -> OSINTState:
    target = state["target"]
    prompt = f"""You are an OSINT supervisor. Given target: {target}

Classify target type and choose which agents to run.
Respond ONLY with JSON:
{{
  "target_type": "domain" | "email" | "ip" | "username",
  "tasks": ["dns", "whois", "shodan", "email", "social"]   // include only relevant ones
}}"""
    import json
    response = llm.invoke([HumanMessage(content=prompt)])
    try:
        parsed = json.loads(response.content.strip())
        return {**state, "target_type": parsed["target_type"], "tasks": parsed["tasks"]}
    except Exception:
        return {**state, "target_type": "domain", "tasks": ["dns", "whois", "shodan"]}


def aggregator_node(state: OSINTState) -> OSINTState:
    all_findings = "\n".join(state.get("findings", []))
    prompt = f"""You are an OSINT report writer. Compile a structured intelligence report for: {state["target"]}

Raw findings from all agents:
{all_findings}

Output a markdown report with sections:
## Executive Summary
## Technical Findings
## Attack Surface
## Recommendations
"""
    response = llm.invoke([HumanMessage(content=prompt)])
    return {**state, "report": response.content}

def route_after_supervisor(state: OSINTState):
    """Fan out to all tasks in parallel via Send (LangGraph ≥ 0.2)."""
    
    task_map = {
        "dns":    "dns_agent",
        "whois":  "whois_agent",
        "shodan": "shodan_agent",
        "email":  "email_agent",
        "social": "social_agent",
    }
    tasks = state.get("tasks", [])
    return [Send(task_map[t], state) for t in tasks if t in task_map]


# ─── Build Graph ──────────────────────────────────────────────────────────────
async def build_osint_graph(store, checkpointer):
    g = StateGraph(OSINTState, context_schema=Context)

    # Nodes
    g.add_node("supervisor",   supervisor_node)
    g.add_node("dns_agent",    dns_node)
    g.add_node("whois_agent",  whois_agent_node)
    g.add_node("shodan_agent", shodan_agent_node)
    g.add_node("email_agent",  email_agent_node)
    g.add_node("social_agent", social_agent_node)
    g.add_node("aggregator",   aggregator_node)

    # Edges
    g.add_edge(START, "supervisor")

    # Conditional fan-out (parallel Send)
    g.add_conditional_edges("supervisor", route_after_supervisor)

    # All agent results converge into aggregator
    for agent in ["dns_agent", "whois_agent", "shodan_agent", "email_agent", "social_agent"]:
        g.add_edge(agent, "aggregator")

    g.add_edge("aggregator", END)

    return g.compile(store=store,checkpointer=checkpointer)
    
DB_URI = "postgresql://postgres:postgres@localhost:5432/postgres?sslmode=disable"
async def main():
    parser = argparse.ArgumentParser(description="OSINT Recon Graph")
    parser.add_argument(
        "--target",
        required=True,
        help="Target domain(s) to recon, e.g. 'example.com mail.example.com'"
    )
    args = parser.parse_args()

    async with (
        AsyncPostgresStore.from_conn_string(DB_URI) as store,
        AsyncPostgresSaver.from_conn_string(DB_URI) as checkpointer,
    ):
        await store.setup()
        await checkpointer.setup()
        graph = await build_osint_graph(store, checkpointer)
        async for chunk in graph.astream(
        {
        "target": args.target,
        "context": Context(user_id=args.target)
        },
        config={"configurable": {"thread_id": args.target}}
    ):
            for node, state in chunk.items():
                print(f"[{node}] processing...")
            
        final = await graph.aget_state(config={"configurable": {"thread_id": args.target}})
        print("\n===== OSINT REPORT =====")
        print(final.values.get("report", "No report generated"))



# ─── Run ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())