# OSINT Agent

An autonomous open-source intelligence (OSINT) recon agent built with LangGraph that performs parallel reconnaissance across multiple data sources.

## Features

- **DNS Enumeration**: A, MX, NS, TXT, CNAME, AAAA records + reverse DNS + zone transfer attempt
- **WHOIS Lookup**: Domain registration data (registrar, dates, registrant info)
- **Shodan Integration**: Open ports, banners, CVEs, and service information
- **Email Breach Check**: HaveIBeenPwned breach detection + MX validation
- **Social Recon**: Username presence across platforms + GitHub profile enumeration

## Architecture

```
┌─────────────┐
│  Supervisor │ ──> classifies target & selects tasks
└──────┬──────┘
       │
       ├──► DNS Agent
       ├──► WHOIS Agent
       ├──► Shodan Agent
       ├──► Email Agent
       └──► Social Agent
              │
              ▼
       ┌─────────────┐
       │ Aggregator │ ──> compiles final markdown report
       └────────────┘
```

## Quick Start

### Prerequisites

- Python 3.12+
- PostgreSQL (for state persistence)
- Ollama running locally with `qwen3` model

### Setup

```bash
# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### Environment Variables

Create a `.env` file:

```env
HIBP_API_KEY=your_hibp_api_key
SHODAN_API_KEY=your_shodan_api_key
```

### Run

```bash
python graph.py --target example.com
```

## Output

The agent outputs a structured markdown intelligence report:

- Executive Summary
- Technical Findings
- Attack Surface
- Recommendations

## Configuration

- **LLM**: Uses Ollama with `qwen3:latest` by default
- **Database**: PostgreSQL at `localhost:5432`
- **Graph Persistence**: Checkpointing enabled via PostgresSaver

