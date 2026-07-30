# Built-in Rules

aipostex ships with 5 embedded rule packs covering AI credential discovery, configuration files, local LLM artifacts, vector database data, and core assessment patterns.

## Rule Packs

### api_keys.yaml -- AI Credentials

Detects API keys and tokens for AI services in configuration and source files.

| Rule | Severity | Patterns |
|---|---|---|
| OpenAI API Key | High | `sk-[a-zA-Z0-9]{20,}`, `OPENAI_API_KEY` assignment |
| Anthropic API Key | High | `sk-ant-[a-zA-Z0-9\-]{20,}`, `ANTHROPIC_API_KEY` assignment |
| Hugging Face Token | High | `hf_[a-zA-Z0-9]{20,}`, `HF_TOKEN` assignment, cache token path |
| Google AI / Vertex API Key | High | `GOOGLE_API_KEY` assignment, `application_default_credentials.json` |
| Cohere API Key | High | `COHERE_API_KEY` assignment |
| Replicate API Token | High | `REPLICATE_API_TOKEN` with `r8_` prefix |
| Mistral API Key | High | `MISTRAL_API_KEY` assignment |
| Groq API Key | High | `GROQ_API_KEY` with `gsk_` prefix |
| AWS Bedrock/SageMaker Credentials | High | `AKIA` prefix AWS access key ID |
| Pinecone API Key | High | `PINECONE_API_KEY` assignment |

### mcp_configs.yaml -- MCP Configurations

Detects MCP server configuration files for various clients.

| Rule | Severity | Patterns |
|---|---|---|
| Claude Desktop MCP Config | High | `claude_desktop_config.json` in Claude paths |
| VS Code MCP Settings | High | `settings.json` with `mcpServers` content |
| Cursor MCP Config | High | `mcp.json` in `.cursor/` or `Cursor/` paths |
| Generic MCP Server Config | Medium | `mcp.json`, `mcp_config.json` with `mcpServers` content |
| MCP Server Source Code | Medium | Python/TypeScript files with MCP server imports |

### local_llm.yaml -- Local LLM Artifacts

Detects local LLM model files, configurations, and Docker AI setups.

| Rule | Severity | Patterns |
|---|---|---|
| Ollama Model Data | Medium | `.ollama/models/` path patterns |
| GGUF Model Files | Medium | `*.gguf` files |
| SafeTensors Model Files | Medium | `*.safetensors` files |
| LM Studio Config | Medium | LM Studio path patterns |
| Docker AI Configuration | Medium | Docker compose files with AI service references |

### vectordb_rag.yaml -- Vector Database & RAG

Detects vector database data, RAG configurations, and Jupyter AI notebooks.

| Rule | Severity | Patterns |
|---|---|---|
| ChromaDB Local Data | Medium | `chroma.sqlite3`, ChromaDB path patterns |
| FAISS Index Files | Medium | `*.faiss`, `*.index` files |
| Weaviate Configuration | Medium | Weaviate config paths |
| Qdrant Data | Medium | Qdrant storage paths |
| LangChain Configuration | Medium | LangChain config files with API key patterns |
| LlamaIndex Configuration | Medium | LlamaIndex config with data connector patterns |
| Jupyter AI Notebooks | Medium | `*.ipynb` with AI library imports |

### core_assessment.yaml -- Core Assessment

Detects fine-tuning data, RAG configurations, and LLMjacking indicators.

| Rule | Severity | Patterns |
|---|---|---|
| Fine-tuning Datasets | Medium | JSONL/CSV files with training data patterns |
| RAG Pipeline Configs | Medium | Config files with chunking/embedding patterns |
| LLMjacking Indicators | High | Proxy configs with AI API forwarding patterns |

## Rule Locations

Built-in rules are embedded from `pkg/discover/rules/`:

```
pkg/discover/rules/
├── api_keys.yaml
├── mcp_configs.yaml
├── local_llm.yaml
├── vectordb_rag.yaml
└── core_assessment.yaml
```

## Listing Rules at Runtime

Rules are loaded automatically by `discover files`. To verify rule loading, use verbose mode:

```bash
./aipostex discover files --path /tmp/test --verbose
```

The summary output shows the count of rules loaded.
