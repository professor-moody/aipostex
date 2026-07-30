# Built-in Templates

aipostex ships with **102** embedded vulnerability templates covering AI infrastructure misconfigurations and CVEs across 19 service categories (under `pkg/vulncheck/templates/`).

Templates are classified as **detection** (58) or **exploit** (44). Detection templates run in all modes; exploit templates only run with `--mode full`. See [Scan Modes](../cli/scan-network.md#scan-modes) in `discover network` for details.

## Ollama

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `ollama-auth-001-unauthenticated-api` | Ollama - Unauthenticated API Access | High | Detection | `ollama`, `auth`, `misconfiguration`, `llmjacking` |
| `ollama-enum-002-system-prompt-extraction` | Ollama - System Prompt Extraction | High | **Exploit** | `ollama`, `enumeration`, `system-prompt`, `data-exposure` |
| `ollama-enum-003-model-metadata-surface` | Ollama - Model Metadata Surface | Medium | Detection | `ollama`, `enumeration`, `metadata`, `model-inventory` |
| `ollama-exploit-004-unauthenticated-generate` | Ollama - Unauthenticated Generate | Critical | **Exploit** | `ollama`, `llmjacking`, `inference`, `unauthenticated` |

## MCP

### Infrastructure Exposure

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `mcp-auth-001-unauthenticated-sse` | MCP - Unauthenticated SSE | High | Detection | `mcp`, `auth` |
| `mcp-auth-002-unauthenticated-http` | MCP - Unauthenticated HTTP | High | Detection | `mcp`, `auth` |
| `mcp-auth-003-inspector-exposed` | MCP - Inspector Exposed | High | Detection | `mcp`, `inspector` |
| `mcp-auth-004-dns-rebinding-host-header` | MCP - DNS Rebinding / Host-Header Trust | Medium | Detection | `mcp`, `dns-rebinding` |
| `mcp-auth-005-inspector-api-exposed` | MCP - Inspector API Exposed | High | Detection | `mcp`, `inspector` |
| `mcp-session-001-session-id-in-url` | MCP SSE - Session ID Exposed in URL | Medium | Detection | `mcp`, `session-management`, `sse` |

### Tool Abuse (command execution, files, SSRF)

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `mcp-cmdi-001-execute-command-rce` | MCP Server - Command Injection via Execute Tool | Critical | **Exploit** | `mcp`, `command-injection`, `rce` |
| `mcp-path-001-read-file-traversal` | MCP Server - Path Traversal via File Read Tool | High | **Exploit** | `mcp`, `path-traversal`, `lfi` |
| `mcp-ssrf-001-fetch-url-ssrf` | MCP Server - SSRF via URL Fetch Tool | High | **Exploit** | `mcp`, `ssrf` |

### CVEs and Server-Specific Vulnerabilities

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `cve-2025-65513-fetch-mcp-ssrf` | Fetch MCP Server SSRF (CVE-2025-65513) | Critical | **Exploit** | `mcp`, `ssrf`, `fetch-server`, `cve-2025` |
| `cve-2025-49596-inspector-rce` | MCP Inspector RCE (CVE-2025-49596) | Critical | **Exploit** | `mcp`, `inspector`, `cve-2025`, `rce` |
| `cve-2025-66414-sdk-dns-rebinding` | MCP SDK DNS Rebinding (CVE-2025-66414/66416) | High | Detection | `mcp`, `dns-rebinding`, `cve-2025`, `sdk` |
| `cve-2025-53355-k8s-mcp-command-injection` | Kubernetes MCP Command Injection (CVE-2025-53355) | High | Detection | `mcp`, `kubernetes`, `cve-2025`, `command-injection` |
| `cve-2025-53967-figma-mcp-rce` | Framelink Figma MCP RCE (CVE-2025-53967) | High | Detection | `mcp`, `figma`, `cve-2025`, `rce` |
| `cve-2025-59163-vet-mcp-dns-rebinding` | Vet MCP DNS Rebinding (CVE-2025-59163) | High | Detection | `mcp`, `dns-rebinding`, `cve-2025`, `vet` |
| `tra-2025-36-ms-learn-mcp-ssrf` | Microsoft Learn MCP SSRF (TRA-2025-36) | High | **Exploit** | `mcp`, `ssrf`, `microsoft` |
| `mcp-enum-006-neo4j-mcp-exposed` | Neo4j MCP Cypher Server Exposure (CVE-2025-10193) | High | Detection | `mcp`, `neo4j`, `cve-2025`, `database` |

## Vector Databases

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `chroma-auth-001-unauthenticated-api` | ChromaDB - Unauthenticated API Access | High | Detection | `chromadb`, `auth` |
| `weaviate-auth-001-unauthenticated-api` | Weaviate - Unauthenticated API Access | High | Detection | `weaviate`, `auth` |
| `qdrant-auth-001-unauthenticated-api` | Qdrant - Unauthenticated API Access | High | Detection | `qdrant`, `auth` |
| `chromadb-exploit-001-data-exfil` | ChromaDB - Unauthenticated Data Exfiltration | High | **Exploit** | `vectordb`, `chromadb`, `data-exfiltration`, `rag` |
| `qdrant-exploit-001-data-exfil` | Qdrant - Unauthenticated Data Exfiltration | High | **Exploit** | `vectordb`, `qdrant`, `data-exfiltration` |
| `weaviate-exploit-001-data-exfil` | Weaviate - Unauthenticated Data Exfiltration | High | **Exploit** | `vectordb`, `weaviate`, `data-exfiltration` |
| `milvus-detect-001-unauth-access` | Milvus - Unauthenticated REST API Access | High | Detection | `vectordb`, `milvus`, `unauth`, `data-exposure` |

## Jupyter

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `jupyter-auth-001-no-token` | Jupyter - No Token Required | High | Detection | `jupyter`, `auth` |
| `jupyter-auth-002-terminals-exposed` | Jupyter - Terminals Exposed | High | Detection | `jupyter`, `terminal` |
| `jupyter-enum-003-kernelspecs-exposed` | Jupyter - Kernelspecs Exposed | Medium | Detection | `jupyter`, `enumeration`, `kernelspecs`, `metadata` |
| `jupyter-exploit-001-terminal-rce` | Jupyter - Terminal Creation RCE | Critical | **Exploit** | `jupyter`, `rce`, `terminal`, `code-execution` |
| `jupyter-exploit-002-contents-read` | Jupyter - Unauthenticated Contents Read | High | **Exploit** | `jupyter`, `data-exposure`, `notebook`, `unauthenticated` |

## Ray

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `ray-auth-001-unauthenticated-dashboard` | Ray - Unauthenticated Dashboard | High | Detection | `ray`, `auth`, `dashboard` |
| `ray-auth-002-jobs-api-exposed` | Ray - Jobs API Exposed | High | Detection | `ray`, `auth`, `jobs` |
| `ray-enum-003-cluster-status-exposed` | Ray - Cluster Status Exposed | Medium | Detection | `ray`, `enumeration`, `cluster-status`, `metadata` |
| `ray-exploit-001-job-submit-rce` | Ray - Unauthenticated Job Submission RCE | Critical | **Exploit** | `ray`, `rce`, `job-submission`, `unauthenticated` |
| `ray-exploit-002-job-logs-exposed` | Ray - Unauthenticated Job Logs Exposure | High | **Exploit** | `ray`, `data-exposure`, `job-logs`, `unauthenticated` |

## MLflow

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `mlflow-auth-001-unauthenticated-tracking` | MLflow - Unauthenticated Tracking API | High | Detection | `mlflow`, `auth` |
| `mlflow-enum-002-artifact-surface` | MLflow - Artifact Surface Exposed | Medium | Detection | `mlflow`, `artifacts` |
| `mlflow-enum-003-registry-surface` | MLflow - Registry Surface Exposed | Medium | Detection | `mlflow`, `registry`, `enumeration`, `metadata` |
| `mlflow-exploit-001-artifact-exfil` | MLflow - Unauthenticated Artifact Exfiltration | High | **Exploit** | `mlflow`, `data-exfiltration`, `artifacts`, `unauthenticated` |

## Gradio

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `gradio-auth-001-config-exposed` | Gradio - Config Exposed | Medium | Detection | `gradio`, `config` |
| `gradio-enum-002-callable-api-surface` | Gradio - Callable API Surface | Medium | Detection | `gradio`, `api` |
| `gradio-enum-003-file-capable-surface` | Gradio - File-Capable Surface Exposed | Medium | Detection | `gradio`, `enumeration`, `file-handling`, `config` |
| `gradio-exploit-001-file-read` | Gradio - Arbitrary File Read via /file= | Critical | **Exploit** | `gradio`, `path-traversal`, `file-read`, `data-exfiltration` |

## OpenAI-Compatible

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `openai-auth-001-unauthenticated-inference` | OpenAI-Compatible - Unauthenticated Inference | High | **Exploit** | `openai-compatible`, `auth`, `misconfiguration`, `llmjacking` |
| `openai-auth-002-model-inventory-exposed` | OpenAI-Compatible - Model Inventory Exposed | High | Detection | `openai-compatible`, `auth`, `enumeration`, `llmjacking` |
| `openai-exploit-003-placeholder-key-chat-completions` | OpenAI-Compatible - Placeholder Key Chat Completions | Critical | **Exploit** | `openai-compatible`, `llmjacking`, `inference`, `weak-auth` |
| `openai-exploit-004-tool-injection` | OpenAI-Compatible API - Tool/Function Call Injection | Critical | **Exploit** | `openai-compatible`, `tool-injection`, `function-calling`, `llm-abuse` |
| `openai-exploit-005-prompt-injection` | OpenAI-Compatible API - Prompt Injection and Jailbreak Validation | Critical | **Exploit** | `openai-compatible`, `prompt-injection`, `jailbreak`, `llm-abuse` |

## vLLM

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `vllm-auth-001-unauthenticated-openai-compat` | vLLM - Unauthenticated OpenAI-Compat API | High | Detection | `vllm`, `auth` |

## Hugging Face

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `hf-tgi-auth-001-unauthenticated-api` | Hugging Face Text Generation Inference - Unauthenticated API | High | Detection | `huggingface`, `tgi`, `auth`, `misconfiguration`, `model-serving` |
| `hf-tei-auth-001-unauthenticated-api` | Hugging Face Text Embeddings Inference - Unauthenticated API | High | Detection | `huggingface`, `tei`, `auth`, `misconfiguration`, `model-serving` |
| `hf-tgi-enum-002-metrics-exposed` | Hugging Face TGI - Metrics Exposed | Medium | Detection | `huggingface`, `tgi`, `metrics`, `model-serving` |
| `hf-tei-enum-002-metrics-exposed` | Hugging Face TEI - Metrics Exposed | Medium | Detection | `huggingface`, `tei`, `metrics`, `model-serving` |

## LangChain / LangServe

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `langserve-auth-001-unauthenticated-api` | LangServe - Unauthenticated API Access | High | Detection | `langchain`, `langserve`, `auth`, `misconfiguration` |
| `langserve-enum-001-playground-exposed` | LangServe - Playground Exposed | Medium | Detection | `langchain`, `langserve`, `playground` |
| `langserve-enum-002-schema-exposed` | LangServe - Input Schema Exposed | Medium | Detection | `langchain`, `langserve`, `schema`, `enumeration` |

## LiteLLM

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `litellm-config-001-endpoint-exposure` | LiteLLM - Configuration and Backend Exposure | High | Detection | `litellm`, `openai-compatible`, `auth`, `config-exposure`, `key-aggregation` |

## Agent-to-Agent (A2A)

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `a2a-enum-001-agent-card-exposed` | Agent-to-Agent - Agent Card Exposed | Medium | Detection | `a2a`, `agent`, `enumeration` |

## Kubeflow

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `kubeflow-auth-001-dashboard-unauthenticated` | Kubeflow - Unauthenticated Dashboard Access | High | Detection | `kubeflow`, `auth`, `misconfiguration`, `mlops` |

## TensorFlow Serving

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `tfserving-auth-001-unauthenticated-api` | TensorFlow Serving - Unauthenticated REST API | High | Detection | `tfserving`, `auth`, `misconfiguration`, `model-serving` |
| `tfserving-enum-001-model-status` | TensorFlow Serving - Model Status Disclosure | Medium | Detection | `tfserving`, `enumeration`, `model-serving` |

## NVIDIA Triton

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `triton-auth-001-unauthenticated-api` | NVIDIA Triton Inference Server - Unauthenticated API Access | High | Detection | `triton`, `auth`, `misconfiguration`, `model-serving` |
| `triton-enum-001-model-enumeration` | NVIDIA Triton Inference Server - Model Enumeration | Medium | Detection | `triton`, `enumeration`, `model-serving` |
| `triton-enum-003-metrics-exposed` | NVIDIA Triton - Metrics Exposed | Medium | Detection | `triton`, `metrics`, `enumeration`, `model-serving` |
| `triton-exploit-001-inference-abuse` | NVIDIA Triton - Inference Abuse | Critical | **Exploit** | `triton`, `inference`, `model-serving` |
| `triton-detect-002-shm-exposed` | NVIDIA Triton - Shared Memory Regions Exposed | High | Detection | `triton`, `shm`, `ipc`, `cve-2025-23319` |
| `triton-detect-003-model-repo-access` | NVIDIA Triton - Model Repository API Exposed | High | Detection | `triton`, `model-repo`, `unauth` |
| `triton-exploit-002-model-load` | NVIDIA Triton - Ungated Model Loading | Critical | **Exploit** | `triton`, `model-load`, `rce` |

## TorchServe

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `torchserve-auth-001-unauthenticated-api` | TorchServe - Unauthenticated Management API | High | Detection | `torchserve`, `auth`, `misconfiguration`, `model-serving` |
| `torchserve-mgmt-001-management-exposed` | TorchServe - Management Endpoint Exposed | Medium | Detection | `torchserve`, `management`, `model-serving` |
| `torchserve-exploit-001-model-register` | TorchServe - Model Registration Exploit | Critical | **Exploit** | `torchserve`, `rce`, `model-serving` |
| `torchserve-detect-002-mgmt-exposed` | TorchServe - Management API Exposed | High | Detection | `torchserve`, `management`, `unauth` |
| `torchserve-exploit-002-register-ssrf` | TorchServe - Model Registration SSRF (ShellTorch) | Critical | **Exploit** | `torchserve`, `ssrf`, `rce`, `shelltorch`, `cve-2023-43654` |

## BentoML

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `bentoml-detect-001-unauth-inference` | BentoML - Unauthenticated Inference Access | High | Detection | `bentoml`, `unauth`, `inference` |
| `bentoml-detect-002-metrics-exposed` | BentoML - Prometheus Metrics Exposed | Medium | Detection | `bentoml`, `metrics`, `prometheus` |
| `bentoml-detect-003-root-banner` | BentoML - Service Root Banner Exposure | Info | Detection | `bentoml`, `enumeration`, `information-disclosure` |

## Weights & Biases

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `wandb-auth-001-unauthenticated-api` | Weights & Biases - Unauthenticated API Access | High | Detection | `wandb`, `auth`, `misconfiguration`, `ml-tracking` |
| `wandb-enum-001-config-exposure` | Weights & Biases - Configuration and API Key Exposure | Critical | Detection | `wandb`, `enumeration`, `credentials`, `artifacts` |
| `wandb-enum-002-api-key-in-config` | Weights & Biases - API Key in Client Configuration | Critical | Detection | `wandb`, `credentials`, `api-key`, `exposure` |

## Campaign

| ID | Name | Severity | Type | Tags |
|---|---|---|---|---|
| `bizarre-bazaar-001-llmjacking-validation` | Bizarre Bazaar - LLMjacking Validation | High | **Exploit** | `campaign`, `llmjacking`, `bizarre-bazaar` |

## Listing Templates at Runtime

```bash
# List all templates
./aipostex templates list

# Filter by tag
./aipostex templates list --tags mcp

# View details for a specific template
./aipostex templates info cve-2025-65513-fetch-mcp-ssrf
```

## Template Locations

Built-in templates are embedded from `pkg/vulncheck/templates/` organized by service subdirectory:

```
pkg/vulncheck/templates/
├── a2a/  bentoml/  campaign/  gradio/  huggingface/  jupyter/
├── kubeflow/  langchain/  litellm/  mcp/  mlflow/  ollama/
├── openai/  ray/  tfserving/  torchserve/  triton/  vectordb/  vllm/  wandb/
```
