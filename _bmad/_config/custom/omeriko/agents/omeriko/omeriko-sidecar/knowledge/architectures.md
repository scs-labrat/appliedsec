# Proven Architecture Patterns

## RAG Architectures for Cybersecurity

### Pattern: Threat Intelligence RAG
**Use Case:** Querying threat reports, MITRE ATT&CK, CVEs
**Architecture:**
```
Documents → Chunker (semantic) → Embeddings (security-tuned) → Vector DB
                                                                    ↓
User Query → Query Expansion → Retrieval → Reranker → LLM Response
```
**Key Decisions:**
- Chunk by semantic boundaries (attack phases, techniques)
- Use security-domain embeddings if available
- Reranking critical for precision

### Pattern: Forensic Knowledge Base
**Use Case:** Artifact reference, investigation procedures
**Architecture:**
- Hierarchical chunking (artifact → sub-artifacts)
- Metadata-enriched embeddings (OS, artifact type, evidence type)
- Citation-tracked responses

---

## Model Fine-tuning Patterns

### Pattern: IOC Extraction Model
**Task:** Named Entity Recognition for IOCs
**Approach:**
- Base: BERT or security-domain transformer
- Fine-tune: LoRA for efficiency
- Labels: IP, Domain, Hash, CVE, Tool

### Pattern: Log Anomaly Detection
**Task:** Classification of anomalous log entries
**Approach:**
- Unsupervised pre-training on normal logs
- Supervised fine-tuning on labeled anomalies
- Ensemble with rule-based baselines

---

## Data Pipeline Patterns

### Pattern: Security Telemetry Pipeline
**Sources:** SIEM, EDR, Network
**Architecture:**
```
Sources → Kafka → Normalization → Feature Store → ML Models
                       ↓
                  Data Lake (raw + processed)
```

### Pattern: Air-gapped ML Pipeline
**Constraint:** No external connectivity
**Approach:**
- Local model serving (ONNX, TensorRT)
- Batch updates via secure transfer
- Local vector DB (Chroma, Qdrant)

### Pattern: AWS-to-Air-Gap Deployment (RTX 4090)
**Context:** Train on AWS SageMaker/Bedrock, deploy on air-gapped RTX 4090 (24GB VRAM)

**Training Phase (AWS):**
```
Data Prep → SageMaker Training Job → Model Checkpoints → S3
                                            ↓
                                    Quantization (GPTQ/AWQ)
                                            ↓
                                    Export to GGUF format
```

**Transfer Phase:**
```
S3 → Encrypted Export → Secure Transfer → Air-gapped System
     (safetensors)      (encrypted USB)
```

**Inference Phase (Air-gapped):**
```
GGUF Model → Ollama/vLLM → Local API
                ↓
Vector DB (Chroma) ← Embeddings ← Documents
                ↓
         Application Layer
```

**Key Considerations (project-specific):**
- Model size depends on task complexity and accuracy requirements
- Quantization (4-bit, 8-bit) expands what fits in 24GB
- Serving stack choice affects throughput vs simplicity trade-off
- VRAM budget must be calculated per-project based on actual needs

**VRAM Reference (RTX 4090 24GB) - Use for planning:**
| Model Size | FP16 | 8-bit | 4-bit | Notes |
|------------|------|-------|-------|-------|
| 7B | ~14GB | ~7GB | ~4GB | Room for embeddings + context |
| 13B | ~26GB | ~13GB | ~7GB | 4-bit fits well |
| 30B | ~60GB | ~30GB | ~17GB | 4-bit tight, limited context |
| 70B | ~140GB | ~70GB | ~35GB | Requires multi-GPU or won't fit |

**Additional VRAM consumers to budget per-project:**
- Embedding model: 0.5-2GB depending on model
- KV cache: Scales with context length and batch size
- Vector DB (if in-memory): Depends on collection size
- Framework overhead: ~1-2GB

**Note:** Calculate actual VRAM budget during System Design [SD] or Inference Optimization [IO] based on specific project requirements.

---

## Add New Patterns Below
<!-- Document successful patterns as projects complete -->
