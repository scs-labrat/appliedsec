# Cyber Domain ML Notes

## Security Data Characteristics

### Log Data
- **Volume:** High - millions to billions of events/day
- **Format:** Semi-structured (JSON, syslog, CEF, LEEF)
- **Challenges:** Noisy, schema drift, timestamp inconsistencies
- **ML Approaches:** Anomaly detection, sequence modeling, NER for extraction

### Network Data
- **Types:** PCAP, NetFlow, DNS logs, proxy logs
- **Volume:** Extremely high for PCAP, manageable for flows
- **Challenges:** Encryption limiting visibility, high dimensionality
- **ML Approaches:** Traffic classification, C2 detection, DGA detection

### Endpoint Data
- **Types:** Process execution, file operations, registry changes
- **Sources:** EDR, Sysmon, auditd
- **Challenges:** Context-dependent (what's normal varies)
- **ML Approaches:** Behavioral analysis, process tree modeling

### Threat Intelligence
- **Types:** IOCs, TTPs, threat reports, MITRE ATT&CK
- **Format:** STIX/TAXII, free-form reports, structured feeds
- **Challenges:** Timeliness, false positives, attribution uncertainty
- **ML Approaches:** NER for IOC extraction, classification, RAG for knowledge

---

## Common ML Tasks in Cybersecurity

### Classification Tasks
| Task | Input | Output | Common Approaches |
|------|-------|--------|-------------------|
| Malware Detection | Binary/behavior | Malicious/Benign | Gradient boosting, CNNs on images |
| Phishing Detection | URL/email | Phishing/Legit | NLP, URL features |
| Log Severity | Log entry | Critical/High/Med/Low | BERT fine-tuned |
| Alert Triage | Alert bundle | True/False Positive | Ensemble models |

### Extraction Tasks
| Task | Input | Output | Common Approaches |
|------|-------|--------|-------------------|
| IOC Extraction | Text | Entities (IP, Hash, Domain) | NER (BERT-based) |
| TTP Mapping | Description | MITRE techniques | Multi-label classification |
| Artifact Parsing | Raw artifact | Structured data | Rule-based + ML hybrid |

### Sequence/Anomaly Tasks
| Task | Input | Output | Common Approaches |
|------|-------|--------|-------------------|
| User Behavior | Activity sequence | Anomaly score | LSTM, Transformer |
| Process Behavior | Process tree | Anomaly score | Graph neural networks |
| Network Anomaly | Flow features | Anomaly score | Isolation Forest, Autoencoder |

---

## Key Frameworks & Tools

### Data Processing
- **Apache Kafka/Flink:** Stream processing for security telemetry
- **Spark:** Batch processing for large-scale analysis
- **Elasticsearch:** Log storage and search

### ML/AI
- **Scikit-learn:** Traditional ML (still excellent for tabular security data)
- **PyTorch/TensorFlow:** Deep learning
- **HuggingFace:** Transformers for NLP security tasks
- **LangChain/LlamaIndex:** RAG frameworks

### Security-Specific
- **MITRE ATT&CK:** TTP framework
- **Sigma:** Detection rule standard
- **YARA:** Pattern matching for malware
- **OpenCTI:** Threat intelligence platform

---

## Domain-Specific Considerations

### Adversarial Robustness
- Attackers will probe and evade ML models
- Consider adversarial training
- Don't rely solely on ML - defense in depth

### Explainability Requirements
- Analysts need to understand why model flagged something
- SHAP, LIME, attention visualization
- Rule extraction from models

### Temporal Dynamics
- Threat landscape evolves rapidly
- Model drift is constant
- Plan for continuous retraining

### Labeling Challenges
- Ground truth is expensive
- Hindsight labeling (we learn something was malicious later)
- Weak supervision approaches valuable

---

## Infrastructure-Specific Knowledge

### RTX 4090 Optimization (24GB VRAM)

**Model Size Guidelines:**
| Model Size | Precision | Fits in 24GB? | Notes |
|------------|-----------|---------------|-------|
| 7B | FP16 | ✅ Yes (~14GB) | Room for context |
| 13B | FP16 | ⚠️ Tight (~26GB) | Needs quantization |
| 7B | 4-bit | ✅ Yes (~4GB) | Excellent headroom |
| 13B | 4-bit | ✅ Yes (~7GB) | Good headroom |
| 30B | 4-bit | ⚠️ Tight (~17GB) | Limited context |
| 70B | 4-bit | ❌ No (~35GB) | Won't fit |

**Recommended Local Serving Stacks:**
- **Ollama** - Easy setup, good quantization support
- **vLLM** - High throughput, PagedAttention
- **text-generation-inference** - HuggingFace's solution
- **llama.cpp** - Best for GGUF models, efficient

**Quantization Formats:**
- **GPTQ** - Good quality, fast inference
- **AWQ** - Activation-aware, better quality
- **GGUF** - llama.cpp native, very flexible
- **bitsandbytes** - Easy integration with transformers

**RTX 4090 Specific Tips:**
- CUDA 12.x recommended
- Flash Attention 2 works well
- 24GB allows decent batch sizes for smaller models
- Consider model sharding for larger models (if multi-GPU available)

### AWS Training Environment

**SageMaker Patterns:**
- Use SageMaker Training Jobs for fine-tuning
- Spot instances for cost savings (70% cheaper)
- Use SageMaker Experiments for tracking
- Export models to S3 for secure transfer

**Bedrock Integration:**
- Use Bedrock for RAG prototyping
- Test with Bedrock before fine-tuning decision
- Bedrock Knowledge Bases for managed RAG
- Model evaluation with Bedrock

**Model Export for Air-gapped Deployment:**
1. Train/fine-tune on SageMaker
2. Export to S3 (safetensors format)
3. Quantize to GGUF/GPTQ
4. Secure transfer (encrypted USB, etc.)
5. Deploy locally on RTX 4090

**Cost Optimization:**
- Use ml.g5.xlarge for development
- ml.p4d.24xlarge for serious training
- Spot instances where possible
- SageMaker Inference for testing before air-gap

---

## Add Domain Notes Below
<!-- Accumulate domain insights as projects progress -->
