# Lessons Learned

## Failures & Gotchas

### RAG Systems
<!-- Document RAG failures and learnings -->

**Gotcha: Generic Chunking for Security Docs**
- Problem: Fixed-size chunks break attack narratives
- Lesson: Use semantic chunking respecting document structure
- Resolution: Custom chunker for security content types

**Gotcha: Embedding Model Mismatch**
- Problem: General embeddings miss security terminology
- Lesson: Domain-specific or fine-tuned embeddings improve retrieval significantly
- Resolution: Test retrieval quality before committing to embedding model

---

### Model Training
<!-- Document training failures and learnings -->

**Gotcha: Class Imbalance in Security Data**
- Problem: Malicious samples rare vs benign
- Lesson: Stratified sampling, SMOTE, or focal loss essential
- Resolution: Always check class distribution first

**Gotcha: Label Quality in Threat Data**
- Problem: Threat intel labels often noisy or outdated
- Lesson: Data quality > model complexity
- Resolution: Invest in label validation pipeline

---

### Deployment
<!-- Document deployment failures and learnings -->

**Gotcha: Air-gapped Model Updates**
- Problem: Can't pull models from HuggingFace
- Lesson: Plan model versioning and secure transfer from start
- Resolution: Local model registry with checksums

---

## What Worked Well

### Architecture Decisions
<!-- Document successful patterns -->

### Tool Choices
<!-- Document tools that delivered value -->

### Process Improvements
<!-- Document process learnings -->

---

## Add New Lessons Below
<!-- Document failures and successes as they occur -->
