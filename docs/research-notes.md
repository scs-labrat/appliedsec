# ALUSKORT Research Notes - Cutting-Edge Techniques

**Project:** ALUSKORT - Cloud-Neutral Security Reasoning Control Plane
**Generated:** 2026-02-20
**Agent:** Omeriko (RS - Research Scout)
**Status:** Phase 2 - Critical Review / Research Check

---

## Research Scope

This document surveys cutting-edge research (2024-2026) directly applicable to ALUSKORT's architecture and remediation backlog. Each recommendation includes relevance to specific ALUSKORT components, implementation notes, and paper references.

**Key ALUSKORT challenges researched:**
1. Autonomous SOC agent orchestration (core architecture)
2. Prompt injection defense (REM-C03)
3. Multi-agent LLM orchestration for incident response (Layer 4)
4. RAG for threat intelligence (Layer 3 / knowledge base)
5. LLM confidence calibration (auto-closure / REM-H02)
6. Concept drift detection (REM-H02 Part D)
7. Human-AI collaboration and trusted autonomy (shadow mode / REM-H05)

---

## 1. Autonomous SOC Agent Architecture

### 1.1 Multi-Agent LLM Orchestration for Incident Response

**Paper:** "Multi-Agent LLM Orchestration Achieves Deterministic, High-Quality Decision Support for Incident Response" (Drammeh, 2025)
- **Link:** https://arxiv.org/abs/2511.15755
- **Why it matters for ALUSKORT:** This is the closest validated architecture to what ALUSKORT is building. Through 348 controlled trials, multi-agent orchestration achieved **100% actionable recommendation rate** vs 1.7% for single-agent, **80x improvement in action specificity**, and **140x improvement in solution correctness**.
- **Key innovation:** The "Decision Quality (DQ)" metric captures validity, specificity, and correctness - exactly the properties ALUSKORT needs for its confidence engine. Multi-agent systems exhibited **zero quality variance** across trials, enabling production SLA commitments.
- **Implementation notes:**
  - ALUSKORT's LangGraph agent graph already follows this pattern. Validate that each agent node (triage, investigation, response) has distinct quality-checking roles.
  - Adopt the DQ metric for ALUSKORT's shadow mode evaluation (REM-H05). Instead of just agreement rate, measure validity + specificity + correctness.
  - The framework (MyAntFarm.ai) is open-source and containerized - consider benchmarking ALUSKORT against it.
- **ALUSKORT relevance:** Layer 4 (Reasoning & Orchestration), REM-H05 (Shadow Mode)

### 1.2 AI-Augmented SOC: Comprehensive Survey

**Paper:** "AI-Augmented SOC: A Survey of LLMs and Agents for Security Automation" (2025)
- **Link:** https://www.mdpi.com/2624-800X/5/4/95
- **Why it matters:** Systematic review of 100+ sources (2022-2025) covering the exact problem ALUSKORT solves. Reports that multi-agent systems like Audit-LLM show **40% reduction in false positives** for insider threat detection.
- **Key findings relevant to ALUSKORT:**
  - Adaptive LLMs can handle evolving log formats without constant retraining (supports ALUSKORT's adapter pattern)
  - AI agents show up to **6x faster response** than human intervention
  - Reasoning-driven systems still lack formal safety guarantees under distribution shift (validates REM-H02 Part D drift detection as critical)
- **Implementation notes:** Use this survey's taxonomy of SOC tasks to validate ALUSKORT's task-tier mapping in `TASK_TIER_MAP` is comprehensive.
- **ALUSKORT relevance:** Overall architecture validation

### 1.3 Agentic AI and Cybersecurity Survey

**Paper:** "A Survey of Agentic AI and Cybersecurity: Challenges, Opportunities and Use-case Prototypes" (2025)
- **Link:** https://arxiv.org/html/2601.05293v1
- **Why it matters:** Catalogs agentic AI capabilities aligned with SOC functions: automated alert triage, autonomous incident response, scalable red-blue simulation, and continuous SOC support.
- **Key insight:** Security operations inherently involve continuous monitoring, sequential decision-making, coordination across tools, and adaptation to adversarial behavior - all characteristics well-aligned with agentic AI.
- **ALUSKORT relevance:** Architecture validation, agent design patterns

### 1.4 LLMs in the SOC: Empirical Study

**Paper:** "LLMs in the SOC: An Empirical Study of Human-AI Collaboration in Security Operations Centres" (2025)
- **Link:** https://arxiv.org/abs/2508.18947
- **Why it matters:** Empirical data on how LLMs perform in real SOC environments. Provides baseline metrics for comparing ALUSKORT's shadow mode performance against industry benchmarks.
- **ALUSKORT relevance:** REM-H05 (Shadow Mode), evaluation framework design

---

## 2. Prompt Injection Defense (REM-C03)

### 2.1 CaMeL: Defeating Prompt Injections by Design (Google DeepMind)

**Paper:** "Defeating Prompt Injections by Design" (Google DeepMind, 2025)
- **Link:** https://arxiv.org/abs/2503.18813
- **Why it matters for ALUSKORT:** CaMeL is the **most architecturally relevant** defense for ALUSKORT. It applies traditional software security principles (Control Flow Integrity, Access Control, Information Flow Control) to LLM agents - exactly the approach REM-C03 Part D (Executor Hard Constraints) is designed around.
- **Key innovation:** CaMeL separates control flow from data flow. It parses user queries into structured plans and execution graphs, tags each data element with capabilities, and enforces fine-grained policies. The LLM is treated as a **black box** with a runtime policy layer.
- **Results:** Solves 77% of tasks with **provable security** (vs 84% undefended) on AgentDojo. Neutralizes 67% of attacks.
- **Implementation notes for REM-C03:**
  - ALUSKORT's evidence block isolation (Part A) maps directly to CaMeL's data flow tagging
  - ALUSKORT's `ROLE_PERMISSIONS` matrix (Part D) maps to CaMeL's capability system
  - **Key gap in ALUSKORT:** CaMeL explicitly prevents data from influencing control flow. ALUSKORT should ensure that LLM outputs from alert analysis never modify the agent graph's routing logic - only the orchestrator code can do that.
  - Consider adopting CaMeL's formal capability model for ALUSKORT's tool/action permissions
- **ALUSKORT relevance:** REM-C03 (all parts), Layer 4 guardrails

**Operationalization Paper:** "Operationalizing CaMeL: Strengthening LLM Defenses for Enterprise Deployment" (2025)
- **Link:** https://arxiv.org/html/2505.22852v1
- **Why it matters:** Practical guidance on deploying CaMeL principles in production systems. Directly applicable to ALUSKORT's enterprise deployment targets.

### 2.2 PromptArmor: Simple Yet Effective Defenses

**Paper:** "PromptArmor: Simple yet Effective Prompt Injection Defenses" (Shi et al., 2025)
- **Link:** https://arxiv.org/abs/2507.15219
- **Why it matters for ALUSKORT:** Achieves **<1% false positive AND false negative rate** using an off-the-shelf LLM as a pre-filter - directly validates ALUSKORT's REM-C03 Part B (LLM-as-Judge injection classifier).
- **Key innovation:** Uses carefully designed prompting strategies to repurpose an LLM into an injection detector/remover. Robust against adaptive attacks specifically crafted to evade it.
- **Implementation notes for REM-C03 Part B:**
  - ALUSKORT's Haiku-based injection classifier can adopt PromptArmor's prompting strategies
  - The <1% FNR is better than ALUSKORT's 5% bypass target - adopt PromptArmor as the baseline to beat
  - Use PromptArmor's methodology for ALUSKORT's red-team regression suite (Part E)
- **ALUSKORT relevance:** REM-C03 Part B (LLM-as-Judge), Part E (Red-Team Suite)

### 2.3 Multi-Agent Defense Pipeline

**Paper:** "A Multi-Agent LLM Defense Pipeline Against Prompt Injection Attacks" (2025)
- **Link:** https://arxiv.org/html/2509.14285v4
- **Why it matters:** Presents a coordinated multi-agent pipeline for injection defense in real-time - aligns with ALUSKORT's defense-in-depth approach (REM-C03).
- **Implementation notes:** ALUSKORT already has layered defense (structured isolation + LLM judge + executor constraints). This paper provides a framework for coordinating those layers as a pipeline rather than independent checks.
- **ALUSKORT relevance:** REM-C03 defense pipeline coordination

### 2.4 PromptGuard: Structured Framework

**Paper:** "PromptGuard: A Structured Framework for Injection-Resilient Language Models" (2025)
- **Link:** https://www.nature.com/articles/s41598-025-31086-y
- **Why it matters:** Four-layer defense framework integrating input gatekeeping, structured prompt formatting, semantic output validation, and adaptive response refinement. Combines regex and MiniBERT-based detection.
- **Implementation notes:** ALUSKORT could add a small fine-tuned classifier (MiniBERT-scale) as a fast first-pass before the Haiku LLM-as-Judge, reducing Haiku calls and latency for obviously benign alerts.
- **ALUSKORT relevance:** REM-C03 optimization, defense-in-depth layering

### 2.5 Emerging Threats: MCP and Tool Poisoning

**Paper:** "Log-To-Leak: Prompt Injection Attacks on Tool-Using LLM Agents via Model Context Protocol" (2025)
- **Link:** https://openreview.net/forum?id=UVgbFuXPaO
- **Why it matters:** Documents attack surfaces in agent systems using MCP - tool poisoning, credential theft. ALUSKORT's adapter pattern (Layer 1) should be hardened against these vectors.
- **ALUSKORT relevance:** Layer 1 (Ingest Adapters), future MCP integration considerations

---

## 3. RAG for Threat Intelligence (Layer 3)

### 3.1 CyberRAG: Agentic RAG for Cyber Attack Classification

**Paper:** "CyberRAG: An Agentic RAG Cyber Attack Classification and Reporting Tool" (2025)
- **Link:** https://arxiv.org/abs/2507.02424
- **Why it matters for ALUSKORT:** CyberRAG is a modular agent-based RAG framework that delivers real-time classification, explanation, and structured reporting for cyber attacks. It uses an iterative **retrieval-and-reason loop** that queries a domain-specific knowledge base until evidence is relevant and self-consistent.
- **Key innovation:** A central LLM agent orchestrates fine-tuned classifiers specialized by attack family, tool adapters for enrichment/alerting, and iterative retrieval. Attack labels are mapped to technical descriptions, with RAG anchoring the LLM to correct attack descriptions and target device context.
- **Implementation notes for ALUSKORT:**
  - ALUSKORT's Context Gateway already does enrichment + retrieval. CyberRAG's iterative loop pattern could improve retrieval quality for complex multi-technique investigations (addresses REM-M01 context budget scaling)
  - The attack-family-specific classifiers map to ALUSKORT's technique validation (REM-C01) - specialized classifiers per ATT&CK tactic could outperform a single general classifier
  - CyberRAG's "self-consistency" check aligns with ALUSKORT's confidence engine - require retrieved evidence to be self-consistent before trusting it
- **ALUSKORT relevance:** Layer 3 (Data Layer), REM-M01, REM-C01

### 3.2 Reasoning RAG: System 1/System 2 for Industry

**Paper:** "Reasoning RAG via System 1 or System 2: A Survey on Reasoning Agentic Retrieval-Augmented Generation for Industry Challenges" (2025)
- **Link:** https://arxiv.org/html/2506.10408v1
- **Why it matters:** Surveys the shift from static RAG to dynamic reasoning-driven architectures. Distinguishes between System 1 (fast, heuristic retrieval) and System 2 (slow, deliberate reasoning retrieval) - directly maps to ALUSKORT's Tier 0 (fast triage) vs Tier 1 (deep reasoning).
- **Implementation notes:**
  - Tier 0 tasks should use System 1 RAG (fast, pattern-matching retrieval)
  - Tier 1+ tasks should use System 2 RAG (reasoning-guided retrieval with iterative refinement)
  - This dual-mode approach naturally fits ALUSKORT's tiered LLM strategy
- **ALUSKORT relevance:** Layer 3 (retrieval design), REM-M01 (context budget)

### 3.3 RAG Security and Adversarial Threats

**Paper:** "Securing RAG: A Risk Assessment and Mitigation Framework" (2025)
- **Link:** https://arxiv.org/html/2505.08728v2

**Paper:** "Adversarial Threat Vectors and Risk Mitigation for Retrieval-Augmented Generation Systems" (2025)
- **Link:** https://arxiv.org/html/2506.00281v1
- **Why they matter:** RAG systems introduce data poisoning and data leakage vulnerabilities. If an attacker can poison ALUSKORT's knowledge base (e.g., inject malicious ATT&CK technique descriptions), the RAG will retrieve and trust that poisoned content.
- **Implementation notes:**
  - ALUSKORT's taxonomy validation (REM-C01) partially addresses this - validated technique IDs prevent hallucinated techniques, but don't prevent poisoned descriptions for valid IDs
  - Consider adding provenance tracking to knowledge base entries (who added it, when, from what source)
  - Implement content integrity checks for RAG sources (hash + signed updates)
- **ALUSKORT relevance:** Layer 3, REM-C01, knowledge base integrity

### 3.4 Provably Secure RAG

**Paper:** "Provably Secure Retrieval-Augmented Generation" (2025)
- **Link:** https://arxiv.org/html/2508.01084v1
- **Why it matters:** Formal security guarantees for RAG systems. While full formal verification may be impractical for ALUSKORT v1, the threat model and security properties defined in this paper should inform ALUSKORT's RAG security design.
- **ALUSKORT relevance:** Layer 3, long-term hardening

---

## 4. LLM Confidence Calibration (REM-H02)

### 4.1 Agentic Uncertainty Quantification (AUQ)

**Paper:** "Agentic Uncertainty Quantification" (2025)
- **Link:** https://arxiv.org/html/2601.15703
- **Why it matters for ALUSKORT:** AUQ transforms verbalized uncertainty into **active, bi-directional control signals** for autonomous agents. This is exactly what ALUSKORT needs for its confidence engine and auto-closure decisions.
- **Key innovations:**
  - **System 1 (Uncertainty-Aware Memory):** Propagates verbalized confidence and semantic explanations to prevent blind decision-making
  - **System 2 (Uncertainty-Aware Reflection):** Uses uncertainty explanations as rational cues to trigger targeted resolution only when necessary
- **Implementation notes for ALUSKORT:**
  - ALUSKORT's confidence engine currently uses numeric scores. AUQ suggests also capturing **semantic uncertainty explanations** ("I'm uncertain because the alert lacks network context" vs "I'm uncertain because this technique ID is unfamiliar")
  - The System 1/System 2 split maps to ALUSKORT's tiers: Tier 0 uses fast uncertainty heuristics, Tier 1+ uses deliberate reflection
  - Uncertainty signals should **propagate forward** through the investigation pipeline, not just be point estimates at each step
  - AUQ's approach to triggering "targeted resolution" maps to ALUSKORT's escalation logic (Tier 1 -> Tier 1+ based on uncertainty)
- **ALUSKORT relevance:** Confidence Engine, REM-H02 (FP validation), auto-closure decisions

### 4.2 Uncertainty Quantification Survey (ICLR 2025 / KDD 2025)

**Paper:** "Uncertainty Quantification and Confidence Calibration in Large Language Models: A Survey" (2025)
- **Link:** https://arxiv.org/abs/2503.15850
- **Conference:** Published at KDD 2025 and presented at ICLR 2025

**Paper:** "Do LLMs Estimate Uncertainty Well?" (ICLR 2025)
- **Link:** https://proceedings.iclr.cc/paper_files/paper/2025/file/ef472869c217bf693f2d9bbde66a6b07-Paper-Conference.pdf
- **Why they matter:** Establishes that sufficiently aligned models **can** produce well-calibrated verbal confidence. However, most work treats UQ as a **static, post-hoc metric** and doesn't address operationalization for multi-step agent trajectories.
- **Implementation notes for ALUSKORT:**
  - ALUSKORT should request confidence scores from Claude in structured output (not just free-text reasoning), then calibrate them against ground truth during shadow mode
  - Use shadow mode (REM-H05) to build a calibration curve: what does "0.95 confidence" actually mean in terms of real precision?
  - Consider using self-consistency (multiple LLM calls with temperature sampling) for critical decisions - if 5/5 calls agree, confidence is higher than if 3/5 agree
- **ALUSKORT relevance:** Confidence Engine, REM-H02, REM-H05

### 4.3 Overconfidence in LLM-as-a-Judge

**Paper:** "Overconfidence in LLM-as-a-Judge: Diagnosis and Confidence-Driven Solution" (2025)
- **Link:** https://arxiv.org/html/2508.06225v2
- **Why it matters:** Documents systematic overconfidence in LLM-as-Judge patterns. ALUSKORT uses LLM-as-Judge for injection detection (REM-C03 Part B) and will use it for FP validation. This paper warns that raw LLM confidence scores tend to be overconfident.
- **Implementation notes:** Apply confidence recalibration (temperature scaling, Platt scaling) to ALUSKORT's LLM confidence outputs. Train the recalibration on shadow mode data.
- **ALUSKORT relevance:** REM-C03 Part B, Confidence Engine, REM-H02

---

## 5. Concept Drift Detection (REM-H02 Part D)

### 5.1 Evolving Cybersecurity Frontiers: Concept Drift in IDS

**Paper:** "Evolving Cybersecurity Frontiers: A Comprehensive Survey on Concept Drift and Feature Dynamics Aware Machine and Deep Learning in Intrusion Detection Systems" (2024)
- **Link:** https://www.sciencedirect.com/science/article/pii/S0952197624013010
- **Why it matters for ALUSKORT:** Exhaustive analysis (2019-2024) of concept drift approaches for security. Key insight: **feature drift** (changes in what data looks like) is distinct from **concept drift** (changes in what data means) - ALUSKORT needs to detect both.
- **Implementation notes:**
  - ALUSKORT should track both distribution shifts in input features (alert source mix, entity patterns) AND shifts in the relationship between features and outcomes (what used to be FP is now TP)
  - The paper identifies that unified models addressing both drift types are still missing - ALUSKORT's dual-tracking approach (REM-H02 Part D) is architecturally sound
- **ALUSKORT relevance:** REM-H02 Part D

### 5.2 Concept Drift in Malware Detection (NDSS 2025)

**Paper:** "Revisiting Concept Drift in Windows Malware Detection" (NDSS 2025)
- **Link:** https://securityboulevard.com/2026/02/ndss-2025-revisiting-concept-drift-in-windows-malware-detection/
- **Why it matters:** Uses graph neural networks with adversarial domain adaptation to learn drift-invariant features. While focused on malware, the technique of learning features that are **invariant to drift** could be applied to ALUSKORT's FP pattern detection.
- **Implementation notes:** Instead of just detecting drift and raising confidence thresholds (current ALUSKORT plan), consider learning drift-invariant features for FP pattern matching that remain stable across distribution shifts.
- **ALUSKORT relevance:** REM-H02 Part D, long-term FP pattern robustness

### 5.3 Model Retraining Upon Drift Detection

**Paper:** "Model Retraining upon Concept Drift Detection in Network Traffic Big Data" (2025)
- **Link:** https://www.mdpi.com/1999-5903/17/8/328
- **Why it matters:** Uses Isolation Forest for efficient anomaly detection in high-dimensional data to trigger retraining. Early retraining with small batch sizes keeps models synchronized with current data.
- **Implementation notes:** ALUSKORT doesn't retrain models (uses API-based LLMs), but the principle applies to FP patterns: detect drift early, revalidate FP patterns incrementally, don't wait for monthly retrospective.
- **ALUSKORT relevance:** REM-H02 Part D

---

## 6. Human-AI Collaboration and Trusted Autonomy (REM-H05)

### 6.1 Unified Framework for Human-AI Collaboration with Trusted Autonomy

**Paper:** "A Unified Framework for Human-AI Collaboration in Security Operations Centers with Trusted Autonomy" (Mohsin et al., 2025)
- **Link:** https://arxiv.org/abs/2505.23397
- **Why it matters for ALUSKORT:** Defines **five levels of AI autonomy** (manual to fully autonomous) mapped to human-in-the-loop roles and task-specific trust thresholds. This is the formal framework ALUSKORT needs for its shadow mode -> canary -> full autonomy progression (REM-H05).
- **Key innovation:** Task-specific trust thresholds - not a single global trust level, but calibrated trust per SOC function (monitoring, protection, detection, triage, response). A system can be Level 4 (high autonomy) for alert triage but Level 2 (assisted) for incident response.
- **Implementation notes for ALUSKORT:**
  - ALUSKORT's current design implicitly has autonomy levels (auto-close for FP vs human-approval for containment). This framework formalizes it.
  - **Map ALUSKORT's task types to autonomy levels:**
    - Level 4 (supervised autonomy): FP auto-closure (after shadow validation)
    - Level 3 (conditional autonomy): Alert enrichment, IOC correlation
    - Level 2 (assisted): Containment recommendations
    - Level 1 (advisory): Critical incident response recommendations
  - Use trust thresholds per function for canary rollout (REM-H05 Part B) - promote autonomy level per-function, not globally
  - The framework's "trust calibration" methodology should inform ALUSKORT's go-live criteria
- **ALUSKORT relevance:** REM-H05 (all parts), governance framework

### 6.2 AI-Driven Human-Machine Co-Teaming for SOCs

**Paper:** "Towards AI-Driven Human-Machine Co-Teaming for Adaptive and Agile Cyber Security Operation Centers" (2025)
- **Link:** https://arxiv.org/html/2505.06394
- **Why it matters:** Focuses on adaptive co-teaming rather than full automation. Relevant for ALUSKORT's human-approval gates on destructive operations.
- **ALUSKORT relevance:** Governance model, approval workflows

---

## 7. Cross-Cutting: Security of LLM-Based Agents

### 7.1 Comprehensive Security Survey

**Paper:** "Security of LLM-based Agents Regarding Attacks, Defenses, and Applications" (2025)
- **Link:** https://www.sciencedirect.com/science/article/abs/pii/S1566253525010036
- **Why it matters:** Comprehensive survey of attacks and defenses for LLM agents. ALUSKORT is an LLM agent operating in a security domain - it must be secure against the very attack techniques it's designed to detect.
- **ALUSKORT relevance:** Overall security posture, REM-C03

### 7.2 End-to-End Threat Model for LLM-Agent Ecosystems

**Paper:** "From Prompt Injections to Protocol Exploits: Threats in LLM-Powered AI Agent Workflows" (2025)
- **Link:** https://www.sciencedirect.com/science/article/pii/S2405959525001997
- **Why it matters:** Catalogs 30+ attack techniques across Input Manipulation, Model Compromise, System and Privacy Attacks, and Protocol Vulnerabilities. Use this as a threat enumeration checklist for ALUSKORT's security review.
- **Implementation notes:** Cross-reference these attack techniques against ALUSKORT's existing defenses (REM-C01 through REM-C03). Identify any gaps not covered by the remediation backlog.
- **ALUSKORT relevance:** Threat modeling, security architecture

---

## Synthesis: Top Recommendations for ALUSKORT

### Immediate Actions (integrate into existing remediation backlog)

| # | Recommendation | Source | ALUSKORT Impact |
|---|---|---|---|
| 1 | **Adopt CaMeL's capability model** for ALUSKORT's tool/action permissions. Ensure LLM outputs cannot modify control flow. | CaMeL (DeepMind, 2025) | Strengthens REM-C03 Part D |
| 2 | **Use PromptArmor's prompting strategies** as baseline for Haiku injection classifier. Target <1% FNR (better than current 5% target). | PromptArmor (2025) | Upgrades REM-C03 Part B |
| 3 | **Adopt Decision Quality (DQ) metric** for shadow mode evaluation instead of just agreement rate. | Multi-Agent IR (2025) | Upgrades REM-H05 evaluation |
| 4 | **Implement AUQ-style semantic uncertainty** - capture WHY the model is uncertain, not just a numeric score. | AUQ (2025) | Upgrades Confidence Engine |
| 5 | **Formalize autonomy levels per task type** using Mohsin et al.'s 5-level framework for canary rollout. | Trusted Autonomy (2025) | Upgrades REM-H05 Part B |

### Architecture Enhancements (consider for v1.1+)

| # | Recommendation | Source | ALUSKORT Impact |
|---|---|---|---|
| 6 | **Dual-mode RAG** (System 1/System 2) matching ALUSKORT's tier structure. Fast retrieval for Tier 0, reasoning-guided retrieval for Tier 1+. | Reasoning RAG Survey (2025) | Layer 3 retrieval quality |
| 7 | **Iterative retrieval-and-reason loop** (CyberRAG pattern) for complex investigations. | CyberRAG (2025) | REM-M01, investigation depth |
| 8 | **RAG provenance tracking** - sign and verify knowledge base entries to prevent data poisoning. | RAG Security (2025) | Layer 3 integrity |
| 9 | **Drift-invariant features** for FP pattern matching using domain adaptation. | NDSS 2025 Drift | Long-term REM-H02 |
| 10 | **Confidence recalibration** (Platt/temperature scaling) trained on shadow mode data. | Overconfidence (2025) | Confidence Engine accuracy |

### Research Gaps (areas where ALUSKORT could contribute)

1. **No existing work** combines CaMeL-style formal security with multi-agent SOC orchestration. ALUSKORT could be the first provably-secure autonomous SOC agent.
2. **Concept drift detection for LLM-based** (not ML-based) security systems is largely unexplored. ALUSKORT's API-based approach needs drift detection at the prompt/output level, not the model weight level.
3. **Cross-tenant isolation guarantees** for multi-tenant LLM agents (REM-M03) is not addressed in current literature.

---

## Sources

- [Multi-Agent LLM Orchestration for IR](https://arxiv.org/abs/2511.15755) - Drammeh, 2025
- [AI-Augmented SOC Survey](https://www.mdpi.com/2624-800X/5/4/95) - 2025
- [Agentic AI and Cybersecurity Survey](https://arxiv.org/html/2601.05293v1) - 2025
- [LLMs in the SOC: Empirical Study](https://arxiv.org/abs/2508.18947) - 2025
- [Large Language Models for SOCs: Comprehensive Survey](https://arxiv.org/abs/2509.10858) - 2025
- [CaMeL: Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813) - Google DeepMind, 2025
- [Operationalizing CaMeL](https://arxiv.org/html/2505.22852v1) - 2025
- [PromptArmor: Simple Yet Effective](https://arxiv.org/abs/2507.15219) - Shi et al., 2025
- [Multi-Agent Defense Pipeline](https://arxiv.org/html/2509.14285v4) - 2025
- [PromptGuard Framework](https://www.nature.com/articles/s41598-025-31086-y) - 2025
- [Log-To-Leak: MCP Attacks](https://openreview.net/forum?id=UVgbFuXPaO) - 2025
- [Prompt Injection Comprehensive Review](https://www.mdpi.com/2078-2489/17/1/54) - 2025
- [From Prompt Injections to Protocol Exploits](https://www.sciencedirect.com/science/article/pii/S2405959525001997) - 2025
- [CyberRAG](https://arxiv.org/abs/2507.02424) - 2025
- [Reasoning RAG Survey](https://arxiv.org/html/2506.10408v1) - 2025
- [Securing RAG](https://arxiv.org/html/2505.08728v2) - 2025
- [RAG Adversarial Threats](https://arxiv.org/html/2506.00281v1) - 2025
- [Provably Secure RAG](https://arxiv.org/html/2508.01084v1) - 2025
- [Agentic Uncertainty Quantification](https://arxiv.org/html/2601.15703) - 2025
- [UQ and Confidence Calibration Survey](https://arxiv.org/abs/2503.15850) - KDD/ICLR 2025
- [Do LLMs Estimate Uncertainty Well?](https://proceedings.iclr.cc/paper_files/paper/2025/file/ef472869c217bf693f2d9bbde66a6b07-Paper-Conference.pdf) - ICLR 2025
- [Overconfidence in LLM-as-a-Judge](https://arxiv.org/html/2508.06225v2) - 2025
- [Concept Drift in IDS Survey](https://www.sciencedirect.com/science/article/pii/S0952197624013010) - 2024
- [Concept Drift in Malware Detection](https://securityboulevard.com/2026/02/ndss-2025-revisiting-concept-drift-in-windows-malware-detection/) - NDSS 2025
- [Model Retraining on Drift](https://www.mdpi.com/1999-5903/17/8/328) - 2025
- [Trusted Autonomy Framework](https://arxiv.org/abs/2505.23397) - Mohsin et al., 2025
- [Human-Machine Co-Teaming for SOCs](https://arxiv.org/html/2505.06394) - 2025
- [Security of LLM-based Agents Survey](https://www.sciencedirect.com/science/article/abs/pii/S1566253525010036) - 2025
- [OWASP LLM Top 10: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) - 2025

---

*Document generated by Omeriko (RS - Research Scout mode) for ALUSKORT project.*
*29 papers surveyed across 7 research domains, with 10 actionable recommendations.*
