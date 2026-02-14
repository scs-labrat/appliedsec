# Omeriko Module ⚔️

**Cyber AI Systems Architect** - A BMM add-on for building AI/ML systems in cybersecurity domains.

## Overview

Omeriko is a collaborative mentor who helps you design, build, and deploy AI systems for:
- **Digital Forensics** - Memory analysis, disk forensics, artifact extraction
- **Incident Response** - Playbooks, triage, containment
- **OS Internals** - Windows/Linux internals, process analysis
- **Threat Intelligence** - MITRE ATT&CK, IOCs, threat feeds

**BMM Integration**: Omeriko works as an add-on to BMM (BMAD Method). After completing AI system design with Omeriko, use the handoff commands to generate documents for BMM's standard agents (Architect, Dev, QA) to implement.

## Features

### Core AI Design Commands

| Command | Trigger | Description |
|---------|---------|-------------|
| System Design | `SD` | Design end-to-end AI architecture |
| Data Pipeline | `DP` | Analyze data formats, logs, and security artifacts |
| Knowledge Base | `KB` | Design RAG systems for cyber intel |
| Training Strategy | `TS` | Plan model fine-tuning approaches |
| Inference Planning| `IO` | Optimize for production deployment on RTX 4090 |
| **Critical Review** | `CR` | Challenge your design as a skeptical expert |
| Research Scout | `RS` | Find cutting-edge papers and techniques |

### Memory Commands

| Command | Trigger | Description |
|---------|---------|-------------|
| Project Memory | `PM` | Save context across sessions |
| Load Project | `LP` | Load saved project context |
| Lessons Learned | `LM` | Review past project lessons |

### BMM Handoff Commands 🔄

| Command | Trigger | Description |
|---------|---------|-------------|
| **HO-PRD** | `HO-PRD` | Generate BMM-compatible Product Requirements Document |
| **HO-ARCH** | `HO-ARCH` | Generate Architecture Document for BMM Dev |
| **HO-TEST** | `HO-TEST` | Generate Testing Requirements for BMM QA |
| **HO-SUM** | `HO-SUM` | Show BMM integration workflow summary |

### Workflow Status Commands 📊

| Command | Trigger | Description |
|---------|---------|-------------|
| **AI-INIT** | `AI-INIT` | Initialize new AI project with workflow tracking |
| **AI-STATUS** | `AI-STATUS` | Check progress and see what's next |

These commands provide BMGD-style workflow tracking for AI projects.

### Critical Review Mode ⚔️

A unique feature - invoke `CR` and Omeriko switches from mentor to skeptical challenger:
- Questions your technology choices
- Probes for edge cases and failure modes
- Challenges assumptions and scalability
- Strengthens your design through tough questions

## Installation

### Using BMad Installer

1. Run the BMad installer in your project:
   ```bash
   npx bmad-method install
   ```

2. When prompted for custom modules, provide the path to this module:
   ```
   samples/sample-custom-modules/omeriko-module
   ```

### Manual Installation

1. Copy the module folder to your project's custom modules location
2. Register the module in your BMad configuration

## Usage

### Start a Session

Invoke Omeriko in your IDE (Claude Code, Cursor, etc.):

```
"I'd like to work with Omeriko on designing a RAG system for threat intelligence"
```

### Example Workflows

**Designing a RAG System:**
```
1. Invoke KB (Knowledge Base Design)
2. Describe your threat intelligence sources
3. Work through chunking, embedding, retrieval strategy
4. Use CR (Critical Review) to stress test the design
5. Use PM (Project Memory) to save context for next session
```

**Planning Model Fine-tuning:**
```
1. Invoke TS (Training Strategy)
2. Define your classification/extraction task
3. Work through data requirements and model selection
4. Review evaluation strategy
5. Challenge with CR before implementation
```

## BMM Integration Workflow 🔄

Omeriko integrates with the full BMM ecosystem. The workflow:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    OMERIKO (AI System Design)                       │
│  SD → DP → KB → TS → IO → CR (Design & Review)                     │
└─────────────────────────┬───────────────────────────────────────────┘
                          │
                          ▼ [HO-PRD]
┌─────────────────────────────────────────────────────────────────────┐
│                    BMM PRD/ARCHITECT                                │
│  Generate PRD → @architect creates implementation architecture      │
└─────────────────────────┬───────────────────────────────────────────┘
                          │
                          ▼ [HO-ARCH]
┌─────────────────────────────────────────────────────────────────────┐
│                       BMM DEV                                       │
│  Generate Architecture Doc → @dev implements the system             │
└─────────────────────────┬───────────────────────────────────────────┘
                          │
                          ▼ [HO-TEST]
┌─────────────────────────────────────────────────────────────────────┐
│                       BMM QA                                        │
│  Generate Test Requirements → @qa creates test plan & executes      │
└─────────────────────────────────────────────────────────────────────┘
```

### Complete Example: Threat Intelligence RAG System

```bash
# Phase 1: AI Design with Omeriko
@omeriko SD     # Design system architecture
@omeriko KB     # Design RAG for threat intel
@omeriko DP     # Analyze STIX/TAXII data formats
@omeriko TS     # Plan embedding fine-tuning
@omeriko IO     # Optimize for RTX 4090 inference
@omeriko CR     # Critical review of design

# Phase 2: Generate Handoff Documents
@omeriko HO-PRD    # Creates docs/prd.md

# Phase 3: BMM Implementation
@architect         # Reviews PRD, creates implementation architecture
@omeriko HO-ARCH   # Creates docs/architecture.md
@dev               # Implements based on architecture

# Phase 4: Testing
@omeriko HO-TEST   # Creates docs/testing-requirements.md
@qa                # Creates test plan and executes
```

## AI Workflow Status System 📊

Omeriko includes a complete workflow status system inspired by BMGD. This tracks your AI project progress through all phases.

### Quick Start

```bash
# Initialize new AI project
@omeriko AI-INIT

# Check progress anytime
@omeriko AI-STATUS
```

### Workflow Paths

| Path | Description | Best For |
|------|-------------|----------|
| **cyber-ai-greenfield** | Full AI system design | Complete RAG + training + inference projects |
| **quick-rag-greenfield** | Streamlined RAG path | Fast knowledge base implementation |

### Phases (Full Cyber AI Path)

```
Phase 0: Discovery & Requirements (Optional)
├── problem-discovery (SD)
└── data-assessment (DP)

Phase 1: AI Architecture Design
├── system-design (SD) ←── REQUIRED
├── knowledge-base (KB) ←── If RAG system
├── training-strategy (TS) ←── If model training
└── inference-optimization (IO) ←── REQUIRED

Phase 2: Critical Review
├── design-review (CR) ←── REQUIRED
└── research-check (RS)

Phase 3: BMM Handoff
├── generate-prd (HO-PRD) ←── REQUIRED
├── generate-architecture (HO-ARCH) ←── REQUIRED
└── generate-testing (HO-TEST) ←── REQUIRED

Phase 4: BMM Implementation
├── bmm-architect-review (@architect) ←── REQUIRED
├── bmm-dev-implement (@dev) ←── REQUIRED
└── bmm-qa-test (@qa) ←── REQUIRED
```

### Status Values

- **required** - Must complete to progress
- **optional** - Can be skipped
- **recommended** - Suggested but not required
- **conditional** - Required if conditions met (e.g., RAG system)
- **file path** (e.g., `docs/ai-design.md`) - Completed
- **skipped** - Intentionally skipped

## Module Structure

```
omeriko-module/
├── module.yaml                           # Module definition
├── README.md                             # This file
├── install-omeriko.sh                    # Installation script
├── agents/
│   └── omeriko/
│       ├── omeriko.agent.yaml            # Agent definition
│       └── omeriko-sidecar/              # Persistent memory
│           ├── instructions.md           # Operating protocols
│           ├── memories.md               # Session history
│           ├── projects/                 # Per-project context
│           └── knowledge/                # Accumulated knowledge
└── workflows/
    └── ai-workflow-status/               # Workflow tracking system
        ├── workflow.yaml                 # Main workflow definition
        ├── instructions.md               # Workflow instructions
        ├── ai-workflow-status-template.yaml
        ├── init/                         # AI-INIT workflow
        │   ├── workflow.yaml
        │   └── instructions.md
        └── paths/                        # Project path definitions
            ├── cyber-ai-greenfield.yaml
            └── quick-rag-greenfield.yaml
```

## Persistent Memory

Omeriko maintains context across sessions through the sidecar:

- **memories.md** - Session summaries, key decisions, patterns observed
- **projects/** - Deep context for each ongoing project
- **knowledge/** - Accumulated domain insights, patterns, lessons

This allows Omeriko to:
- Reference past decisions naturally
- Track project evolution
- Apply lessons from previous work
- Maintain continuity across sessions

## Customization

### Adding Domain Knowledge

Edit files in `omeriko-sidecar/knowledge/` to add:
- Architecture patterns from your projects
- Lessons learned from deployments
- Domain-specific notes

### Adjusting Communication Style

Edit `omeriko-sidecar/instructions.md` to tune:
- User preferences
- Domain focus areas
- Interaction guidelines

## License

Part of the BMAD-METHOD project.
