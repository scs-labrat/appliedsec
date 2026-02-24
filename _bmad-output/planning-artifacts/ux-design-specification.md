---
stepsCompleted: [1, 2, 3]
inputDocuments:
  - "docs/prd.md"
  - "_bmad-output/planning-artifacts/architecture.md"
  - "_bmad-output/planning-artifacts/epics.md"
  - "docs/development-guide.md"
  - "docs/index.md"
---

# UX Design Specification ALUSKORT

**Author:** d8rh8r
**Date:** 2026-02-21

---

## Executive Summary

### Project Vision

ALUSKORT Setup Wizard — a guided first-run experience that transforms a complex multi-service deployment (8 microservices, 6 infrastructure dependencies, 31 Kafka topics, 7 SQL migrations) into a confident, validated setup flow. Two paths: a "get me running in 5 minutes" local dev experience, and a step-by-step production deployment with infrastructure validation at every stage. The wizard is the front door to the entire ALUSKORT SOC platform — the first impression for every user who will ever operate it.

### Target Users

**Primary: Security Team Lead (Installer/Operator)**
- Built the system, deeply technical, knows the architecture
- Needs both local dev and production deployment paths
- Wants confidence that everything is configured correctly, not just "it ran without errors"
- Will use the wizard repeatedly: for fresh installs, new environments, team onboarding

**Secondary: Developer (Team Onboarding)**
- Joining the team, needs a local dev environment fast
- Technical but unfamiliar with ALUSKORT's specific infrastructure dependencies
- Wants sensible defaults, minimal decisions, and a working system in minutes
- Should not need to understand Neo4j bolt URIs or Qdrant HNSW parameters to get started

### Key Design Challenges

1. **Silent failure detection** — Infrastructure services can appear healthy but be misconfigured (missing Kafka topics, absent Qdrant collections, empty taxonomy tables). The wizard must validate at every step, not just execute blindly.

2. **Two radically different paths** — Local dev (Docker Compose, sensible defaults, zero external deps beyond an API key) vs. production (existing infrastructure endpoints, custom auth, tenant configuration). These paths share structure but almost no content.

3. **The API key gate** — ALUSKORT is non-functional for LLM features without ANTHROPIC_API_KEY, but all infrastructure can run without it. The wizard must support "set up infrastructure now, add key later" without feeling broken.

4. **Progressive complexity** — New users shouldn't face Neo4j bolt URIs on screen one. Experienced users shouldn't endure 12 screens of Next buttons. The wizard must adapt to both.

### Design Opportunities

1. **Health-first feedback** — Live health dashboard after each phase with green/red/yellow indicators for every service. Visual confidence that the system is actually working.

2. **Smart defaults with escape hatches** — Pre-fill everything for local dev. For production, detect and validate existing infrastructure (DSN reachability, Kafka health, service connectivity) before proceeding.

3. **Resumable setup** — Persist wizard state so interrupted setups can resume cleanly. Docker pulls fail, someone steps away, network drops — the wizard remembers where it left off.

## Core User Experience

### Defining Experience

The ALUSKORT Setup Wizard is a CLI-based guided installation and configuration tool. The core experience is **validated confidence** — the user finishes the wizard knowing, not hoping, that every service, topic, collection, and migration is correctly configured and healthy. The wizard replaces a manual 8-step process (pip install, docker-compose, 3 init scripts, env var configuration, health checking) with a single command: `python -m aluskort setup`.

The primary interaction is a two-path fork: **Dev** (local Docker Compose, sensible defaults, running in minutes) or **Production** (existing infrastructure endpoints, custom configuration, validation at every stage). After that single choice, the wizard drives — the user watches services come alive with real-time progress feedback and a final health validation report.

### Platform Strategy

- **Platform:** CLI (terminal-native Python application)
- **Interaction:** Keyboard-driven — arrow keys, enter, text input for values like API keys and DSNs
- **Output:** Rich terminal output — colours, spinners, progress bars, health tables, ASCII status indicators
- **Library candidates:** `rich` or `textual` for terminal UI, `click` or `typer` for CLI framework
- **No browser required:** The wizard runs entirely in-terminal. No web server, no port to remember, no context switch
- **Offline-capable (partial):** Infrastructure setup (Docker, migrations, topics) works without internet. Only Anthropic API key validation requires connectivity

### Effortless Interactions

1. **Path selection** — One question: "Dev or Production?" with clear descriptions of what each means. No ambiguity.
2. **API key entry** — Prompted once, validated immediately against the Anthropic API, stored securely. Skippable with a clear warning about what won't work without it.
3. **Infrastructure spinup** — Fully automatic for dev path. Docker Compose up, health poll, proceed when ready. Zero user input required.
4. **Database initialisation** — Kafka topics, Qdrant collections, Neo4j constraints, SQL migrations all run automatically with progress indicators.
5. **Environment configuration** — Smart defaults pre-filled for dev. Production path validates each endpoint as the user provides it (is Postgres reachable? Is Kafka healthy?).

### Critical Success Moments

1. **The Fork (screen one)** — "Dev or Production?" must be immediately clear. Wrong path = wasted minutes. Descriptions should paint the picture: "Dev: Docker Compose, local everything, 5 minutes" vs "Production: Your infrastructure, custom endpoints, guided validation."
2. **The Wait (infrastructure spinup)** — Docker pulls, service health checks, migration runs. Rich progress feedback (service-by-service status, elapsed time, what's happening now) prevents "is it stuck?" anxiety.
3. **The Validation Report (finale)** — Every service checked, every dependency verified, presented as a clear health table. Green/red/yellow per component. This IS the "know, not hope" moment.
4. **The Failure Recovery (when things break)** — Port conflicts, Docker not running, invalid API key, unreachable endpoints. Caught early, explained clearly, fix suggested. Never a raw stack trace.

### Experience Principles

1. **Validated confidence over silent success** — Never say "done" without proving it. Every step is verified and the result is shown.
2. **One decision, then autopilot** — Minimise choices. Smart defaults. The user steers, the wizard drives.
3. **Terminal-native, not terminal-tolerated** — Rich CLI output (colours, spinners, progress bars, tables) that feels like a first-class experience, not a bash script with echo statements.
4. **Fail fast, fail helpful** — Catch problems in seconds, not minutes. Every error message includes the fix.
