# AI Workflow Init - AI Project Setup Instructions

<critical>The workflow execution engine is governed by: {project-root}/_bmad/core/tasks/workflow.xml</critical>
<critical>You MUST have already loaded and processed: ai-workflow-init/workflow.yaml</critical>
<critical>Communicate in {communication_language} with {user_name}</critical>
<critical>This workflow sets up AI/ML project tracking for Omeriko agent</critical>

<workflow>

<step n="1" goal="Welcome and scan for existing work">
<output>Welcome to Omeriko AI System Development, {user_name}! 🤖⚔️</output>

<action>Perform comprehensive scan for existing AI work:
- Omeriko artifacts: AI architecture docs, RAG designs, training strategies
- BMM artifacts: PRD, architecture, testing requirements  
- Data/Model artifacts: datasets, models, embeddings, vector DBs
- Check both {output_folder} and docs/ locations
</action>

<action>Categorize into one of these states:
- CLEAN: No AI artifacts (new project)
- DESIGN: Has AI design docs but no implementation
- ACTIVE: Has implementation artifacts or models
- UNCLEAR: Mixed state needs clarification
</action>

<ask>What's your AI project called? {{#if project_name}}(Config shows: {{project_name}}){{/if}}</ask>
<action>Store project_name</action>
<template-output>project_name</template-output>
</step>

<step n="2" goal="Choose setup path">
<check if="state == CLEAN">
  <output>Perfect! Fresh start detected. Let's design your AI system!</output>
  <action>Continue to step 3</action>
</check>

<check if="state == ACTIVE AND ai_workflow_status exists">
  <output>✅ You already have AI workflow tracking at: {{workflow_status_path}}

To check progress: Run `AI-STATUS` with Omeriko

Happy AI building! 🤖</output>
<action>Exit workflow (already initialized)</action>
</check>

<check if="state != CLEAN">
  <output>Found existing work:
{{summary_of_findings}}</output>

<ask>How would you like to proceed?

1. **Continue** - Work with existing artifacts
2. **Archive & Start Fresh** - Move old work to archive
3. **Express Setup** - I know exactly what I need
4. **Guided Setup** - Walk me through options

Choice [1-4]</ask>

  <check if="choice == 1">
    <action>Set continuing_existing = true</action>
    <action>Store found artifacts</action>
    <action>Continue to step 6 (detect track from artifacts)</action>
  </check>

  <check if="choice == 2">
    <ask>Archive existing work? (y/n)</ask>
    <action if="y">Move artifacts to {output_folder}/archive/</action>
    <output>Ready for fresh start!</output>
    <action>Continue to step 3</action>
  </check>

  <check if="choice == 3">
    <action>Jump to step 3 (express path)</action>
  </check>

  <check if="choice == 4">
    <action>Continue to step 4 (guided path)</action>
  </check>
</check>

<check if="state == CLEAN">
  <ask>Setup approach:

1. **Express** - I know what I need
2. **Guided** - Show me the options

Choice [1 or 2]:</ask>

  <check if="choice == 1">
    <action>Continue to step 3 (express)</action>
  </check>

  <check if="choice == 2">
    <action>Continue to step 4 (guided)</action>
  </check>
</check>
</step>

<step n="3" goal="Express setup path">
<ask>What type of AI system are you building?

1. **Full Cyber AI System** - Complete RAG + training + inference pipeline
2. **Quick RAG System** - Fast knowledge base implementation
3. **Custom Model Training** - Fine-tuning or training focused

Choice [1/2/3]:</ask>

<action>Map to ai_system_type and selected_track:
- 1 → cyber-ai, Full Cyber AI path
- 2 → quick-rag, Quick RAG path
- 3 → training-focused, Training path
</action>

<ask>Is this:
1. **New system** (greenfield)
2. **Adding AI to existing project** (brownfield)

Choice [1/2]:</ask>
<action>Set field_type based on choice</action>

<template-output>ai_system_type</template-output>
<template-output>selected_track</template-output>
<template-output>field_type</template-output>
<action>Jump to step 5 (configuration)</action>
</step>

<step n="4" goal="Guided setup - understand project">
<ask>Tell me about your AI project. What problem are you trying to solve with AI?</ask>
<action>Store user_description</action>

<action>Analyze for AI system type indicators:
- RAG/knowledge base keywords: "search", "documents", "knowledge", "retrieval", "answers"
- Training keywords: "classify", "detect", "train", "fine-tune", "labels"
- Full system: Complex requirements, multiple components
</action>

<output>Based on your description, I'd recommend:

{{#if rag_focused}}
🔍 **Quick RAG System** - For knowledge retrieval and Q&A
- Fast to implement
- Great for threat intel, forensics knowledge, playbooks
{{/if}}

{{#if training_focused}}
🎯 **Training Focused** - For classification/detection models
- Custom model development
- Malware classification, threat detection, etc.
{{/if}}

{{#if complex_system}}
🏗️ **Full Cyber AI System** - Complete architecture
- RAG + Training + Inference pipeline
- Production-ready design
{{/if}}
</output>

<ask>Which path would you like?

1. Full Cyber AI System (comprehensive)
2. Quick RAG System (fast knowledge base)
3. Training Focused (custom models)

Choice [1/2/3]:</ask>

<action>Set ai_system_type and selected_track based on choice</action>
<template-output>ai_system_type</template-output>
<template-output>selected_track</template-output>
<action>Set field_type = greenfield (default for new)</action>
<template-output>field_type</template-output>
</step>

<step n="5" goal="Deployment configuration">
<output>Let me capture your deployment constraints:</output>

<ask>Training environment:
1. **AWS** (SageMaker, Bedrock, full cloud)
2. **Local GPU** (RTX 4090 or similar)
3. **Hybrid** (AWS training, local inference)
4. **Other**

Choice [1/2/3/4]:</ask>
<action>Store training_environment</action>

<ask>Inference/Production environment:
1. **Cloud** (AWS, GCP, Azure)
2. **Air-gapped** (no external connectivity)
3. **On-prem** (local but with network)
4. **Hybrid**

Choice [1/2/3/4]:</ask>
<action>Store inference_environment</action>

<check if="inference_environment == air-gapped">
  <ask>Air-gapped GPU (for model size constraints)?
e.g., RTX 4090 (24GB), A100 (40GB/80GB), etc.</ask>
  <action>Store gpu_spec</action>
</check>

<template-output>training_environment</template-output>
<template-output>inference_environment</template-output>
<template-output>gpu_spec</template-output>
</step>

<step n="6" goal="Detect track from artifacts" if="continuing_existing">
<action>Analyze artifacts to detect track:
- Has RAG design → Quick RAG or Full
- Has training strategy → Training or Full
- Has PRD/architecture → In BMM handoff phase
</action>

<output>Detected: **{{detected_track}}** based on {{found_artifacts}}</output>
<ask>Correct? (y/n)</ask>

<ask if="n">Which AI development track instead?

1. Full Cyber AI System
2. Quick RAG System
3. Training Focused

Choice:</ask>

<action>Set selected_track</action>
<template-output>selected_track</template-output>
</step>

<step n="7" goal="Generate workflow path">
<action>Load path file: {path_files}/{{selected_track}}-{{field_type}}.yaml</action>
<action>Build workflow_items from path file</action>
<action>Scan for existing completed work and update statuses</action>
<action>Set generated date</action>

<template-output>generated</template-output>
<template-output>workflow_path_file</template-output>
<template-output>workflow_items</template-output>
</step>

<step n="8" goal="Create tracking file">
<output>Your Omeriko AI workflow path:

**Track:** {{selected_track}}
**Type:** {{field_type}}
**Project:** {{project_name}}
**AI System:** {{ai_system_type}}

**Training:** {{training_environment}}
**Inference:** {{inference_environment}} {{#if gpu_spec}}({{gpu_spec}}){{/if}}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{{workflow_path_summary}}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Phases:
1. **AI Design** (Omeriko) - SD, KB, TS, IO, CR
2. **Review** (Omeriko) - Critical review, research
3. **BMM Handoff** (Omeriko) - HO-PRD, HO-ARCH, HO-TEST
4. **Implementation** (BMM) - @architect, @dev, @qa
</output>

<ask>Create workflow tracking file? (y/n)</ask>

<check if="y">
  <action>Generate YAML from template with all variables</action>
  <action>Save to {output_folder}/ai-workflow-status.yaml</action>
  <action>Identify next workflow and agent</action>

<output>✅ **Created:** {output_folder}/ai-workflow-status.yaml

**Next Step:** {{next_workflow_name}}
**Agent:** {{next_agent}}
**Command:** {{next_command}}

To check progress anytime: Run `AI-STATUS` with Omeriko

Happy AI building! 🤖⚔️</output>
</check>

</step>

</workflow>
