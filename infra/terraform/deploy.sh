#!/usr/bin/env bash
# =============================================================================
# ALUSKORT SOC Platform — AWS Production Deployment Wizard
# =============================================================================
# Interactive setup wizard that collects configuration, generates terraform.tfvars,
# builds & pushes Docker images, and runs Terraform apply.
#
# Usage: bash deploy.sh [--plan-only] [--destroy] [--skip-build]
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TFVARS_FILE="$SCRIPT_DIR/terraform.tfvars"

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ---------- Helpers ----------
banner() {
    echo ""
    echo -e "${RED}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${RED}│${NC}  ${BOLD}ALUSKORT SOC Platform${NC} — AWS Production Deployment       ${RED}│${NC}"
    echo -e "${RED}│${NC}  Applied Computing Technologies                          ${RED}│${NC}"
    echo -e "${RED}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

step() { echo -e "\n${CYAN}━━━ Step $1: $2 ━━━${NC}\n"; }
info() { echo -e "${BLUE}ℹ${NC}  $1"; }
ok()   { echo -e "${GREEN}✓${NC}  $1"; }
warn() { echo -e "${YELLOW}⚠${NC}  $1"; }
err()  { echo -e "${RED}✗${NC}  $1" >&2; }

prompt() {
    local var_name="$1" prompt_text="$2" default="${3:-}"
    if [[ -n "$default" ]]; then
        echo -en "${BOLD}$prompt_text${NC} [${GREEN}$default${NC}]: "
        read -r input
        eval "$var_name=\"${input:-$default}\""
    else
        echo -en "${BOLD}$prompt_text${NC}: "
        read -r input
        eval "$var_name=\"$input\""
    fi
}

prompt_secret() {
    local var_name="$1" prompt_text="$2"
    echo -en "${BOLD}$prompt_text${NC}: "
    read -rs input
    echo ""
    eval "$var_name=\"$input\""
}

confirm() {
    echo -en "${YELLOW}$1 [y/N]:${NC} "
    read -r yn
    [[ "$yn" =~ ^[Yy] ]]
}

# ---------- Pre-flight checks ----------
preflight() {
    step "0" "Pre-flight Checks"
    local missing=0

    for cmd in terraform aws docker; do
        if command -v "$cmd" &>/dev/null; then
            ok "$cmd found: $(command -v "$cmd")"
        else
            err "$cmd not found — please install it first"
            missing=1
        fi
    done

    if ! aws sts get-caller-identity &>/dev/null; then
        err "AWS credentials not configured. Run: aws configure"
        missing=1
    else
        local acct_id
        acct_id=$(aws sts get-caller-identity --query Account --output text)
        ok "AWS authenticated — account $acct_id"
    fi

    if [[ $missing -eq 1 ]]; then
        err "Missing dependencies. Please install them and try again."
        exit 1
    fi
}

# ---------- Parse args ----------
PLAN_ONLY=false
DESTROY=false
SKIP_BUILD=false

for arg in "$@"; do
    case "$arg" in
        --plan-only)  PLAN_ONLY=true ;;
        --destroy)    DESTROY=true ;;
        --skip-build) SKIP_BUILD=true ;;
        --help|-h)
            echo "Usage: bash deploy.sh [--plan-only] [--destroy] [--skip-build]"
            echo ""
            echo "  --plan-only   Generate tfvars and run 'terraform plan' without applying"
            echo "  --destroy     Tear down all infrastructure"
            echo "  --skip-build  Skip Docker build/push (use existing ECR images)"
            exit 0
            ;;
    esac
done

# ---------- Main ----------
banner

if $DESTROY; then
    warn "DESTROY MODE — this will tear down ALL infrastructure"
    if confirm "Are you sure you want to destroy everything?"; then
        cd "$SCRIPT_DIR"
        terraform destroy -auto-approve
        ok "Infrastructure destroyed."
    fi
    exit 0
fi

preflight

# ===========================
# STEP 1: AWS Configuration
# ===========================
step "1" "AWS Configuration"

prompt AWS_REGION     "AWS region"                  "us-east-1"
prompt ENVIRONMENT    "Environment (prod/staging/dev)" "prod"
prompt VPC_CIDR       "VPC CIDR block"              "10.0.0.0/16"

# ===========================
# STEP 2: Domain & SSL
# ===========================
step "2" "Domain & SSL (Optional)"

info "If you have a domain and ACM certificate, the dashboard will use HTTPS."
info "Leave blank for HTTP-only access via ALB DNS name."
echo ""

prompt DOMAIN_NAME      "Domain name (e.g. soc.example.com)" ""
prompt ACM_CERT_ARN     "ACM certificate ARN" ""

# ===========================
# STEP 3: Database
# ===========================
step "3" "Database Configuration"

prompt DB_INSTANCE_CLASS "RDS instance class" "db.t4g.medium"

while true; do
    prompt_secret DB_PASSWORD "PostgreSQL master password (min 8 chars)"
    if [[ ${#DB_PASSWORD} -ge 8 ]]; then
        ok "Password accepted"
        break
    else
        err "Password must be at least 8 characters"
    fi
done

# ===========================
# STEP 4: Cache & Streaming
# ===========================
step "4" "Cache & Streaming"

prompt REDIS_NODE_TYPE    "ElastiCache Redis node type"  "cache.t4g.small"
prompt KAFKA_INSTANCE     "MSK Kafka instance type"      "kafka.t3.small"

# ===========================
# STEP 5: API Keys & Secrets
# ===========================
step "5" "API Keys & Secrets"

prompt_secret ANTHROPIC_KEY "Anthropic API key (sk-ant-...)"
if [[ -z "$ANTHROPIC_KEY" ]]; then
    warn "No Anthropic key provided — LLM features will be disabled"
fi

# ===========================
# STEP 6: Monitoring
# ===========================
step "6" "Monitoring & Alerts"

prompt ALARM_EMAIL "Email for CloudWatch alarm notifications" ""

# ===========================
# STEP 7: ECS Sizing
# ===========================
step "7" "ECS Service Sizing"

info "Default sizing is suitable for moderate workloads (~5k alerts/day)."
info "Adjust replica counts for your expected volume."
echo ""

prompt DASH_REPLICAS     "Dashboard replicas"         "2"
prompt GW_REPLICAS       "Context Gateway replicas"   "2"
prompt ROUTER_REPLICAS   "LLM Router replicas"        "2"
prompt ORCH_REPLICAS     "Orchestrator replicas"      "2"
prompt PARSER_REPLICAS   "Entity Parser replicas"     "1"
prompt CTEM_REPLICAS     "CTEM Normaliser replicas"   "1"

# ===========================
# Generate terraform.tfvars
# ===========================
step "8" "Generating Configuration"

cat > "$TFVARS_FILE" <<TFEOF
# Generated by deploy.sh on $(date -u '+%Y-%m-%dT%H:%M:%SZ')
# WARNING: Contains sensitive values — do not commit to git

aws_region          = "$AWS_REGION"
environment         = "$ENVIRONMENT"
vpc_cidr            = "$VPC_CIDR"

domain_name         = "$DOMAIN_NAME"
acm_certificate_arn = "$ACM_CERT_ARN"

db_instance_class   = "$DB_INSTANCE_CLASS"
db_password         = "$DB_PASSWORD"

redis_node_type     = "$REDIS_NODE_TYPE"
kafka_instance_type = "$KAFKA_INSTANCE"

anthropic_api_key   = "$ANTHROPIC_KEY"
alarm_email         = "$ALARM_EMAIL"

ecs_services = {
  dashboard = {
    cpu     = 512
    memory  = 1024
    port    = 8080
    count   = $DASH_REPLICAS
    command = ["uvicorn", "services.dashboard.app:app", "--host", "0.0.0.0", "--port", "8080"]
    public  = true
  }
  context-gateway = {
    cpu     = 1024
    memory  = 2048
    port    = 8030
    count   = $GW_REPLICAS
    command = ["uvicorn", "context_gateway.api:app", "--host", "0.0.0.0", "--port", "8030"]
    public  = false
  }
  llm-router = {
    cpu     = 512
    memory  = 1024
    port    = 8031
    count   = $ROUTER_REPLICAS
    command = ["uvicorn", "llm_router.api:app", "--host", "0.0.0.0", "--port", "8031"]
    public  = false
  }
  orchestrator = {
    cpu     = 1024
    memory  = 2048
    port    = 0
    count   = $ORCH_REPLICAS
    command = ["python", "-m", "orchestrator.service"]
    public  = false
  }
  entity-parser = {
    cpu     = 512
    memory  = 1024
    port    = 0
    count   = $PARSER_REPLICAS
    command = ["python", "-m", "entity_parser.service"]
    public  = false
  }
  ctem-normaliser = {
    cpu     = 512
    memory  = 1024
    port    = 0
    count   = $CTEM_REPLICAS
    command = ["python", "-m", "ctem_normaliser.service"]
    public  = false
  }
}
TFEOF

ok "Generated $TFVARS_FILE"

# ===========================
# Review
# ===========================
step "9" "Configuration Review"

echo -e "${BOLD}Region:${NC}        $AWS_REGION"
echo -e "${BOLD}Environment:${NC}   $ENVIRONMENT"
echo -e "${BOLD}VPC CIDR:${NC}      $VPC_CIDR"
echo -e "${BOLD}Domain:${NC}        ${DOMAIN_NAME:-"(none — HTTP via ALB)"}"
echo -e "${BOLD}SSL:${NC}           ${ACM_CERT_ARN:-"(none)"}"
echo -e "${BOLD}RDS:${NC}           $DB_INSTANCE_CLASS (Multi-AZ: $([ "$ENVIRONMENT" = "prod" ] && echo "yes" || echo "no"))"
echo -e "${BOLD}Redis:${NC}         $REDIS_NODE_TYPE"
echo -e "${BOLD}Kafka:${NC}         $KAFKA_INSTANCE"
echo -e "${BOLD}Alerts:${NC}        ${ALARM_EMAIL:-"(none)"}"
echo -e "${BOLD}Services:${NC}      dashboard=$DASH_REPLICAS, gateway=$GW_REPLICAS, router=$ROUTER_REPLICAS, orch=$ORCH_REPLICAS, parser=$PARSER_REPLICAS, ctem=$CTEM_REPLICAS"
echo ""

# Estimated monthly cost
info "Estimated monthly cost (approximate):"
echo -e "  RDS $DB_INSTANCE_CLASS:     ~\$50-100/mo"
echo -e "  ElastiCache:               ~\$25-50/mo"
echo -e "  MSK (3 brokers):           ~\$150-200/mo"
echo -e "  ECS Fargate:               ~\$100-200/mo"
echo -e "  ALB + NAT:                 ~\$40-60/mo"
echo -e "  ${BOLD}Total estimate:          ~\$365-610/mo${NC}"
echo ""

if ! confirm "Proceed with deployment?"; then
    info "Aborted. Your config is saved at $TFVARS_FILE"
    info "Re-run or edit the file, then: cd $SCRIPT_DIR && terraform apply -var-file=terraform.tfvars"
    exit 0
fi

# ===========================
# Terraform Init & Plan
# ===========================
step "10" "Terraform Init"

cd "$SCRIPT_DIR"
terraform init -upgrade

step "11" "Terraform Plan"
terraform plan -var-file="$TFVARS_FILE" -out=deploy.tfplan

if $PLAN_ONLY; then
    ok "Plan complete. Review above and run: terraform apply deploy.tfplan"
    exit 0
fi

# ===========================
# Terraform Apply
# ===========================
step "12" "Terraform Apply"

if ! confirm "Apply the plan above?"; then
    info "Aborted. Run manually: terraform apply deploy.tfplan"
    exit 0
fi

terraform apply deploy.tfplan
rm -f deploy.tfplan

# ===========================
# Docker Build & Push
# ===========================
if ! $SKIP_BUILD; then
    step "13" "Build & Push Docker Images"

    ACCT_ID=$(aws sts get-caller-identity --query Account --output text)
    ECR_BASE="$ACCT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

    info "Logging into ECR..."
    aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$ECR_BASE"

    SERVICES=("dashboard" "context-gateway" "llm-router" "orchestrator" "entity-parser" "ctem-normaliser")
    for svc in "${SERVICES[@]}"; do
        ECR_URI="$ECR_BASE/aluskort-$ENVIRONMENT/$svc"
        info "Building & pushing $svc..."
        docker build -t "$ECR_URI:latest" -f "$REPO_ROOT/Dockerfile" "$REPO_ROOT"
        docker push "$ECR_URI:latest"
        ok "$svc pushed to ECR"
    done

    # Force new deployment to pull latest images
    info "Triggering ECS redeployment..."
    CLUSTER="aluskort-$ENVIRONMENT-cluster"
    for svc in "${SERVICES[@]}"; do
        aws ecs update-service --cluster "$CLUSTER" --service "$svc" --force-new-deployment --region "$AWS_REGION" >/dev/null 2>&1 || true
    done
    ok "ECS services restarting with new images"
fi

# ===========================
# Run DB Migrations
# ===========================
step "14" "Database Migrations"

info "Running migrations via ECS Exec..."
CLUSTER="aluskort-$ENVIRONMENT-cluster"
TASK_ARN=$(aws ecs list-tasks --cluster "$CLUSTER" --service-name dashboard --query 'taskArns[0]' --output text --region "$AWS_REGION" 2>/dev/null || echo "")

if [[ -n "$TASK_ARN" && "$TASK_ARN" != "None" ]]; then
    info "Waiting for dashboard task to reach RUNNING..."
    aws ecs wait tasks-running --cluster "$CLUSTER" --tasks "$TASK_ARN" --region "$AWS_REGION" 2>/dev/null || true

    # Run migrations inside container
    aws ecs execute-command \
        --cluster "$CLUSTER" \
        --task "$TASK_ARN" \
        --container dashboard \
        --interactive \
        --command "python -m infra.scripts.migrate" \
        --region "$AWS_REGION" 2>/dev/null || warn "Auto-migration failed — run manually if needed"
else
    warn "Could not find running dashboard task — run migrations manually"
fi

# ===========================
# Done!
# ===========================
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Deployment complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Show outputs
ALB_DNS=$(terraform output -raw alb_dns_name 2>/dev/null || echo "pending")
DASHBOARD_URL=$(terraform output -raw dashboard_url 2>/dev/null || echo "pending")

echo -e "${BOLD}Dashboard URL:${NC}  $DASHBOARD_URL"
echo -e "${BOLD}ALB DNS:${NC}        $ALB_DNS"
echo ""

if [[ -n "$DOMAIN_NAME" ]]; then
    echo -e "${YELLOW}DNS Setup Required:${NC}"
    echo -e "  Create a CNAME record:  $DOMAIN_NAME -> $ALB_DNS"
    echo ""
fi

echo -e "${BOLD}Next steps:${NC}"
echo "  1. Verify dashboard:  curl -s $DASHBOARD_URL/health"
echo "  2. Check ECS services: aws ecs list-services --cluster aluskort-$ENVIRONMENT-cluster"
echo "  3. View logs:          aws logs tail /ecs/aluskort-$ENVIRONMENT/dashboard --follow"
echo "  4. Monitor:            Open CloudWatch dashboard 'aluskort-$ENVIRONMENT-overview'"
echo ""
echo -e "${BLUE}To tear down: bash deploy.sh --destroy${NC}"
echo ""
