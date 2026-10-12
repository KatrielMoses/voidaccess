#!/usr/bin/env bash
# Step 2.1 — Check setup.sh exists and is executable
[ -f setup.sh ] && echo "✓ setup.sh exists" || echo "✗ setup.sh missing"
[ -x setup.sh ] && echo "✓ setup.sh executable" || (chmod +x setup.sh && echo "✓ Made executable")

# Step 2.2 — Run setup.sh non-interactively
printf "2\nsk-or-v1-TEST-NOT-A-REAL-KEY\n\n\nn\ny\ny\nadmin@voidaccess.tech\ntest-password-not-real\ntest-password-not-real\n" \
  | bash setup.sh 2>&1 | tee /tmp/setup_log.txt

SETUP_EXIT=$?
echo "setup.sh exit code: $SETUP_EXIT"

# Step 2.3 — Analyze setup.sh output
echo "=== Setup wizard output analysis ==="
STEPS=(
  "Prerequisites"
  "environment"
  "JWT_SECRET"
  "OpenRouter"
  "MITRE"
  "Starting"
  "ready"
  "Admin"
)

for STEP in "${STEPS[@]}"; do
  grep -qi "$STEP" /tmp/setup_log.txt && echo "✓ Step '$STEP' appeared" || echo "○ Step '$STEP' not found"
done

if grep -qi "error\|failed\|exception\|traceback" /tmp/setup_log.txt; then
  echo ""
  echo "⚠ Errors found in setup output:"
  grep -i "error\|failed\|exception" /tmp/setup_log.txt | head -10
fi

# Step 2.4 — Verify .env was created correctly
[ -f .env ] && echo "✓ .env created" || echo "✗ .env not created"

REQUIRED=(
  "JWT_SECRET"
  "POSTGRES_PASSWORD"
  "DATABASE_URL"
  "OPENROUTER_API_KEY"
  "DEFAULT_MODEL"
)

for VAR in "${REQUIRED[@]}"; do
  VAL=$(grep "^${VAR}=" .env 2>/dev/null | cut -d= -f2-)
  if [ -n "$VAL" ]; then
    echo "✓ $VAR set (${#VAL} chars)"
  else
    echo "✗ $VAR missing from .env"
  fi
done

JWT=$(grep "^JWT_SECRET=" .env | cut -d= -f2-)
[ "$JWT" = "supersecret" ] && echo "✗ CRITICAL: JWT_SECRET is weak default" || echo "✓ JWT_SECRET is not the weak default"

# Step 2.5 — Check if stack started from setup.sh
RUNNING=$(docker compose ps --format "{{.State}}" 2>/dev/null | grep -c "running" || echo "0")
echo "Services running after setup.sh: $RUNNING"
