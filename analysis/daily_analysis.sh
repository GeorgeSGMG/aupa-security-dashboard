#!/bin/bash
# -----------------------------------------------------------------
# daily_analysis.sh - Daily security analysis
# Desafio Tripulaciones - Equipo 4 - Ciberseguridad
#
# Usage:
#   ./daily_analysis.sh <repo_path>
#
# Examples:
#   ./daily_analysis.sh ~/repos/aupa-backend
#   ./daily_analysis.sh ~/repos/aupa-frontend
#   ./daily_analysis.sh ~/repos/aupa-data
#
# Each repo must have a .sonar-config file in its root:
#   PROJECT_KEY="aupa-backend"
#   SONAR_TOKEN="sqp_xxxxxxxxxxxx"
# -----------------------------------------------------------------

# -- CONFIG -- edit before use ------------------------------------
SONAR_HOST="http://localhost:9000"
SONAR_USER="admin"
SONAR_PASS="YOUR_PASSWORD_HERE"
export SONAR_HOST SONAR_USER SONAR_PASS
# -----------------------------------------------------------------

SEP="----------------------------------------------------------------"

# -- Arguments ----------------------------------------------------
if [ $# -lt 1 ]; then
  echo "Usage: ./daily_analysis.sh <repo_path> [json_path]"
  echo "Example: ./daily_analysis.sh ~/repos/aupa-backend ~/dashboard/aupa-security-dashboard/data.json"
  exit 1
fi

REPO_PATH=$(realpath "$1")
JSON_PATH=""
if [ -n "$2" ]; then
  JSON_PATH=$(realpath "$2")
fi

if [ ! -d "$REPO_PATH" ]; then
  echo "ERROR: Directory not found: $REPO_PATH"
  exit 1
fi

# -- Load project config ------------------------------------------
CONFIG_FILE="$REPO_PATH/.sonar-config"

if [ ! -f "$CONFIG_FILE" ]; then
  echo "ERROR: .sonar-config not found in $REPO_PATH"
  echo ""
  echo "Create a .sonar-config file in the repo root with:"
  echo "  PROJECT_KEY=\"aupa-backend\""
  echo "  SONAR_TOKEN=\"sqp_xxxxxxxxxxxx\""
  exit 1
fi

source "$CONFIG_FILE"

if [ -z "$PROJECT_KEY" ] || [ -z "$SONAR_TOKEN" ]; then
  echo "ERROR: .sonar-config must define PROJECT_KEY and SONAR_TOKEN"
  exit 1
fi

# -- Detect project type ------------------------------------------
detect_type() {
  if [ -f "$REPO_PATH/pyproject.toml" ] || [ -f "$REPO_PATH/requirements.txt" ]; then
    echo "python"
  elif [ -f "$REPO_PATH/package.json" ]; then
    echo "node"
  else
    echo "unknown"
  fi
}

PROJECT_TYPE=$(detect_type)
DATE=$(date +"%d/%m/%Y")
DATE_FILE=$(date +"%Y%m%d")
COMMIT=$(git -C "$REPO_PATH" log --format="%H" -1 2>/dev/null || echo "unavailable")
BRANCH=$(git -C "$REPO_PATH" branch --show-current 2>/dev/null || echo "—")
MD_OUT="$(pwd)/informe_${PROJECT_KEY}_${DATE_FILE}.md"

echo ""
echo "$SEP"
echo "DAILY ANALYSIS - $PROJECT_KEY"
echo "Repo: $REPO_PATH  |  Type: $PROJECT_TYPE  |  Date: $DATE"
echo "$SEP"

# -- 1. SonarQube scan --------------------------------------------
echo ""
echo "[1/4] SonarQube - $PROJECT_KEY"
cd "$REPO_PATH" || exit 1

sonar-scanner \
  -Dsonar.projectKey="$PROJECT_KEY" \
  -Dsonar.sources=. \
  -Dsonar.exclusions="**/notebooks/**,**/__pycache__/**,**/node_modules/**,**/.git/**" \
  -Dsonar.host.url="$SONAR_HOST" \
  -Dsonar.token="$SONAR_TOKEN" \
  2>&1 | grep -E "ANALYSIS SUCCESSFUL|Analysis total|ERROR"

if [ ${PIPESTATUS[0]} -ne 0 ]; then
  echo "    ERROR: Scan failed. Is SonarQube running?"
  exit 1
fi

echo "    Scan completed. Waiting for server to process results..."
sleep 5

# -- 2. Semgrep (Docker) ------------------------------------------
echo ""
echo "[2/4] Semgrep"

if [ "$PROJECT_TYPE" = "python" ]; then
  SEMGREP_CONFIG="--config=p/python --config=p/owasp-top-ten"
elif [ "$PROJECT_TYPE" = "node" ]; then
  SEMGREP_CONFIG="--config=p/javascript --config=p/typescript --config=p/owasp-top-ten"
else
  SEMGREP_CONFIG="--config=auto"
fi

SEMGREP_OUTPUT=$(docker run --rm -v "$(pwd):/src" returntocorp/semgrep semgrep \
  $SEMGREP_CONFIG --text . 2>/dev/null)
SEMGREP_SUMMARY=$(echo "$SEMGREP_OUTPUT" | grep -E "^Ran|findings" | tail -1)
echo "    $SEMGREP_SUMMARY"

# -- 3. Dependency audit (Docker) ---------------------------------
echo ""
echo "[3/4] Dependency audit"

if [ "$PROJECT_TYPE" = "python" ]; then
  DEPS_OUTPUT=$(docker run --rm -v "$(pwd):/apps" -w /apps python:3.11-slim bash -c \
    "pip install --quiet pip-audit && pip-audit . 2>/dev/null" 2>/dev/null)
  echo "    $DEPS_OUTPUT"
elif [ "$PROJECT_TYPE" = "node" ]; then
  DEPS_OUTPUT=$(npm audit --audit-level=high 2>/dev/null)
  echo "    $DEPS_OUTPUT"
else
  DEPS_OUTPUT="Unknown project type - skipped"
  echo "    $DEPS_OUTPUT"
fi

# -- 4. Hardcoded secrets -----------------------------------------
echo ""
echo "[4/4] Hardcoded secrets search"

SECRETS=$(grep -rniE \
  "password|token|secret|api_key|apikey|db_url|private_key" \
  "$REPO_PATH" \
  --include="*.py" --include="*.js" --include="*.ts" \
  --include="*.yml" --include="*.yaml" --include="*.env*" \
  --exclude-dir=.git --exclude-dir=__pycache__ --exclude-dir=node_modules \
  --exclude="*.lock" 2>/dev/null)

if [ -z "$SECRETS" ]; then
  SECRETS_RESULT="No matches found"
else
  SECRETS_RESULT=$(echo "$SECRETS" | head -20)
fi
echo "    $SECRETS_RESULT"

# -- 5. Fetch results from SonarQube API --------------------------
echo ""
echo "[5/5] Fetching findings from SonarQube API..."

ISSUES_TMP=$(mktemp)
HOTSPOTS_TMP=$(mktemp)

export ISSUES_TMP HOTSPOTS_TMP PROJECT_KEY
python3 - << 'PYEOF'
import json, urllib.request, urllib.parse, os, base64

host    = os.environ["SONAR_HOST"]
user    = os.environ["SONAR_USER"]
passwd  = os.environ["SONAR_PASS"]
project = os.environ["PROJECT_KEY"]
issues_tmp  = os.environ["ISSUES_TMP"]
hotspots_tmp = os.environ["HOTSPOTS_TMP"]

credentials = base64.b64encode(f"{user}:{passwd}".encode()).decode()
headers = {"Authorization": f"Basic {credentials}"}

def fetch_paginated(url_base, result_key, total_key_path):
    all_items = []
    page = 1
    total = 1
    while len(all_items) < total:
        url = f"{url_base}&ps=500&p={page}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as r:
            data = json.load(r)
        # Obtener total
        t = data
        for k in total_key_path:
            t = t.get(k, 0)
        total = t or 0
        items = data.get(result_key, [])
        all_items.extend(items)
        if not items or total == 0:
            break
        page += 1
        if page > 20:
            break
    return all_items, total

# Issues
issues_url = f"{host}/api/issues/search?projects={project}&resolved=false"
issues, issues_total = fetch_paginated(issues_url, "issues", ["total"])
with open(issues_tmp, "w") as f:
    json.dump({"issues": issues, "total": issues_total}, f)

# Hotspots
hotspots_url = f"{host}/api/hotspots/search?projectKey={project}"
hotspots, hotspots_total = fetch_paginated(hotspots_url, "hotspots", ["paging", "total"])
with open(hotspots_tmp, "w") as f:
    json.dump({"hotspots": hotspots, "paging": {"total": hotspots_total}}, f)

print(f"    Issues recogidos: {len(issues)} / {issues_total}")
print(f"    Hotspots recogidos: {len(hotspots)} / {hotspots_total}")
PYEOF

export MD_OUT
export DATE
export COMMIT
export BRANCH
export JSON_PATH
# -- Report for template ------------------------------------------
echo ""
echo "$SEP"
echo "INFORME - DATOS PARA EL TEMPLATE"
echo "$SEP"

echo ""
echo "--- 1. IDENTIFICACION DEL ANALISIS ---"
echo ""
echo "Fecha:          $DATE"
echo "Rama analizada: [la rama configurada en SonarQube al crear el proyecto]"
echo "Commit:         $COMMIT"

echo ""
echo "--- 2. RESUMEN DEL ANALISIS ---"
echo ""
echo "2.1 Issues"
echo ""

python3 - << PYEOF
import json, sys, os

issues_raw = open(os.environ.get("ISSUES_TMP","")).read()
try:
    d = json.loads(issues_raw)
    issues = d.get('issues', [])
except:
    print("    ERROR: Could not parse SonarQube API response")
    sys.exit(0)

SEV_MAP = {
    'BLOCKER':  'Critico',
    'CRITICAL': 'Critico',
    'MAJOR':    'Alto',
    'MINOR':    'Medio',
    'INFO':     'Bajo',
}
OWASP_MAP = {
    # Docker
    'docker:S7019': 'A05:2025 — Security Misconfiguration',
    'docker:S6470': 'A05:2025 — Security Misconfiguration',
    # Python — seguridad
    'python:S105':  'A02:2025 — Cryptographic Failures',
    'python:S106':  'A02:2025 — Cryptographic Failures',
    'python:S4790': 'A02:2025 — Cryptographic Failures',
    'python:S5332': 'A02:2025 — Cryptographic Failures',
    'python:S2076': 'A03:2025 — Injection',
    'python:S2077': 'A03:2025 — Injection',
    'python:S5131': 'A03:2025 — Injection',
    'python:S2083': 'A01:2025 — Broken Access Control',
    'python:S5144': 'A01:2025 — Broken Access Control',
    'python:S5727': 'A07:2025 — Identification and Authentication Failures',
    'python:S6096': 'A08:2025 — Software and Data Integrity Failures',
    # Python — calidad con impacto de seguridad
    'python:S1186': 'A05:2025 — Security Misconfiguration',
    'python:S1192': 'A05:2025 — Security Misconfiguration',
    'python:S125':  'A05:2025 — Security Misconfiguration',
    # JavaScript
    'javascript:S2631': 'A03:2025 — Injection',
    'javascript:S5131': 'A03:2025 — Injection',
    'javascript:S4790': 'A02:2025 — Cryptographic Failures',
    'javascript:S5332': 'A02:2025 — Cryptographic Failures',
    'javascript:S5144': 'A01:2025 — Broken Access Control',
    'javascript:S5122': 'A05:2025 — Security Misconfiguration',
    # TypeScript — seguridad
    'typescript:S2631': 'A03:2025 — Injection',
    # TypeScript — calidad con impacto de seguridad
    'typescript:S1082': 'A04:2025 — Insecure Design',
    'typescript:S1128': 'A05:2025 — Security Misconfiguration',
    'typescript:S1854': 'A05:2025 — Security Misconfiguration',
    'typescript:S2137': 'A04:2025 — Insecure Design',
    'typescript:S3358': 'A04:2025 — Insecure Design',
    'typescript:S3863': 'A05:2025 — Security Misconfiguration',
    'typescript:S4325': 'A05:2025 — Security Misconfiguration',
    'typescript:S4624': 'A04:2025 — Insecure Design',
    'typescript:S6479': 'A05:2025 — Security Misconfiguration',
    'typescript:S6481': 'A05:2025 — Security Misconfiguration',
    'typescript:S6571': 'A04:2025 — Insecure Design',
    'typescript:S6582': 'A05:2025 — Security Misconfiguration',
    'typescript:S6772': 'A04:2025 — Insecure Design',
    'typescript:S6819': 'A05:2025 — Security Misconfiguration',
    'typescript:S6847': 'A05:2025 — Security Misconfiguration',
    'typescript:S6848': 'A05:2025 — Security Misconfiguration',
    'typescript:S6853': 'A05:2025 — Security Misconfiguration',
    'typescript:S7735': 'A05:2025 — Security Misconfiguration',
    'typescript:S7748': 'A05:2025 — Security Misconfiguration',
    'typescript:S7763': 'A05:2025 — Security Misconfiguration',
    'typescript:S7764': 'A05:2025 — Security Misconfiguration',
    'typescript:S7772': 'A05:2025 — Security Misconfiguration',
    'typescript:S7773': 'A05:2025 — Security Misconfiguration',
    'typescript:S7776': 'A04:2025 — Insecure Design',
    # Web
    'Web:S5725': 'A08:2025 — Software and Data Integrity Failures',
    'css:S7924':  'A05:2025 — Security Misconfiguration',
}

counts = {'Critico': 0, 'Alto': 0, 'Medio': 0, 'Bajo': 0}
for i in issues:
    sev = SEV_MAP.get(i.get('severity',''), 'Bajo')
    counts[sev] = counts.get(sev, 0) + 1
total = sum(counts.values())

print(f"{'Severidad':<12} {'Hallazgos nuevos':<20} {'Resueltos hoy':<16} {'Pendientes':<14} {'Total acum.'}")
print("-" * 70)
for sev in ['Critico', 'Alto', 'Medio', 'Bajo']:
    n = counts[sev]
    print(f"{sev:<12} {n:<20} {'0':<16} {str(n):<14} {n}")
print(f"{'Total':<12} {total:<20} {'0':<16} {str(total):<14} {total}")

print()
print("2.2 Security Hotspots")
print()

hotspots_raw = open(os.environ.get("HOTSPOTS_TMP","")).read()
try:
    hd = json.loads(hotspots_raw)
    hotspots = hd.get('hotspots', [])
except:
    print("    ERROR: Could not parse hotspots response")
    sys.exit(0)

PROB_MAP = {'HIGH': 'Alta', 'MEDIUM': 'Media', 'LOW': 'Baja'}
hcounts = {'Alta': 0, 'Media': 0, 'Baja': 0}
for h in hotspots:
    prob = PROB_MAP.get(h.get('vulnerabilityProbability',''), 'Baja')
    hcounts[prob] = hcounts.get(prob, 0) + 1
htotal = sum(hcounts.values())

print(f"{'Probabilidad':<14} {'Hallazgos nuevos':<20} {'Resueltos hoy':<16} {'Pendientes':<14} {'Total acum.'}")
print("-" * 70)
for prob in ['Alta', 'Media', 'Baja']:
    n = hcounts[prob]
    print(f"{prob:<14} {n:<20} {'0':<16} {str(n):<14} {n}")
print(f"{'Total':<14} {htotal:<20} {'0':<16} {str(htotal):<14} {htotal}")

print()
print("--- 3. HALLAZGOS DEL DIA ---")
print()
print("3.1 Issues")
print()

if not issues:
    print("    No issues found.")
else:
    for idx, issue in enumerate(issues, 1):
        rule   = issue.get('rule', '')
        sev    = SEV_MAP.get(issue.get('severity',''), issue.get('severity',''))
        msg    = issue.get('message', '')
        comp   = issue.get('component', '').replace(issue.get('project','') + ':', '')
        line   = issue.get('line', '?')
        owasp  = OWASP_MAP.get(rule, 'Revisar manualmente en SonarQube')
        itype  = issue.get('type', '')
        pri    = 'Inmediata' if sev == 'Critico' else 'Esta semana' if sev == 'Alto' else 'Backlog'
        impacts_raw = issue.get('impacts', [])
        impacts_str = ', '.join([f"{i.get('softwareQuality','')} ({i.get('severity','')})" for i in impacts_raw]) or '-'

        print(f"Issue #{idx}")
        print(f"{'Campo':<16} Detalle")
        print("-" * 60)
        print(f"{'Descripcion':<16} {msg}")
        print(f"{'Fichero/linea':<16} {comp} - linea {line}")
        print(f"{'Severidad':<16} {sev} ({issue.get('severity','')})")
        print(f"{'Impactos':<16} {impacts_str}")
        print(f"{'Tipo':<16} {itype}")
        print(f"{'OWASP':<16} {owasp}")
        print(f"{'Prioridad':<16} {pri}")
        print()

print("3.2 Security Hotspots")
print()

if not hotspots:
    print("    No hotspots found.")
else:
    for idx, h in enumerate(hotspots, 1):
        msg   = h.get('message', '')
        comp  = h.get('component', '').replace(h.get('project','') + ':', '')
        line  = h.get('line', '?')
        prob  = PROB_MAP.get(h.get('vulnerabilityProbability',''), h.get('vulnerabilityProbability',''))
        cat   = h.get('securityCategory', '')
        pri   = 'Inmediata' if prob == 'Alta' else 'Esta semana'

        print(f"Security Hotspot #{idx}")
        print(f"{'Campo':<16} Detalle")
        print("-" * 60)
        print(f"{'Descripcion':<16} {msg}")
        print(f"{'Fichero/linea':<16} {comp} - linea {line}")
        print(f"{'Probabilidad':<16} {prob}")
        print(f"{'Categoria':<16} {cat}")
        print(f"{'OWASP':<16} A02:2025 - Security Misconfiguration")
        print(f"{'Prioridad':<16} {pri}")
        print()

print("--- 4. ESTADO GENERAL ---")
print()
print("Tendencia:             [completar: comparar con el dia anterior]")
print("Observacion destacada: [completar: patrones, modulos con mas problemas, mejoras]")
print()
print("--- 5. NOTAS PARA EL EQUIPO DE DESARROLLO ---")
print()
print("[completar: recomendaciones concretas para el equipo de desarrollo]")
print()
print("--- 6. EVOLUCION ACUMULADA ---")
print()
print("Issues:")
print(f"{'Dia':<20} {'Criticos':<12} {'Altos':<10} {'Medios':<10} {'Bajos':<10} Total")
print("-" * 65)
print(f"{'Hoy':<20} {counts['Critico']:<12} {counts['Alto']:<10} {counts['Medio']:<10} {counts['Bajo']:<10} {total}")
print()
print("Security Hotspots:")
print(f"{'Dia':<20} {'Alta':<12} {'Media':<10} {'Baja':<10} Total")
print("-" * 55)
print(f"{'Hoy':<20} {hcounts['Alta']:<12} {hcounts['Media']:<10} {hcounts['Baja']:<10} {htotal}")

# -- Markdown generation ------------------------------------------
SEV_EMOJI = {'Critico': '🔴', 'Alto': '🟠', 'Medio': '🟡', 'Bajo': '🔵'}
PROB_EMOJI = {'Alta': '🔴', 'Media': '🟠', 'Baja': '🟡'}

md_path = os.environ.get("MD_OUT", "informe.md")
date    = os.environ.get("DATE", "")
commit  = os.environ.get("COMMIT", "")
branch  = os.environ.get("BRANCH", "—")
pk      = os.environ.get("PROJECT_KEY", "")

lines = []

# Sección 1
lines.append(f"# Informe diario de seguridad — {pk}")
lines.append(f"")
lines.append(f"## 1. Identificación del análisis")
lines.append(f"")
lines.append(f"| Campo | Detalle |")
lines.append(f"|---|---|")
lines.append(f"| Fecha | {date} |")
lines.append(f"| Rama analizada | {branch} |")
lines.append(f"| Commit | {commit} |")
lines.append(f"")

# Sección 2 — Issues
lines.append(f"## 2. Resumen del análisis")
lines.append(f"")
lines.append(f"### 2.1 Issues")
lines.append(f"")
lines.append(f"| Severidad | Hallazgos |")
lines.append(f"|---|---|")
for sev in ['Critico', 'Alto', 'Medio', 'Bajo']:
    n = counts[sev]
    emoji = SEV_EMOJI[sev]
    lines.append(f"| {emoji} {sev} | {n} |")
lines.append(f"| **Total** | **{total}** |")
lines.append(f"")

# Sección 2 — Hotspots
lines.append(f"### 2.2 Security Hotspots")
lines.append(f"")
lines.append(f"| Probabilidad | Hallazgos |")
lines.append(f"|---|---|")
for prob in ['Alta', 'Media', 'Baja']:
    n = hcounts[prob]
    emoji = PROB_EMOJI[prob]
    lines.append(f"| {emoji} {prob} | {n} |")
lines.append(f"| **Total** | **{htotal}** |")
lines.append(f"")

# Sección 3 — Issues
lines.append(f"## 3. Hallazgos del día")
lines.append(f"")
lines.append(f"### 3.1 Issues")
lines.append(f"")

if not issues:
    lines.append("_No se encontraron issues._")
    lines.append("")
else:
    for idx, issue in enumerate(issues, 1):
        rule        = issue.get('rule', '')
        sev         = SEV_MAP.get(issue.get('severity',''), issue.get('severity',''))
        msg         = issue.get('message', '')
        comp        = issue.get('component', '').replace(issue.get('project','') + ':', '')
        line        = issue.get('line', '?')
        owasp       = OWASP_MAP.get(rule, 'Revisar manualmente en SonarQube')
        itype       = issue.get('type', '')
        pri         = 'Inmediata' if sev == 'Critico' else 'Esta semana' if sev == 'Alto' else 'Backlog'
        impacts_raw = issue.get('impacts', [])
        impacts_str = ', '.join([f"{i.get('softwareQuality','')} ({i.get('severity','')})" for i in impacts_raw]) or '—'
        emoji       = SEV_EMOJI.get(sev, '')

        lines.append(f"#### Hallazgo #{idx}")
        lines.append(f"")
        lines.append(f"| Campo | Detalle |")
        lines.append(f"|---|---|")
        lines.append(f"| Descripción | {msg} |")
        lines.append(f"| Fichero/línea | {comp} - línea {line} |")
        lines.append(f"| Severidad | {emoji} {sev} ({issue.get('severity','')}) |")
        lines.append(f"| Impactos | {impacts_str} |")
        lines.append(f"| Tipo | {itype} |")
        lines.append(f"| OWASP | {owasp} |")
        lines.append(f"| Prioridad | {pri} |")
        lines.append(f"")

# Sección 3 — Hotspots
lines.append(f"### 3.2 Security Hotspots")
lines.append(f"")

if not hotspots:
    lines.append("_No se encontraron security hotspots._")
    lines.append("")
else:
    for idx, h in enumerate(hotspots, 1):
        msg   = h.get('message', '')
        comp  = h.get('component', '').replace(h.get('project','') + ':', '')
        line  = h.get('line', '?')
        prob  = PROB_MAP.get(h.get('vulnerabilityProbability',''), h.get('vulnerabilityProbability',''))
        cat   = h.get('securityCategory', '')
        pri   = 'Inmediata' if prob == 'Alta' else 'Esta semana'
        emoji = PROB_EMOJI.get(prob, '')

        lines.append(f"#### Hallazgo #{idx}")
        lines.append(f"")
        lines.append(f"| Campo | Detalle |")
        lines.append(f"|---|---|")
        lines.append(f"| Descripción | {msg} |")
        lines.append(f"| Fichero/línea | {comp} - línea {line} |")
        lines.append(f"| Probabilidad | {emoji} {prob} |")
        lines.append(f"| Categoría | {cat} |")
        lines.append(f"| OWASP | A02:2025 — Security Misconfiguration |")
        lines.append(f"| Prioridad | {pri} |")
        lines.append(f"")

with open(md_path, 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))

print(f"\n    Markdown generado: {md_path}")

# -- JSON generation for dashboard ----------------------------
import datetime

json_path = os.environ.get("JSON_PATH", "")

if json_path:
    # Leer JSON existente o crear estructura vacía
    existing = {}
    if os.path.exists(json_path):
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                existing = json.load(f)
        except:
            existing = {}

    # Construir sección de este repo
    repo_data = {
        "project_key": pk,
        "date": date,
        "branch": branch,
        "commit": commit,
        "issues": {
            "Critico": counts['Critico'],
            "Alto":    counts['Alto'],
            "Medio":   counts['Medio'],
            "Bajo":    counts['Bajo'],
            "total":   total,
        },
        "hotspots": {
            "Alta":  hcounts['Alta'],
            "Media": hcounts['Media'],
            "Baja":  hcounts['Baja'],
            "total": htotal,
        },
        "issue_findings": [
            {
                "desc":     issue.get('message', ''),
                "file":     issue.get('component', '').replace(issue.get('project','') + ':', ''),
                "line":     issue.get('line', '?'),
                "sev":      SEV_MAP.get(issue.get('severity',''), issue.get('severity','')),
                "sev_raw":  issue.get('severity', ''),
                "type":     issue.get('type', ''),
                "owasp":    OWASP_MAP.get(issue.get('rule',''), 'Revisar manualmente en SonarQube'),
                "priority": 'Inmediata' if SEV_MAP.get(issue.get('severity',''), '') == 'Critico' else 'Esta semana' if SEV_MAP.get(issue.get('severity',''), '') == 'Alto' else 'Backlog',
                "impacts":  ', '.join([f"{i.get('softwareQuality','')} ({i.get('severity','')})" for i in issue.get('impacts', [])]) or '—',
            }
            for issue in issues
        ],
        "hotspot_findings": [
            {
                "desc":    h.get('message', ''),
                "file":    h.get('component', '').replace(h.get('project','') + ':', ''),
                "line":    h.get('line', '?'),
                "prob":    PROB_MAP.get(h.get('vulnerabilityProbability',''), h.get('vulnerabilityProbability','')),
                "cat":     h.get('securityCategory', ''),
                "priority": 'Inmediata' if PROB_MAP.get(h.get('vulnerabilityProbability',''), '') == 'Alta' else 'Esta semana',
            }
            for h in hotspots
        ],
        "updated_at": datetime.datetime.now().isoformat(),
    }

    # Actualizar solo la sección de este repo
    existing[pk] = repo_data

    # Añadir nueva entrada al histórico (una por ejecución, sin sobreescribir)
    now = datetime.datetime.now()
    run_id = now.strftime("%Y%m%d_%H%M%S")
    history = existing.get("history", [])
    history.append({
        "run_id":  run_id,
        "date":    date,
        "time":    now.strftime("%H:%M:%S"),
        "repo":    pk,
        "branch":  branch,
        "commit":  commit,
        "issues": {
            "Critico": counts['Critico'],
            "Alto":    counts['Alto'],
            "Medio":   counts['Medio'],
            "Bajo":    counts['Bajo'],
            "total":   total,
        },
        "hotspots": {
            "Alta":  hcounts['Alta'],
            "Media": hcounts['Media'],
            "Baja":  hcounts['Baja'],
            "total": htotal,
        },
    })
    existing["history"] = history

    # Añadir metadatos globales (excluir claves internas de la lista de repos)
    repo_keys = [k for k in existing.keys() if k not in ("_meta", "history")]
    existing["_meta"] = {
        "last_updated": datetime.datetime.now().isoformat(),
        "repos": repo_keys,
    }

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(existing, f, ensure_ascii=False, indent=2)

    print(f"    JSON actualizado: {json_path}")
else:
    print("    AVISO: JSON_PATH no especificado, JSON no generado")
PYEOF

echo ""
echo "$SEP"
echo "FICHEROS GENERADOS"
echo "$SEP"
echo ""
echo "  Markdown:  $MD_OUT"
echo "  JSON:      $JSON_PATH"
echo ""

echo "$SEP"
