# 🛡️ Aupa Security Dashboard

Dashboard de seguridad desarrollado durante el **Desafío de Tripulaciones** para la empresa **Inetum**, en el marco del bootcamp oficial de ciberseguridad de **The Bridge**.

El proyecto analiza la seguridad de tres repositorios de la aplicación **Aupa** (web app turística para Euskadi) mediante análisis de seguridad diarios cuyos resultados se visualizan en un dashboard con histórico acumulado.

🔗 **[Ver dashboard](https://georgesgmg.github.io/aupa-security-dashboard/)**

🔗 **[Ver presentación](https://aupa-app.lovable.app/)**

---

## Cómo funciona

```
daily_analysis.sh <repo>
        │
        ├── SonarQube (análisis estático)
        ├── Semgrep (reglas OWASP Top 10 2025)
        ├── pip-audit / npm audit (dependencias)
        └── grep (secretos hardcodeados)
                │
                ▼
        informe_<repo>_<fecha>.md
        data.json (histórico acumulado)
                │
                ▼
        Dashboard GitHub Pages
```

El script se lanzaba a diario sobre cada repositorio. Los resultados se guardaban en `data.json`, que alimenta el dashboard.

---

## Repositorios analizados

| Repo | Stack |
|---|---|
| repo-aupa-data | Python + FastAPI + Docker |
| repo-aupa-backend | Node/Express + TypeScript |
| repo-aupa-frontend | React + TypeScript + Vite |

---

## Requisitos

- [SonarQube](https://www.sonarqube.org/) corriendo en local (por defecto `http://localhost:9000`)
- [sonar-scanner](https://docs.sonarqube.org/latest/analysis/scan/sonarscanner/) instalado y en el PATH
- Docker (para Semgrep y pip-audit)
- Python 3
- bash

---

## Uso del script

```bash
./daily_analysis.sh <ruta_repo> [ruta_data.json]
```

### Configuración por repositorio

Cada repositorio analizado necesita un fichero `.sonar-config` en su raíz. Usa `.sonar-config.example` como plantilla:

```bash
cp analysis/.sonar-config.example /ruta/al/repositorio/.sonar-config
# Edita PROJECT_KEY y SONAR_TOKEN con los valores reales
```

El script también requiere editar las variables de conexión a SonarQube al inicio de `daily_analysis.sh`:

```bash
SONAR_HOST="http://localhost:9000"
SONAR_USER="admin"
SONAR_PASS="YOUR_PASSWORD_HERE"
```

---

## Estructura del repositorio

```
aupa-security-dashboard/
├── index.html              # Dashboard (GitHub Pages)
├── data.json               # Histórico acumulado de análisis
├── analysis/               # Herramientas de análisis diario
│   ├── daily_analysis.sh
│   └── .sonar-config.example
└── docs/                   # Documentación técnica (PDFs)
    ├── docs.json
    └── *.pdf
```

---

## Contexto

Proyecto desarrollado por el **Equipo 4 — "Más allá del Guggen"** del Desafío de Tripulaciones, con cuatro verticales: **Marketing Digital**, **Data Science**, **Full Stack** y **Ciberseguridad**.

---

*The Bridge · Desafío de Tripulaciones · Inetum*
