# 🛡️ Container Image Threat Scanner with Layer-Aware Forensics

**Final Year BCA Project — BGS First Grade College, Mysore | 2025-2026**

> A professional-grade Docker container security scanner that detects vulnerabilities, 
> secrets, and misconfigurations — and traces every finding back to its exact originating layer.

---

## 🎯 Features

| Feature | Description |
|---------|-------------|
| 📦 Layer-by-layer analysis | Inspect each Docker image layer independently |
| 🔍 CVE detection | Match packages against NVD CVE database |
| 🔑 Secret scanning | Detect AWS keys, tokens, passwords in image files |
| 🛡️ Threat intelligence | Flag SUID binaries, root user, world-writable files |
| 🗺️ Forensic mapping | Trace every CVE to the exact layer that introduced it |
| 📊 Risk scoring | 0–10 score with A–F grade classification |
| 📄 Multi-format reports | JSON, YAML, SBOM (CycloneDX), plain text |
| 🖥️ Dashboard | Streamlit web dashboard with charts and heatmaps |
| ⚙️ CI/CD | GitHub Actions pipeline for automated scanning |

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Ensure Docker is running
```bash
docker info
```

### 3. Run a scan
```bash
python main.py nginx:latest
```

### 4. Launch dashboard
```bash
python main.py nginx:latest --dashboard
```

Or run dashboard standalone (uses demo data if no scan has been run):
```bash
streamlit run dashboard/app.py
```

---

## 📂 Project Structure

```
container-security-scanner/
├── scanner/
│   ├── image_pull.py           # Step 1: Pull Docker image, extract metadata
│   ├── layer_extractor.py      # Step 2: Extract filesystem layers
│   ├── package_enum.py         # Step 3: Enumerate packages, generate SBOM
│   ├── vulnerability_scanner.py# Step 4: CVE detection (NVD API + demo DB)
│   ├── threat_intelligence.py  # Step 5: Secret/misconfiguration detection
│   ├── forensic_mapper.py      # Step 6: Map findings to origin layers
│   ├── risk_engine.py          # Step 7: Calculate risk score
│   └── report_generator.py     # Step 8: Generate JSON/YAML/TXT reports
├── dashboard/
│   └── app.py                  # Streamlit visualization dashboard
├── utils/
│   └── helpers.py              # Shared utilities
├── ci/
│   └── scan.yml                # GitHub Actions workflow
├── reports/                    # Generated reports (auto-created)
├── main.py                     # CLI entry point
└── requirements.txt
```

---

## 💻 CLI Usage

```bash
# Basic scan
python main.py nginx:latest

# With live NVD API queries
python main.py alpine:3.18 --live-api

# Custom output directory
python main.py ubuntu:22.04 --output /tmp/scan_results/

# Print JSON to stdout
python main.py nginx:latest --json

# Launch dashboard after scan
python main.py nginx:latest --dashboard
```

---

## 📊 Sample Output

```
Scanning Image: nginx:latest

Layer 2 [a1b2c3d4e5f6]:
  Package: openssl 1.1.1n
  CVE: CVE-2023-0464 | Severity: HIGH | CVSS: 7.5
  Fix: apt-get upgrade openssl (target: 1.1.1u)

Layer 3 [b3c4d5e6f7a8]:
  Package: curl 7.88.1
  CVE: CVE-2023-38545 | Severity: CRITICAL | CVSS: 9.8
  Fix: apt-get upgrade curl (target: 8.4.0)

Image Risk Score: 7.2 / 10  (Grade: D)
CLASSIFICATION: HIGH RISK — Significant vulnerabilities detected.
```

---

## 🔬 Methodology

1. **Image Acquisition** — Pull from local cache or Docker Hub
2. **Layer Decomposition** — Extract filesystem tar archives per layer
3. **Filesystem Inspection** — Analyze files, permissions, metadata per layer
4. **Package Enumeration** — Parse dpkg/apk/rpm databases, generate SBOM
5. **CVE Matching** — Compare packages against NVD CVE database
6. **Threat Detection** — Regex-based secret scanning, misconfiguration checks
7. **Forensic Mapping** — Link every finding to its originating layer
8. **Risk Scoring** — Weighted CVSS-based score (0–10) with A–F grade
9. **Report Generation** — Structured reports in JSON, YAML, TXT formats

---

## 🛠️ System Requirements

- Python 3.9+
- Docker Engine 20.x+
- 8GB RAM (16GB recommended)
- 50GB free disk space
- Internet connection (for image pull + optional NVD API)

---

## 👨‍💻 Team

| Name | USN |
|------|-----|
| Harshitha Shree D | U01CO23S0201 |
| Spandana R S | U01CO23S0202 |
| Yogesh S | U01CO23S0203 |
| Pavan N | U01CO23S0204 |

**Guide:** Annapoorna M S, Assistant Professor, Dept. of BCA  
**Institution:** BGS First Grade College, Mysore

---

## 📚 References

- NIST NVD CVE Database: https://nvd.nist.gov
- Docker SDK for Python: https://docker-py.readthedocs.io
- CycloneDX SBOM Spec: https://cyclonedx.org
- OWASP Container Security: https://owasp.org
