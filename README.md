# Mailcious_Docs_scan_CI_CD
Mailcious_Docs_scan_CI_CD is a GitHub Actions workflow that automatically scans documents (.pdf, .docx, .txt) pushed to the repository for hidden QR codes or malicious links. It analyzes embedded content for suspicious patterns, flags potential threats, and generates detailed security reports as CI/CD artifacts.










![logo](https://github.com/user-attachments/assets/5ccf6f4b-6e3d-4472-be96-75ddda499fbd)


# 🔐 Automated Docker image Security Scanner  


In the modern era, most organizations have shifted from **monolithic architectures** to **microservices-based applications** deployed in **containerized environments** such as Docker and Kubernetes. While this transition improves scalability, agility, and deployment speed, it also introduces **new security challenges**. With CI/CD pipelines powering rapid software delivery, ensuring security at every stage—known as **DevSecOps**—has become a critical requirement.  

One of the major concerns in this landscape is the **detection and remediation of vulnerabilities** in Docker images, application code, and dependencies. Without continuous scanning and compliance mapping, organizations risk exposing their systems to attackers.  

To address this, we developed a **GitHub Actions workflow** that automatically:  
- Scans Docker images for vulnerabilities using **Trivy, Bandit, and Docker Scout**.  
- Generates **JSON and PDF reports** for detailed analysis.  
- Maps detected vulnerabilities to **NIST Cybersecurity Framework (CSF)**, **MITRE ATT&CK techniques**, and **OWASP Top 10 risks**.  

This project demonstrates **automated DevSecOps practices** and provides a framework for **threat assessment, vulnerability management, and compliance reporting** directly within the CI/CD pipeline.  


## 📌 Introduction  
Containers have become the backbone of modern application deployment, but they also introduce unique security challenges.  
This project, **Automated Docker Security Scanner**, was designed to address those challenges by **automating vulnerability scanning of Docker images and applications**.  

It combines multiple open-source tools and recognized cybersecurity frameworks into a single workflow.  
The output is a **professional, consolidated PDF report** that organizations can use to detect, analyze, and mitigate security risks.  

Key Features:  
- Scans Docker images and code for vulnerabilities.  
- Maps findings to **NIST CSF**, **MITRE ATT&CK**, and **OWASP Top 10**.  
- Automatically runs in **GitHub Actions** for CI/CD pipelines.  
- Generates a **detailed PDF report** with charts and compliance mappings.  

---

## 📂 File Structure  



```bash
.
├── .github/
│   └── workflows/
│       └── docker-scan.yml        # GitHub Actions workflow (runs scans automatically)
│
├── docker/
│   ├── Dockerfile                 # Custom Dockerfile used for building/scanning
│   └── app/
│       └── main.py                # Example Python application code to scan
│
├── scripts/
│   ├── generate_report.py         # Combines all scan results and produces a PDF
│   ├── gen_charts.py              # Optional: Generates Matplotlib charts for reports
│   └── mappings.py                # Maps findings to NIST CSF, MITRE, and OWASP
│
├── assets/
│   └── severity_chart.png         # Example chart embedded in the final PDF
│
├── reports/                       # JSON outputs of all scans
│   ├── trivy.json                 # Docker image vulnerabilities (Trivy)
│   ├── bandit.json                # Python code analysis (Bandit)
│   ├── docker_scout.json          # Dependency scans (Docker Scout)
│   ├── mitre_T1003.json           # Example MITRE ATT&CK mapping output
│   └── nist_report.json           # Consolidated report with NIST mapping
│
├── requirements.txt               # Python dependencies for scripts
├── report.pdf                     # Generated PDF report (final output)
└── README.md
```

**Explanation of structure:**  
- **`.github/workflows`** → CI/CD pipeline that triggers scans automatically on each commit.  
- **`docker/`** → Contains the Dockerfile and app to be scanned.  
- **`scripts/`** → Automation scripts for generating reports and framework mappings.  
- **`assets/`** → Images and charts used in PDF reporting.  
- **`reports/`** → Stores raw JSON scan results and final consolidated outputs.  
- **`requirements.txt`** → Lists dependencies (ReportLab, Matplotlib, etc.).  
- **`report.pdf`** → The final professional security report.  

---

## 🛠️ Technology Used  

- **Backend:** Python (scripts for scanning, mapping, and report generation).  
- **Frontend/Reports:**  
  - ReportLab → To generate structured PDF reports.  
  - Matplotlib → To generate severity charts and visual data.  
- **Security Tools:**  
  - **Trivy** → Detects vulnerabilities in Docker images.  
  - **Bandit** → Analyzes Python code for common security issues.  
  - **Docker Scout** → Checks image dependencies against known CVEs.  
- **Frameworks:**  
  - **NIST CSF** → Compliance & categorization.  
  - **MITRE ATT&CK** → Threat actor technique mapping.  
  - **OWASP Top 10** → Common web application risks.  
- **CI/CD:** GitHub Actions (automated scans in pipeline).  
- **Containerization:** Docker (for image builds and scans).  

---

## ⚙️ Workflow & Tools Used  

This project includes a **GitHub Actions workflow** (`.github/workflows/docker-scan.yml`) that automates the **DevSecOps security pipeline**.  
The workflow runs automatically on every push to the `main` branch and executes the following stages:  

---

### 🔹 1. Build Docker Image  
```yaml
- name: Build Docker Image
  run: docker build -t my-custom-app:latest ./docker
```
- Tool: Docker
- Purpose: Builds the application container image from the Dockerfile inside the ./docker directory.
- Output: A containerized application (my-custom-app:latest) that is ready for security scanning.


### 🔹 2. Trivy (Docker Image Vulnerability Scanner)

```
- name: Run Trivy Docker Scan
  run: trivy image --ignore-unfixed --exit-code 0 --format json --output reports/trivy.json my-custom-app:latest
```
- Tool: Trivy
- Purpose: Scans the built Docker image for known vulnerabilities (CVEs) in OS packages and dependencies.
- Output: reports/trivy.json → JSON report containing vulnerability details with severity levels.

### 🔹 3. Bandit (Python Source Code Analysis)

```
- name: Run Bandit Scan
  run: bandit -ll -ii -r . -f json -o reports/bandit.json || true
```
- Tool: Bandit
- Purpose: Performs Static Application Security Testing (SAST) for Python source code.
- Detects issues such as:
-Insecure function usage (eval, exec)
-Hardcoded credentials
-Insecure file permissions
- Output: reports/bandit.json → JSON report of security issues in code.


### 🔹 4. Docker Scout (Optional Dependency Scanner)

```
# docker scout quickview
# docker scout cves
```
- Tool: Docker Scout
- Purpose: Provides insights into container dependencies, image provenance, and supply chain vulnerabilities.
- Benefit: Complements Trivy by analyzing image layers and dependencies more deeply.

### 🔹 5. MITRE ATT&CK (Atomic Red Team Simulation)

```
- name: Run Atomic Red Team (MITRE ATT&CK)
  shell: pwsh
  run: |
    git clone https://github.com/redcanaryco/atomic-red-team.git
    git clone https://github.com/redcanaryco/invoke-atomicredteam.git
    Import-Module ./invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 -Force
    Invoke-AtomicTest T1003 ...
```
- Tools:
-Atomic Red Team
-Invoke-AtomicRedTeam

- Purpose: Simulates MITRE ATT&CK techniques against the container or application.
- Example: T1003 – Credential Dumping test.
- Output: reports/mitre_T1003.json → JSON report mapping vulnerabilities to real-world adversarial behaviors.

### 🔹 6. NIST CSF Mapping

```
- name: Map Results to NIST CSF
  run: python scripts/mappings.py reports/ nist_report.json
```

- Purpose: Maps scan results from Trivy, Bandit, and MITRE ATT&CK into NIST Cybersecurity Framework (CSF) categories:
- Identify → Asset discovery issues
- Protect → Missing patches, insecure configs
- Detect → Intrusion detection gaps
- Respond/Recover → Response & recovery mechanisms

### 🔹 7. Report Generation (Charts + PDF)

```
- name: Generate Charts
  run: python scripts/gen_charts.py

- name: Generate PDF Report
  run: python scripts/generate_report.py
```
- Purpose: Produces a professional PDF report consolidating:
- Vulnerability details
- Severity breakdown (with charts)
- NIST CSF mapping
- MITRE ATT&CK mapping
- OWASP Top 10 mapping


### 🔹 8. Upload Artifacts

```
- name: Upload PDF Report
  uses: actions/upload-artifact@v4
  with:
    name: docker-vulnerability-report
    path: report.pdf
```

- Purpose: Uploads both the PDF report and raw JSON reports as GitHub build artifacts.
- Benefit: Results can be downloaded and reviewed by security teams after each workflow run.






## ⚡ Security Framework Integration  

### 🔹 NIST Cybersecurity Framework (CSF)  
The **NIST CSF** provides five functions: **Identify, Protect, Detect, Respond, Recover**.  
Each vulnerability is automatically mapped to one of these functions.  
For example:  
- A missing patch may map to **Protect**.  
- An insecure API exposure may map to **Detect/Respond**.  

This ensures findings are not just technical but **aligned with compliance requirements**.  

### 🔹 MITRE ATT&CK  
The **MITRE ATT&CK** knowledge base describes how attackers exploit systems.  
Vulnerabilities detected are mapped to adversarial techniques.  
For example:  
- Credential leakage → **T1003 (Credential Dumping)**.  
- Insecure file permissions → **T1078 (Valid Accounts)**.  

This allows security teams to understand **how real attackers might exploit vulnerabilities**.  

### 🔹 OWASP Top 10  
The **OWASP Top 10** is an industry-standard list of the most critical web application risks.  
This scanner maps findings to OWASP categories, such as:  
- **A01: Broken Access Control**  
- **A03: Injection Attacks**  
- **A04: Insecure Design**  

This helps prioritize remediation according to **global best practices**.  

---

## 🎯 Purpose  
The primary purpose of this project is to:  
- **Automate vulnerability management** for Dockerized applications.  
- Provide a **single, consolidated PDF report** instead of multiple scattered outputs.  
- Help developers, DevOps, and security teams **integrate security into CI/CD pipelines (DevSecOps)**.  
- Align findings with **compliance frameworks and attacker models**.  

---

## ✅ Advantages  

- **Automated** → Scans run automatically with every code push (via GitHub Actions).  
- **Comprehensive** → Covers Docker images, source code, and dependencies.  
- **Framework-Aware** → Maps to NIST CSF, MITRE ATT&CK, and OWASP Top 10.  
- **Professional Reports** → PDF reports with charts, severity analysis, and framework mappings.  
- **Open-Source & Extensible** → Easily add new scanners or frameworks.  

---

## ⚡ Challenges Faced  

1. **Data Normalization** → Different scanners produce JSON in different formats.  
2. **Framework Mapping** → Consistently mapping vulnerabilities across NIST, MITRE, and OWASP required custom logic (`mappings.py`).  
3. **PDF Reporting** → Ensuring the final report is clear, visual, and boardroom-ready.  
4. **Automation in CI/CD** → Ensuring scans work smoothly within GitHub Actions with minimal setup.  

---

## 🖼️ Sample Report Preview  

Below is a preview of the kind of report generated by the scanner:  

![Download Vulnerability Test Report](https://github.com/ADITYADAS1999/Automated-Docker-Security-Scanner/blob/main/vulnerability_report.pdf)  

The PDF includes:  
- Vulnerability summary tables.  
- Severity distribution charts.  
- NIST CSF, MITRE ATT&CK, OWASP Top 10 mappings.  
- Final consolidated recommendations.  

---

## 🔚 Conclusion  
The **Automated Docker Security Scanner** provides a **complete security assessment workflow** for containerized applications.  
By integrating scanning tools with industry-standard frameworks, it transforms raw scan data into **actionable insights** that can guide both developers and security teams.  

Future Work:  
- Add real-time **CVE database lookups**.  
- Build a **web dashboard** for interactive vulnerability tracking.  
- Extend support for more programming languages (Go, Java, etc.).  

---

## 📜 License  
This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.  






