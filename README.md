# 🔐 Malicious_Docs_scan_CI_CD

Malicious_Docs_scan_CI_CD is a GitHub Actions workflow that automatically scans documents (.pdf, .docx, .txt) pushed to the repository for hidden QR codes or malicious links. It analyzes embedded content for suspicious patterns, flags potential threats, and generates detailed security reports as CI/CD artifacts.





![logo](https://github.com/user-attachments/assets/5ccf6f4b-6e3d-4472-be96-75ddda499fbd)



In today’s digital world, documents and images often serve as carriers of sensitive information. Unfortunately, attackers exploit these files to hide malicious payloads, embed scripts, or distribute harmful content. This raises a critical security challenge: **how can organizations ensure that documents and images shared across their environments are safe?**

With CI/CD pipelines becoming the backbone of modern software delivery, integrating **automated document security scanning** is now essential. This project, **StegoGuard-CI-CD**, was built to tackle exactly that challenge.  



## 📌 Introduction
This is a GitHub Actions workflow that **automatically scans images and documents** for hidden malicious payloads, QR codes, or suspicious content during the CI/CD process.  

It leverages open-source security tools and regex-based content analysis to identify potential risks and maps them to well-known security frameworks such as **NIST CSF**, **MITRE ATT&CK**, and **OWASP Top 10**.  

The final output is a **consolidated PDF report** with detailed findings, making it easier for organizations to analyze risks, take corrective actions, and maintain compliance.  

---

## 🚀 Key Features
- 🔍 **Scans images (`.jpg`, `.jpeg`, `.png`) and documents (`.pdf`, `.docx`, `.txt`)** for:
  - Hidden QR codes  
  - Embedded malicious URLs  
  - Suspicious payloads or scripts  
- 🗂️ **Generates structured JSON reports** for raw scan results.  
- 📑 **Creates professional PDF reports** with:
  - Charts  
  - Vulnerability analysis  

---

## 📂 File Structure  



```bash
.
Mailcious_Docs_scan_CI_CD-main/
│── .github/
│   └── workflows/
│       └── doc_scan.yml         # GitHub Actions workflow for scanning docs
│
│── doc/
│   ├── my_doc.pdf
│   ├── my_doc_01.pdf
│   ├── my_doc_02.pdf
│   ├── my_doc_03.pdf
│   ├── my_doc_04.pdf
│   ├── my_doc_05.pdf
│   └── qr_04.jpg                # Sample test docs & image with QR code
│
│── reports/                     # Stores scan results (JSON, PDF, logs)
│
│── scripts/
│   └── scan_docs.py             # Main script for scanning documents
│
│── example.txt                   # Example input text file
│── requirements.txt              # Python dependencies
│── README.md                     # Project documentation
│── LICENSE                       # License file

```

**Explanation of structure:**  
- **`.github/workflows`** → Contains the GitHub Actions workflow (`doc_scan.yml`) that automatically scans documents and images when pushed.  
- **`doc/`** → Sample input files (`.pdf`, `.jpg`) used for testing the scanner.  
- **`scripts/`** → Python scripts for scanning documents (`scan_docs.py`) and detecting QR codes or malicious payloads.  
- **`reports/`** → Output directory that stores raw scan results and consolidated reports.  
- **`example.txt`** → Example text file for testing scans.  
- **`requirements.txt`** → Lists Python dependencies (PyMuPDF, Pyzbar, ReportLab, Matplotlib, etc.).  
- **`README.md`** → Documentation for the project.  
- **`LICENSE`** → License information.  

---

## 🛠️ Technology Used  

- **Backend:**  
  Python (scripts for scanning documents/images, content analysis, and report generation).  

- **Frontend/Reports:**  
  - **ReportLab** → Generates structured PDF reports.  
  - **Matplotlib** → Creates charts/graphs for detection statistics.  

- **Security Tools & Libraries:**  
  - **PyMuPDF / pdfminer** → Extracts text and metadata from PDF files.  
  - **Pyzbar / qrcode** → Decodes QR codes from images and embedded docs.  
  - **Regex & Keyword Analysis** → Detects malicious URLs, encoded payloads, or suspicious scripts.  

- **CI/CD:**  
  GitHub Actions (automated scanning pipeline on every commit/push).  


---

## ⚙️ Workflow & Tools Used  

This project includes a **GitHub Actions workflow** (`.github/workflows/docker-scan.yml`) that automates the **DevSecOps security pipeline**.  
The workflow runs automatically on every push to the `main` branch and executes the following stages:  

---

### 🔹 1. Document & Image Collection
```yaml
- name: Collect Documents
  run: ls ./doc

```
- Purpose: Reads all PDF, TXT, and image files (`.jpg`, `.png`) from the `./doc` directory.
- Output: List of files to be scanned.


### 🔹 2. PDF Text Extraction

```
- name: Extract PDF Content
  run: python scripts/scan_docs.py --input ./doc --output ./reports

```
- Tool: PyMuPDF / pdfminer
- Purpose: Extracts text, metadata, and embedded objects from PDF files.
- Output: `reports/pdf_extract.json` → Extracted document data for further analysis.

### 🔹 3. QR Code Detection

```
- name: QR Code Scan
  run: python scripts/scan_docs.py --scan-qr ./doc --output ./reports

```
- Tool: Pyzbar / qrcode
- Purpose: Detects and decodes QR codes hidden inside documents or image files.
- Output: reports/qr_results.json → QR code values (URLs, payloads, etc.).


### 🔹 4. Content Analysis (Regex & Keyword Scan)
```
- name: Content Analysis
  run: python scripts/scan_docs.py --analyze ./doc --output ./reports

```
- Tool: Regex & Keyword Matching
- Purpose: Identifies malicious URLs, encoded payloads, or suspicious keywords inside documents.
- Output: `reports/content_analysis.json` → JSON report of suspicious findings.

### 🔹 5. Report Generation (Charts + PDF)

```
- name: Generate PDF Report
  run: python scripts/report_generator.py ./reports ./reports/final_report.pdf

```
- Tools: ReportLab, Matplotlib
- Purpose: Produces a professional PDF report with:
-Extracted QR code values
- Malicious content findings
- Severity breakdown (with charts)
- Output: reports/final_report.pdf




### 🔹 6. Upload Artifacts

```
- name: Upload PDF Report
  uses: actions/upload-artifact@v4
  with:
    name: document-security-report
    path: reports/final_report.pdf

```

- Purpose: Uploads the generated PDF report and raw JSON results as GitHub build artifacts.
- Benefit: Security teams can download and review results after each workflow run.





---

## 🎯 Purpose  
The primary purpose of this project is to:  
- Automate malicious document scanning in CI/CD workflows.
- Detect hidden QR codes, malicious URLs, and embedded scripts inside uploaded documents.
- Provide a single consolidated PDF report instead of scattered outputs.
- Help security teams and developers identify threats early before deployment.
  

---

## ✅ Advantages  

- **Automated** → Scans run automatically with every code push (via GitHub Actions).  
- **Comprehensive** → Covers multiple document types (.pdf, .docx, .txt) for malicious payloads.
- **Professional Reports** →PDF reports with charts, severity analysis, and framework mappings.  
- **Open-Source & Extensible** → New rules, regex patterns, or scanners can be easily added.  

---

## ⚡ Challenges Faced  

1. **Data Normalization** → Extracted QR codes, URLs, and scripts needed to be converted into a unified JSON structure.
2. **Detection Accuracy** → Building effective regex rules and keyword lists to flag obfuscated or encoded threats.
3. **PDF Reporting** → Combining QR scan results, malicious pattern detections, and framework mappings into a single clear report.
4. **CI/CD Integration** → Ensuring document scans run smoothly inside GitHub Actions with minimal setup.


---

## 🖼️ Sample Report Preview  

Below is a preview of the kind of report generated by the scanner:  

![Download Vulnerability Test Report](https://github.com/ADITYADAS1999/Malicious_Docs_scan_CI_CD/actions/runs/17497161904/artifacts/3938346784)  

The PDF includes:  

- Summary of scanned files and detected threats.
- Extracted QR code data and decoded payloads.
- Malicious URLs, encoded payloads, and hidden scripts.
- Severity distribution charts.
- Final consolidated recommendations.

---

## 🔚 Conclusion  

The **Document Security Scanner** (CI/CD) provides a **complete automated security assessment workflow** for uploaded documents.
By integrating QR scanning, malicious content analysis, and compliance mappings into GitHub Actions, it transforms raw scan outputs into actionable insights.

Future Work:  
- Add AI-powered detection models for phishing/malware patterns.
- Extend support for additional file types (`.pptx`, `.xls`, `.epub`).  
- Build a real-time dashboard for interactive monitoring of scanned documents.
---

## 📜 License  
This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.  






