import os
import re
from PyPDF2 import PdfReader
import docx

DOC_FOLDER = "doc"
REPORT_FOLDER = "reports"
REPORT_FILE = os.path.join(REPORT_FOLDER, "scan_report.md")

SUSPICIOUS_PATTERNS = [
    r"http://", r"https?://.*bit\.ly", r"cmd.exe", r"powershell", r"javascript:",
    r"base64,", r"vbscript", r"shellcode", r"macro", r"AutoOpen"
]

def scan_text(content, filename):
    issues = []
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            issues.append(pattern)
    if issues:
        return f"⚠️ Suspicious ({', '.join(issues)})", "High"
    return "✅ Safe", "Low"

def extract_text_from_pdf(filepath):
    try:
        reader = PdfReader(filepath)
        return " ".join([page.extract_text() or "" for page in reader.pages])
    except Exception as e:
        return f"Error reading PDF: {e}"

def extract_text_from_docx(filepath):
    try:
        doc = docx.Document(filepath)
        return " ".join([para.text for para in doc.paragraphs])
    except Exception as e:
        return f"Error reading DOCX: {e}"

def main():
    if not os.path.exists(REPORT_FOLDER):
        os.makedirs(REPORT_FOLDER)

    with open(REPORT_FILE, "w", encoding="utf-8") as report:
        report.write("# Document Security Scan Report\n\n")
        report.write("| File | Status | Risk |\n")
        report.write("|------|--------|------|\n")

        for file in os.listdir(DOC_FOLDER):
            path = os.path.join(DOC_FOLDER, file)
            content = ""

            if file.lower().endswith(".pdf"):
                content = extract_text_from_pdf(path)
            elif file.lower().endswith(".docx"):
                content = extract_text_from_docx(path)
            elif file.lower().endswith(".txt"):
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception as e:
                    content = f"Error reading TXT: {e}"
            else:
                continue

            status, risk = scan_text(content, file)
            report.write(f"| {file} | {status} | {risk} |\n")

    print(f"✅ Report generated: {REPORT_FILE}")

if __name__ == "__main__":
    main()
