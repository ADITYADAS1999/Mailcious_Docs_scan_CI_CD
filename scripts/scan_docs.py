import os
import re
from PyPDF2 import PdfReader
import docx
import matplotlib.pyplot as plt

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

def generate_charts(results):
    # Count statuses
    status_counts = {"Safe": 0, "Suspicious": 0}
    risk_counts = {"High": 0, "Medium": 0, "Low": 0}

    for _, status, risk in results:
        if "Suspicious" in status:
            status_counts["Suspicious"] += 1
        else:
            status_counts["Safe"] += 1

        if risk in risk_counts:
            risk_counts[risk] += 1

    # Avoid division errors if no docs
    if sum(status_counts.values()) == 0:
        return []

    chart_files = []

    # Pie chart for Safe vs Suspicious
    pie_chart = os.path.join(REPORT_FOLDER, "status_pie_chart.png")
    plt.figure(figsize=(5,5))
    plt.pie(status_counts.values(), labels=status_counts.keys(), autopct='%1.1f%%', 
            colors=["#4CAF50", "#F44336"])
    plt.title("Document Safety Distribution")
    plt.savefig(pie_chart)
    plt.close()
    chart_files.append(pie_chart)

    # Bar chart for Risk Levels
    bar_chart = os.path.join(REPORT_FOLDER, "risk_bar_chart.png")
    plt.figure(figsize=(6,4))
    plt.bar(risk_counts.keys(), risk_counts.values(), color=["#F44336", "#FF9800", "#4CAF50"])
    plt.title("Risk Level Distribution")
    plt.xlabel("Risk Level")
    plt.ylabel("Number of Documents")
    plt.savefig(bar_chart)
    plt.close()
    chart_files.append(bar_chart)

    return chart_files

def main():
    if not os.path.exists(REPORT_FOLDER):
        os.makedirs(REPORT_FOLDER)

    results = []

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
            results.append((file, status, risk))
            report.write(f"| {file} | {status} | {risk} |\n")

        # Generate charts and embed in report
        chart_files = generate_charts(results)
        if chart_files:
            report.write("\n## Charts\n")
            for chart in chart_files:
                report.write(f"![{os.path.basename(chart)}]({os.path.basename(chart)})\n")

    print(f"✅ Report generated: {REPORT_FILE}")
    print("📊 Charts embedded into report")

if __name__ == "__main__":
    main()
