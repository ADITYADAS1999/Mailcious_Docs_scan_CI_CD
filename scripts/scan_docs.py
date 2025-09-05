import os
import re
from PyPDF2 import PdfReader
import docx
import markdown
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

DOC_FOLDER = "doc"
REPORT_FOLDER = "reports"
REPORT_MD = os.path.join(REPORT_FOLDER, "scan_report.md")
REPORT_HTML = os.path.join(REPORT_FOLDER, "scan_report.html")
REPORT_PDF = os.path.join(REPORT_FOLDER, "scan_report.pdf")

SUSPICIOUS_PATTERNS = [
    r"http://", r"https?://.*bit\.ly", r"cmd.exe", r"powershell", r"javascript:",
    r"base64,", r"vbscript", r"shellcode", r"macro", r"AutoOpen"
]

def scan_text(content):
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

# --- Report Generators ---
def generate_md_report(results):
    with open(REPORT_MD, "w", encoding="utf-8") as report:
        report.write("# Document Security Scan Report\n\n")
        report.write("| File | Status | Risk |\n")
        report.write("|------|--------|------|\n")
        for row in results:
            report.write(f"| {row[0]} | {row[1]} | {row[2]} |\n")

def generate_html_report():
    with open(REPORT_MD, "r", encoding="utf-8") as f:
        md_content = f.read()
    html_content = markdown.markdown(md_content, extensions=["tables"])
    with open(REPORT_HTML, "w", encoding="utf-8") as f:
        f.write("<html><head><title>Document Scan Report</title></head><body>")
        f.write(html_content)
        f.write("</body></html>")

def generate_pdf_report(results):
    doc = SimpleDocTemplate(REPORT_PDF, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Document Security Scan Report", styles["Title"]))
    elements.append(Spacer(1, 12))

    table_data = [["File", "Status", "Risk"]]
    for row in results:
        table_data.append(row)

    table = Table(table_data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.gray),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 12),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
        ("GRID", (0, 0), (-1, -1), 1, colors.black),
    ]))

    elements.append(table)
    doc.build(elements)

# --- Main ---
def main():
    if not os.path.exists(REPORT_FOLDER):
        os.makedirs(REPORT_FOLDER)

    results = []

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

        status, risk = scan_text(content)
        results.append((file, status, risk))

    # Generate reports
    generate_md_report(results)
    generate_html_report()
    generate_pdf_report(results)

    print(f"✅ Reports generated in {REPORT_FOLDER}")

if __name__ == "__main__":
    main()
