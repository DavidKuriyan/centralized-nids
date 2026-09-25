import json
import re
import sys
try:
    from pypdf import PdfReader
except ImportError:
    print("Please install pypdf: pip install pypdf")
    sys.exit(1)

def parse_pdf(pdf_path, output_json):
    rules = []
    # Regex to match the PDF table rows separated by newlines: Severity Action Proto SID Rev Message
    pattern = re.compile(r'(Critical|High|Medium|Low)\n(ALERT|LOG|PASS|DROP|REJECT)\n([A-Z0-9]+)\n(\d+)\n(\d+)\n([^\n]+)')
    
    print(f"Reading PDF: {pdf_path}")
    reader = PdfReader(pdf_path)
    
    for page in reader.pages:
        text = page.extract_text()
        if not text:
            continue
            
        for match in pattern.finditer(text):
            severity = match.group(1)
            action = match.group(2)
            proto = match.group(3)
            sid = int(match.group(4))
            rev = int(match.group(5))
            message = match.group(6).strip()
            
            # A PDF index contains rule metadata, not the original detection
            # options. Never invent a payload/content condition from
            # the alert message; doing so causes false positives in unrelated
            # binary or encrypted traffic.
            rule = {
                "sid": sid,
                "rev": rev,
                "action": action,
                "protocol": proto,
                "severity": severity,
                "message": message,
                "unsupported_source": "metadata-only PDF export"
            }
            rules.append(rule)
                
    print(f"Successfully extracted {len(rules)} rules.")
    
    with open(output_json, 'w') as f:
        json.dump(rules, f, indent=4)
    print(f"Wrote rules to {output_json}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python parse_rules.py <input_pdf> <output_json>")
        sys.exit(1)
    parse_pdf(sys.argv[1], sys.argv[2])
