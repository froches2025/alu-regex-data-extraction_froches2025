import re
import json

raw = open ("input/raw-text.txt", "r")
content = raw.read()
raw.close()

# Security: patterns that indicate hostile or malicious input attempts
HOSTILE_PATTERNS = [
    r'<script.*?>',           # XSS attempt
    r'SELECT.*?FROM',         # SQL injection
    r'OR\s+1=1',              # SQL injection variant
    r'\.\./\.\.',             # Path traversal
    r'%00',                   # Null byte injection
    r'onerror\s*=',           # XSS event handler
]

def check_hostile_input(text):
    flagged = []
    for pattern in HOSTILE_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            flagged.append(pattern)
    return flagged

hostile_findings = check_hostile_input(content)
if hostile_findings:
    print(f"WARNING: Hostile input detected. Patterns matched: {hostile_findings}")

# Security: mask credit card numbers before display or output
def mask_card(card_number):
    digits_only = re.sub(r'\D', '', card_number)
    masked = '**** **** **** ' + digits_only[-4:]
    return masked

# matches all hashtags that contain at least one letter and allows digits anywhere
hashtag_pattern = r'#\w*[a-zA-Z]\w*'
# matches 4 different currencies, in all formats
currency_pattern = r'(?:\$|₦|£|KES\s)\d+(?:,\d{3})*(?:\.\d{2})?'
# matches all valid emails
email_pattern = r'[a-zA-Z0-9][\w\.\-\+]*\@[\w\-\.]+\.[a-zA-Z]{2,6}'
# matches all valid phone numbers with different country codes
phone_pattern = r'(?:\+[\d\s\-\(\)]+|0[\d\s\-\(\)]+|\(0[\d\s\-\(\)]+)'



hashtag_match = re.findall(hashtag_pattern, content)
currency_match = re.findall(currency_pattern, content)
email_match = re.findall(email_pattern, content)
phone_match = re.findall(phone_pattern, content)

valid_phones = []
for match in phone_match:
    digits_only = re.sub(r'\D', '', match)
    if 9 <= len(digits_only) <= 15:
        if match.strip().startswith('00'):
            continue
        if re.match(r'^0{9,}$', digits_only):
            continue
        valid_phones.append(match.strip().rstrip('( '))

valid_emails = []
for match in email_match:
    if len(match) > 254:
        continue
    if '..' in match:
        continue
    local_part = match.split('@')[0]
    if not re.search(r'[a-zA-Z]', local_part):
        continue
    valid_emails.append(match)

alu_official = []
alu_alumni = []
alu_si = []

for email in valid_emails:
    if re.search(r'@alueducation\.com$', email):
        alu_official.append(email)
    elif re.search(r'@alumni\.alueducation\.com$', email):
        alu_alumni.append(email)
    elif re.search(r'@si\.alueducation\.com$', email):
        alu_si.append(email)


output = {
    "hostile_input_detected": len(hostile_findings) > 0,
    "hostile_patterns_matched": hostile_findings,
    "emails": {
        "all_valid": valid_emails,
        "alu_official": alu_official,
        "alu_alumni": alu_alumni,
        "alu_si": alu_si
    },
    "phone_numbers": valid_phones,
    "hashtags": hashtag_match,
    "currency_amounts": currency_match
}

with open('output/sample-output.json', 'w', encoding='utf-8') as f:
    json.dump(output, f, indent=2, ensure_ascii=False)

print("Output written to output/sample-output.json")