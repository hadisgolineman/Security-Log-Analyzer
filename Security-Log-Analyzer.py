
import re
from urllib.parse import unquote

sql_patterns = [
    "union select",
    "or 1=1",
    "drop table",
    "select * from",
    "admin'--",
    "' or '1'='1"
]

xss_patterns = [
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
    "alert("
]

sql_regex = [
    r"union\s+select",
    r"or\s+\d+=\d+",
    r"drop\s+table",
    r"select\s+.*\s+from"
]

xss_regex = [
    r"<\s*script",
    r"javascript\s*:",
    r"onerror\s*=",
    r"onload\s*=",
    r"alert\s*\(",
    r"document\s*\.\s*cookie"
]

log_pattern = re.compile(
    r'^(\S+)\s+-\s+\[([^\]]+)\]\s+"(\S+)\s+(.*?)\s+HTTP/\d(?:\.\d)?"\s+(\d{3})$'
)

total_requests = 0
unauthorized_count = 0
sql_count = 0
xss_count = 0
invalid_lines = 0

suspicious_ips = {}

with open("security.log", "r", encoding="utf-8") as file:
    logs = file.readlines()

for line_number, log in enumerate(logs, start=1):

    log = log.strip()

    if not log:
        continue

    match = log_pattern.match(log)

    if not match:
        print(f"Invalid log format at line {line_number}")
        invalid_lines += 1
        continue

    ip = match.group(1)
    method = match.group(3)
    url = match.group(4)
    status = match.group(5)

    total_requests += 1

    decoded_url = unquote(url)
    normalized_url = decoded_url.lower()

    sql_detected = any(
        pattern in normalized_url
        for pattern in sql_patterns
    )

    xss_detected = any(
        pattern in normalized_url
        for pattern in xss_patterns
    )

    sql_regex_detected = any(
        re.search(pattern, normalized_url)
        for pattern in sql_regex
    )

    xss_regex_detected = any(
        re.search(pattern, normalized_url)
        for pattern in xss_regex
    )

    if status == "401":
        unauthorized_count += 1

    if sql_detected or sql_regex_detected:
        sql_count += 1

        if ip not in suspicious_ips:
            suspicious_ips[ip] = {
                "SQL Injection": 0,
                "XSS": 0
            }

        suspicious_ips[ip]["SQL Injection"] += 1

    if xss_detected or xss_regex_detected:
        xss_count += 1

        if ip not in suspicious_ips:
            suspicious_ips[ip] = {
                "SQL Injection": 0,
                "XSS": 0
            }

        suspicious_ips[ip]["XSS"] += 1

    print("IP:", ip)
    print("Method:", method)
    print("URL:", decoded_url)
    print("Status:", status)

    if sql_detected or sql_regex_detected:
        print("SQL Injection Attempt Detected!")

    if xss_detected or xss_regex_detected:
        print("XSS Attempt Detected!")

    print("----------------")

print("\n========== SECURITY REPORT ==========")

print("Total Requests:", total_requests)
print("Unauthorized Requests:", unauthorized_count)
print("SQL Injection Attempts:", sql_count)
print("XSS Attempts:", xss_count)
print("Invalid Log Lines:", invalid_lines)

print("\n========== SUSPICIOUS IPs ==========")

if suspicious_ips:
    for ip, attacks in suspicious_ips.items():
        print("\nIP:", ip)
        print("SQL Injection:", attacks["SQL Injection"])
        print("XSS:", attacks["XSS"])
else:
    print("No suspicious IPs found.")

print("\n====================================")
