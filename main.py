
import re

log_pattern = re.compile(
    r'^(\S+)\s+-\s+\[([^\]]+)\]\s+"(\S+)\s+(.*?)\s+HTTP/\d(?:\.\d)?"\s+(\d{3})$'
)

unauthorized_count = 0
total_requests = 0
suspicious_ips = {}
invalid_lines = 0

with open("security.log", "r", encoding="utf-8") as file:
    for line_number, log in enumerate(file, start=1):
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

        print("IP:", ip)
        print("Method:", method)
        print("URL:", url)
        print("Status:", status)

        if status == "401":
            print("Unauthorized Request!")
            unauthorized_count += 1

            if ip in suspicious_ips:
                suspicious_ips[ip] += 1
            else:
                suspicious_ips[ip] = 1

        print("----------------")

print("\n========== SECURITY REPORT ==========")
print("Total Requests:", total_requests)
print("Total Unauthorized Requests:", unauthorized_count)
print("Invalid Log Lines:", invalid_lines)

print("\nSuspicious IPs:")

if suspicious_ips:
    for ip, count in suspicious_ips.items():
        print(ip, ":", count)
else:
    print("No suspicious IPs found.")

print("====================================")
