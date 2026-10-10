import re
import json
from collections import Counter

def parse_auth_logs(log_file_path, threshold=3):
    """
    Parses authentication logs to flag potential brute-force attacks 
    based on a threshold of failed login attempts from a single IP.
    """
    failed_ips = []
    
    # Regex pattern to match failed login lines and extract the IP address
    # Example match: "Failed password for root from IP 203.0.113.50"
    pattern = re.compile(r"FAILED.*?from\s(?:IP\s)?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)

    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                match = pattern.search(line)
                if match:
                    ip_address = match.group(1)
                    failed_ips.append(ip_address)
                    
    except FileNotFoundError:
        print(f"Error: The file {log_file_path} was not found.")
        return

    # Count frequency of failures per IP
    ip_counts = Counter(failed_ips)
    
    # Identify suspicious IPs exceeding the failure threshold
    alerts = []
    for ip, count in ip_counts.items():
        if count >= threshold:
            alerts.append({
                "ip_address": ip,
                "failed_attempts": count,
                "status": "Potential Brute-Force Attack Detected"
            })

    report = {
        "total_failures_analyzed": len(failed_ips),
        "unique_flagged_ips": len(alerts),
        "alerts": alerts
    }

    # Save output report
    output_path = "output/security_report.json"
    with open(output_path, 'w') as json_file:
        json.dump(report, json_file, indent=4)

    print(f"[+] Parsing complete. Security report successfully saved to {output_path}")
    print(json.dumps(report, indent=4))

if __name__ == "__main__":
    # Run the parser against the sample log file
    parse_auth_logs("logs/sample_auth.log", threshold=3)
