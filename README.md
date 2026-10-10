 # Python Security Log Parser & Automation Utility

## Objective
Developed a lightweight Python automation utility to parse system authentication logs, extract security anomalies, and automatically flag high-frequency failed login spikes to assist in threat detection.

## Tech Stack
* Python (File I/O, Regular Expressions, Collections, JSON Handling)
* CLI & IT Automation

## Key Features
* **Automated Log Parsing:** Uses Regex to extract crucial Indicators of Compromise (IP addresses) from raw log files.
* **Threshold Detection:** Flags potential brute-force behavior when failed attempts cross a defined threshold.
* **Structured Reporting:** Automatically compiles findings into an organized JSON security report for downstream analysis.

## How to Run
1. Clone the repository.
2. Place your target log file inside the `logs/` directory.
3. Run the script:
   ```bash
   python parser.py
