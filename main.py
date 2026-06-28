import sys
from collections import defaultdict
from datetime import datetime
import iopath
import re

# Импортируем регулярные выражения из patterns.py
from patterns import SQLi_PATTERN, XSS_PATTERN, PATH_TRAVERSAL_PATTERN, DDOS_PATTERN

LOG_LEVELS = ['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL']
HTTP_STATUS_CLASSES = {'4xx': range(400, 500), '5xx': range(500, 600)}

# Функция для определения формата лога
def detect_log_format(line):
    # Пример форматов:
    # Nginx: [28/Jun/2026:13:26:47 +0000] "GET /path HTTP/1.1" 200 1234
    nginx_pattern = re.compile(r'^\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} \+0\d\d\]\s+"GET \S+ HTTP/1\.1" \d{3} \d+$', re.MULTILINE)
    
    # Apache: 185.90.197.46 - mybrowser [31/Oct/2020:00:12:21 +0000] "GET /robots.txt HTTP/1.1" 200 110
    apache_pattern = re.compile(r'^\d+\.\d+\.\d+\.\d+ - \S+ \[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [\+-]\d{4}\] "\S+ /[^ ]+ HTTP/1.1" \d{3} \d+$', re.MULTILINE)
    
    if nginx_pattern.match(line):
        return 'nginx'
    elif apache_pattern.match(line):
        return 'apache'
    else:
        raise ValueError("Unsupported log format")

def parse_log_line(line, log_format):
    parts = line.split()
    if log_format == 'nginx':
        timestamp = datetime.strptime(parts[0][1:], '%d/%b/%Y:%H:%M:%S %z')
        status_code = int(parts[parts.index('"') + 3].split()[0])
        message = " ".join(parts[max(len(parts), 6) - 5:])
    elif log_format == 'apache':
        timestamp = datetime.strptime(parts[3][1:-1], '%d/%b/%Y:%H:%M:%S %z')
        status_code = int(parts[8])
        message = " ".join(parts[9:])
    else:
        raise ValueError("Unsupported log format")
    
    return {
        'timestamp': timestamp,
        'status_code': status_code,
        'message': message
    }

def analyze_security(log_data):
    security_issues = defaultdict(int)
    
    for log in log_data:
        if SQLi_PATTERN.search(log['message']):
            security_issues['SQLi'] += 1
        elif XSS_PATTERN.search(log['message']):
            security_issues['XSS'] += 1
        elif PATH_TRAVERSAL_PATTERN.search(log['message']):
            security_issues['Path_Traversal'] += 1
        elif DDOS_PATTERN.search(log['message']):
            security_issues['DDoS'] += 1
    
    return security_issues

def generate_report(log_data):
    ip_counts = defaultdict(int)
    error_counts = defaultdict(int)

    for log in log_data:
        if log['status_code'] in HTTP_STATUS_CLASSES['4xx']:
            for part in log['message'].split():
                if ':' in part:
                    ip_counts[part.split(':')[0]] += 1
        elif log['status_code'] in HTTP_STATUS_CLASSES['5xx']:
            error_counts[log['message']] += 1

    report = f"""
    Top-5 IP Addresses:
    {sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]}

    Top-5 Most Frequent Errors:
    {sorted(error_counts.items(), key=lambda x: x[1], reverse=True)[:5]}
    
    Critical Incidents (4xx and 5xx):
    Total: {sum(ip_counts.values()) + sum(error_counts.values())}
    """

    return report

if __name__ == "__main__":
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        handle = iopath.create_handler()
        try:
            line = handle.open(file_path).readline().strip()  # Чтение первой строки для определения формата
            log_format = detect_log_format(line)
            log_data = [parse_log_line(line.strip(), log_format) for line in handle.open(file_path).readlines()[1:]]
        except ValueError as e:
            print(e)
            sys.exit(1)
    else:
        try:
            line = sys.stdin.readline().strip()  # Чтение первой строки для определения формата из STDIN
            log_format = detect_log_format(line)
            log_data = [parse_log_line(line.strip(), log_format) for line in sys.stdin.readlines()[1:]]
        except ValueError as e:
            print(e)
            sys.exit(1)

    security_issues = analyze_security(log_data)
    report = generate_report(log_data)

    print(security_issues)
    print(report)