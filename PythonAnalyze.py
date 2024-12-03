from collections import Counter, defaultdict

def load_logs(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.readlines()
    except OSError as error:
        print(f"Error reading log file: {error}")
        return []

def count_requests_by_ip(log_lines):
    ip_counts = Counter()
    for line in log_lines:
        ip = line.split()[0]
        ip_counts[ip] += 1
    return ip_counts.most_common()

def find_top_endpoint(log_lines):
    endpoint_counts = Counter()
    for line in log_lines:
        endpoint = line.split()[6]
        endpoint_counts[endpoint] += 1
    return endpoint_counts.most_common(1)[0]

def find_suspicious_ips(log_lines):
    failed_attempts = defaultdict(int)
    flagged_ips = set()
    failure_limit = 3

    for line in log_lines:
        parts = line.split()
        ip = parts[0]
        endpoint = parts[6]
        status_code = parts[8]

        if endpoint == '/login' and status_code == '401':
            failed_attempts[ip] += 1
            if failed_attempts[ip] >= failure_limit:
                flagged_ips.add(ip)
        else:
            failed_attempts[ip] = 0

    return list(flagged_ips)

def run_analysis():
    log_file_path = r"C:\Users\91915\Desktop\sample.log"
    log_lines = load_logs(log_file_path)

    if not log_lines:
        print("No logs to analyze.")
        return

    ip_counts = count_requests_by_ip(log_lines)
    print("IP Request Counts:")
    print(ip_counts)

    top_endpoint = find_top_endpoint(log_lines)
    print("\nMost Accessed Endpoint:", top_endpoint)

    suspicious_ips = find_suspicious_ips(log_lines)
    print("\nSuspicious IPs:")
    print(suspicious_ips)

if __name__ == "__main__":
    run_analysis()
