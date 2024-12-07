import re
import csv
from collections import defaultdict

# File paths
log_file_path = 'sample.log'  # Replace with your log file path
output_file_path = 'log_analysis_results.csv'

# Initialize counters
ip_request_count = defaultdict(int)
failed_login_attempts = defaultdict(int)
endpoint_access_count = defaultdict(int)

# Patterns to match log details
ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'  # IP Address pattern
failed_login_pattern = r'login failed|FAILED LOGIN|Invalid credentials|Authentication Failed'  # Adjust this pattern based on your log format
endpoint_pattern = r'"(GET|POST|PUT|DELETE) (.*?) HTTP'  # Extracting HTTP endpoints

print("Processing log file...")

# Read and analyze the log file
with open(log_file_path, 'r') as log_file:
    for line in log_file:
        # Extract IP address
        ip_match = re.search(ip_pattern, line)
        if ip_match:
            ip_address = ip_match.group(1)
            ip_request_count[ip_address] += 1
        
        # Check for failed login attempts (try to catch all failed login patterns)
        if re.search(failed_login_pattern, line):  # Check if failed login attempt is in the line
            failed_login_attempts[ip_address] += 1
        
        # Extract endpoint accessed
        endpoint_match = re.search(endpoint_pattern, line)
        if endpoint_match:
            endpoint = endpoint_match.group(2)
            endpoint_access_count[endpoint] += 1

# Determine most accessed endpoint
most_accessed_endpoint = max(endpoint_access_count, key=endpoint_access_count.get, default="None")
most_accessed_count = endpoint_access_count.get(most_accessed_endpoint, 0)

# Write results to CSV
with open(output_file_path, 'w', newline='') as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(["IP Address", "Request Count"])
    for ip, count in ip_request_count.items():
        writer.writerow([ip, count])
    
    writer.writerow([])
    writer.writerow(["Most Frequently Accessed Endpoint"])
    writer.writerow([most_accessed_endpoint, f"Accessed {most_accessed_count} times"])
    
    writer.writerow([])
    writer.writerow(["Suspicious Activity Detected"])
    writer.writerow(["IP Address", "Failed Login Attempts"])
    for ip, attempts in failed_login_attempts.items():
        if attempts > 0:  # Include only IPs with failed login attempts
            writer.writerow([ip, attempts])

# Print results to console
print("\nIP Address Request Count:")
for ip, count in ip_request_count.items():
    print(f"{ip:<20} {count}")

print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed_endpoint} (Accessed {most_accessed_count} times)")

print("\nSuspicious Activity Detected:")
print(f"{'IP Address':<20} {'Failed Login Attempts'}")
for ip, attempts in failed_login_attempts.items():
    if attempts > 0:  # Include only IPs with failed login attempts
        print(f"{ip:<20} {attempts}")

print(f"\nResults saved to {output_file_path}")
