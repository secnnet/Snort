import re

# Function to validate an IP address using a regular expression
def validate_ip_address(ip_address):
    ip_pattern = r'^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    return bool(re.match(ip_pattern, ip_address))

# Function to validate a port number by checking if it's an integer within the valid range (0-65535)
def validate_port_number(port_number):
    try:
        port_number = int(port_number)
        return 0 <= port_number <= 65535
    except ValueError:
        return False

# Function to generate a SNORT rule using validated inputs
def generate_snort_rule(protocol, src_ip, src_port, dest_ip, dest_port, msg, sid):
    if not validate_ip_address(src_ip):
        raise ValueError(f"Invalid source IP address: {src_ip}")
    if not validate_port_number(src_port):
        raise ValueError(f"Invalid source port number: {src_port}")
    if not validate_ip_address(dest_ip):
        raise ValueError(f"Invalid destination IP address: {dest_ip}")
    if not validate_port_number(dest_port):
        raise ValueError(f"Invalid destination port number: {dest_port}")

    rule = f"{protocol} {src_ip} {src_port} -> {dest_ip} {dest_port} (msg:\"{msg}\"; sid:{sid};)"
    return rule

# Function to save the generated rule to a file
def save_rule_to_file(rule, file_name):
    with open(file_name, "a") as file:
        file.write(rule + "\n")

def get_user_input(prompt, validation_function=None):
    while True:
        value = input(prompt)
        if validation_function is None or validation_function(value):
            return value
        print("Invalid input. Please try again.")

try:
    user_protocol = get_user_input("Enter protocol (e.g. tcp, udp): ")
    user_src_ip = get_user_input("Enter source IP (e.g. any, [IP address]): ", validate_ip_address)
    user_src_port = get_user_input("Enter source port (e.g. any, [port number]): ", validate_port_number)
    user_dest_ip = get_user_input("Enter destination IP (e.g. any, [IP address]): ", validate_ip_address)
    user_dest_port = get_user_input("Enter destination port (e.g. any, [port number]): ", validate_port_number)
    user_msg = get_user_input("Enter message for the rule: ")
    user_sid = get_user_input("Enter rule SID (unique rule ID): ")

    snort_rule = generate_snort_rule(user_protocol, user_src_ip, user_src_port, user_dest_ip, user_dest_port, user_msg, user_sid)
    print("Generated SNORT rule:", snort_rule)

    file_name = "snort_rules.txt"
    save_rule_to_file(snort_rule, file_name)
    print(f"Rule saved to file: {file_name}")
except ValueError as e:
    print(f"Error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")