import yara
import os
import threading
import argparse
import subprocess

# Dictionary to link rule types to their paths
rules_dict = {
    "M": "rules/malware",            
    "Cr": "rules/crypto",            
    "AB": "rules/antidebug_antivm",   
    "C": "rules/capabilities",        
    "EK": "rules/exploit_kits",      
    "WS": "rules/webshell",          
    "E": "rules/email",                
    "MM": "rules/mobile_malware",      
    "CV": "rules/cve_rules",           
    "P": "rules/packers",          
    "MD": "rules/maldocs",           
    "ALL": "all"                      
}

# Global variables for tracking results
match_count = 0
error_count = 0
matches_details = []  # To store match details
lock = threading.Lock()  # To synchronize access to shared variables

# Function to load a YARA rule file
def load_yara_rule(rule_file):
    try:
        rules = yara.compile(filepath=rule_file)
        return rules
    except yara.SyntaxError as e:
        global error_count
        with lock:
            error_count += 1
        return None

# Function to load all YARA rules from a folder
def load_yara_rules_from_folder(folder_path, rule_type):
    rules = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.yar') or file.endswith('.yara'):
                rule_path = os.path.join(root, file)
                rule = load_yara_rule(rule_path)
                if rule:
                    rules.append((rule, rule_type))  # Associate rule type
    return rules

# Function to scan a file with a YARA rule
def scan_file_with_rule(rule, file_path, rule_type):
    global match_count, error_count, matches_details
    try:
        matches = rule.match(file_path)
        if matches:
            with lock:
                match_count += len(matches)
                for match in matches:
                    matches_details.append({
                        'rule': match.rule,
                        'tags': match.tags,
                        'meta': match.meta,
                        'type': rule_type  # Associate rule type with match
                    })
    except yara.Error:
        with lock:
            error_count += 1

# Function to scan a file with all YARA rules
def scan_file_with_all_rules(rules, file_path):
    threads = []
    for rule, rule_type in rules:
        thread = threading.Thread(target=scan_file_with_rule, args=(rule, file_path, rule_type))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    # Display results after analysis
    print("\n--- Analysis Summary ---")
    print(f"Total number of threads used: {len(threads)}")
    print(f"Total number of matches found: {match_count}")
    print(f"Total number of errors encountered: {error_count}")
    
    # Display details of matches found
    if matches_details:
        print("\n--- Match Details ---")
        for i, match in enumerate(matches_details, 1):
            print(f"\nMatch {i}:")
            print(f"Rule Type: {rules_dict[match['type']]}")
            print(f"Rule: {match['rule']}")
            print(f"Tags: {', '.join(match['tags']) if match['tags'] else 'None'}")
            print(f"Meta Identifiers: {match['meta']}")
    else:
        print("No matches found.")

# Function to execute a git clone in the rules directory
def clone_rules_repository():
    try:
        subprocess.run(['git', 'clone', 'https://github.com/Yara-Rules/rules.git'], check=True)
        print("Rules cloned successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error cloning rules: {e}")

# Function to execute a git pull in the rules directory
def update_rules_repository():
    try:
        subprocess.run(['git', '-C', 'rules', 'pull'], check=True)
        print("Rules updated successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error updating rules: {e}")

# Main function with argparse
def main():
    parser = argparse.ArgumentParser(description="File analysis with YARA rules")
    parser.add_argument(
        "-f", "--file", 
        help="Path to the file to analyze"
    )
    parser.add_argument(
        "-M", action='store_true', help="Use malware rules"
    )
    parser.add_argument(
        "-Cr", action='store_true', help="Use crypto rules"
    )
    parser.add_argument(
        "-AB", action='store_true', help="Use anti-debug/anti-VM rules"
    )
    parser.add_argument(
        "-C", action='store_true', help="Use capabilities rules"
    )
    parser.add_argument(
        "-EK", action='store_true', help="Use exploit kits rules"
    )
    parser.add_argument(
        "-WS", action='store_true', help="Use webshell rules"
    )
    parser.add_argument(
        "-E", action='store_true', help="Use email rules"
    )
    parser.add_argument(
        "-MM", action='store_true', help="Use mobile malware rules"
    )
    parser.add_argument(
        "-CV", action='store_true', help="Use CVE rules"
    )
    parser.add_argument(
        "-P", action='store_true', help="Use packers rules"
    )
    parser.add_argument(
        "-MD", action='store_true', help="Use maldocs rules"
    )
    parser.add_argument(
        "-ALL", action='store_true', help="Use all rules"
    )
    parser.add_argument(
        "--update", action='store_true', help="Update the rules repository with git pull"
    )
    parser.add_argument(
        "--init", action='store_true', help="Clone the rules repository"
    )

    args = parser.parse_args()

    if args.init:
        clone_rules_repository()

    if args.update:
        update_rules_repository()

    if args.ALL:
        selected_rule_types = list(rules_dict.keys())[:-1]  # All rules except "all"
    else:
        selected_rule_types = [key for key, value in vars(args).items() if value and key in rules_dict]

    if not selected_rule_types:
        print("No valid rule type selected.")
        return

    file_path = args.file

    if not os.path.exists(file_path):
        print(f"The file {file_path} does not exist.")
        return

    # Load rules for the selected types
    all_rules = []
    for rule_type in selected_rule_types:
        folder_path = rules_dict[rule_type]
        if folder_path != "all":
            rules = load_yara_rules_from_folder(folder_path, rule_type)
            all_rules.extend(rules)

    if all_rules:
        # Analyze the file with all rules in parallel
        scan_file_with_all_rules(all_rules, file_path)
    else:
        print("No valid rules found in the selected folders.")

if __name__ == "__main__":
    main()