import yara
import os
import threading
import argparse
import subprocess

# Dictionnaire pour lier les types de règles à leurs chemins
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

# Variables globales pour le suivi des résultats
match_count = 0
error_count = 0
matches_details = []  # Pour stocker les détails des matchs
lock = threading.Lock()  # Pour synchroniser l'accès aux variables partagées

# Fonction pour charger un fichier de règles YARA
def load_yara_rule(rule_file):
    try:
        rules = yara.compile(filepath=rule_file)
        return rules
    except yara.SyntaxError as e:
        global error_count
        with lock:
            error_count += 1
        return None

# Fonction pour charger toutes les règles YARA à partir d'un dossier
def load_yara_rules_from_folder(folder_path, rule_type):
    rules = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.yar') or file.endswith('.yara'):
                rule_path = os.path.join(root, file)
                rule = load_yara_rule(rule_path)
                if rule:
                    rules.append((rule, rule_type))  # Associer le type de règle
    return rules

# Fonction pour scanner un fichier avec une règle YARA
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
                        'type': rule_type  # Associer le type de règle au match
                    })
    except yara.Error:
        with lock:
            error_count += 1

# Fonction pour scanner un fichier avec toutes les règles YARA
def scan_file_with_all_rules(rules, file_path):
    threads = []
    for rule, rule_type in rules:
        thread = threading.Thread(target=scan_file_with_rule, args=(rule, file_path, rule_type))
        threads.append(thread)
        thread.start()

    # Attendre que tous les threads se terminent
    for thread in threads:
        thread.join()

    # Affichage des résultats après l'analyse
    print("\n--- Résumé de l'analyse ---")
    print(f"Nombre total de threads utilisés : {len(threads)}")
    print(f"Nombre total de matchs trouvés : {match_count}")
    print(f"Nombre total d'erreurs rencontrées : {error_count}")
    
    # Afficher les détails des matchs trouvés
    if matches_details:
        print("\n--- Détails des matchs ---")
        for i, match in enumerate(matches_details, 1):
            print(f"\nMatch {i}:")
            print(f"Type de règle : {rules_dict[match['type']]}")
            print(f"Règle : {match['rule']}")
            print(f"Tags : {', '.join(match['tags']) if match['tags'] else 'Aucun'}")
            print(f"Identifiants (meta) : {match['meta']}")
    else:
        print("Aucun match trouvé.")

# Fonction pour exécuter un git pull dans le dossier des règles
def update_rules_repository():
    try:
        subprocess.run(['git', '-C', 'rules', 'pull'], check=True)
        print("Mise à jour des règles effectuée avec succès.")
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de la mise à jour des règles : {e}")

# Fonction principale avec argparse
def main():
    parser = argparse.ArgumentParser(description="Analyse de fichier avec règles YARA")
    parser.add_argument(
        "-f", "--file", 

        help="Chemin du fichier à analyser"
    )
    parser.add_argument(
        "-M", action='store_true', help="Utiliser les règles de malware"
    )
    parser.add_argument(
        "-Cr", action='store_true', help="Utiliser les règles de crypto"
    )
    parser.add_argument(
        "-AB", action='store_true', help="Utiliser les règles d'anti-debug/anti-VM"
    )
    parser.add_argument(
        "-C", action='store_true', help="Utiliser les règles de capabilities"
    )
    parser.add_argument(
        "-EK", action='store_true', help="Utiliser les règles d'exploit kits"
    )
    parser.add_argument(
        "-WS", action='store_true', help="Utiliser les règles de webshell"
    )
    parser.add_argument(
        "-E", action='store_true', help="Utiliser les règles d'email"
    )
    parser.add_argument(
        "-MM", action='store_true', help="Utiliser les règles de mobile malware"
    )
    parser.add_argument(
        "-CV", action='store_true', help="Utiliser les règles de CVE"
    )
    parser.add_argument(
        "-P", action='store_true', help="Utiliser les règles de packers"
    )
    parser.add_argument(
        "-MD", action='store_true', help="Utiliser les règles de maldocs"
    )
    parser.add_argument(
        "-ALL", action='store_true', help="Utiliser toutes les règles"
    )
    parser.add_argument(
        "--update", action='store_true', help="Mettre à jour le dépôt de règles avec git pull"
    )

    args = parser.parse_args()

    if args.update:
        update_rules_repository()

    if args.ALL:
        selected_rule_types = list(rules_dict.keys())[:-1]  # Toutes les règles sauf "all"
    else:
        selected_rule_types = [key for key, value in vars(args).items() if value and key in rules_dict]

    if not selected_rule_types:
        print("Aucun type de règle valide sélectionné.")
        return

    file_path = args.file

    if not os.path.exists(file_path):
        print(f"Le fichier {file_path} n'existe pas.")
        return

    # Charger les règles pour les types sélectionnés
    all_rules = []
    for rule_type in selected_rule_types:
        folder_path = rules_dict[rule_type]
        if folder_path != "all":
            rules = load_yara_rules_from_folder(folder_path, rule_type)
            all_rules.extend(rules)

    if all_rules:
        # Analyser le fichier avec toutes les règles en parallèle
        scan_file_with_all_rules(all_rules, file_path)
    else:
        print("Aucune règle valide trouvée dans les dossiers sélectionnés.")

if __name__ == "__main__":
    main()