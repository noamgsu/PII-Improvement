import re
import json
import os
import validations
import csv
from analyzer_settings2 import analyzer_settings

class PasswordExtractor:
    def __init__(self, analyzer_settings):
        self.validations = validations.Validations()
        self.blacklist = analyzer_settings.get('blacklist', [])
        self.patterns = analyzer_settings['patterns']
        self.keywords = analyzer_settings['keywords']
        self.table_row_separators = [',', '" "']

    def extract(self, text):
        if not text:
            return set()

        if not any(keyword.lower() in text.lower() for keyword in self.keywords):
            return set()        

        plain_text_results = self.extract_from_plain_text(text=text)

        table_results = []
        for separator in self.table_row_separators:
            current_table_results = self.extract_from_table(text=text, separator=separator)
            table_results += current_table_results

        results = plain_text_results + table_results

        sanitized_results = [
            password for password in results if self.validate(password=password)
        ]
        
        return set(sanitized_results)

    def extract_from_plain_text(self, text, is_table=False):
        results = []

        lines = text.splitlines()

        # Build full regex pattern per keyword
        for line in lines:
            for keyword in self.keywords:
                for pattern_raw in self.patterns:
                    pattern = rf"{re.escape(keyword)}[\s]*({pattern_raw})"
                    match = re.search(pattern, line, flags=re.IGNORECASE)
                    if match:
                        password = match.group(1)
                        end_index = match.end(1)
                        next_char = line[end_index:end_index+1]
                        if (next_char == "" or next_char == " ") and self.validate(password):
                            results.append(password)

        return list(set(results))

    def extract_from_table(self, text, separator):
        results = []
        rows = text.split('\n')
        if not rows:
            return []

        columns = rows[0].split(separator)
        if len(columns) <= 1:
            return []

        column_indexes_with_keywords = [
            i for i, col in enumerate(columns) if 'password' in col.lower()
        ]

        if not column_indexes_with_keywords:
            return []

        for single_row in rows[1:]:
            cells = single_row.split(separator)
            for column_index in column_indexes_with_keywords:
                if column_index < len(cells):
                    current_cell_text = cells[column_index]
                    results_in_cell = self.extract_from_plain_text(text=current_cell_text, is_table=True)
                    results.extend(results_in_cell)

        return results

    def validate(self, password):
        password_lowercase = password.lower()
        result = [phrase for phrase in self.blacklist if phrase.lower() in password_lowercase]

        if result:
            return False

        if password.startswith('<') and password.endswith('>'):
            return False

        return True

if __name__ == "__main__":
    INPUT_DIR = "input_oren_test"
    OUTPUT_DIR = "output_analayzer_settings_2_oren_test"
    all_passwords = []

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    files = [f for f in os.listdir(INPUT_DIR) if f.endswith(".txt")]

    if not files:
        print("❌ No text files found in the directory.")
        exit(1)

    for file_name in files:
        file_path = os.path.join(INPUT_DIR, file_name)
        
        extractor = PasswordExtractor(analyzer_settings)
        with open(file_path, "r", encoding="utf-8") as file:
            text = file.read()
        passwords = extractor.extract(text)
        
        output_file = os.path.join(OUTPUT_DIR, f"results_{file_name.replace('.txt', '')}.json")
        
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(list(passwords), f, indent=4, ensure_ascii=False)

        for password in passwords:
            all_passwords.append((file_name, password))

        if passwords:
            print(f"✅ Passwords found in {file_name} (saved to {output_file})")
        else:
            print(f"❌ No passwords found in {file_name}")

    # Save all passwords to a single CSV file
    csv_output_file = os.path.join(OUTPUT_DIR, "all_results.csv")
    with open(csv_output_file, mode='w', encoding='utf-8', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["filename", "pii"])  
        for file_name, password in all_passwords:
            writer.writerow([file_name, password])  

    print(f"📊 Combined CSV with all passwords saved to {csv_output_file}")
