import validations
from multi_setting import analyzer_settings
import os
import json
import csv
import re

class PasswordExtractor:
    def __init__(
        
        self,
        analyzer_settings,
    ):
        self.validations = validations.Validations()
        self.analyzer_settings = analyzer_settings
        self.table_row_separators = [
            ',',
            '" "',
        ]

    def extract(
        self,
        text,
    ):
        if not text:
            return set()
        
       

        multi_settings = self.analyzer_settings.get('multi_settings', [])

        if not multi_settings:
            multi_settings = [
                {
                    'blacklist': self.analyzer_settings.get('blacklist', []),
                    'margin': self.analyzer_settings.get('margin'),
                    'patterns': self.analyzer_settings['patterns'],
                    'keywords': self.analyzer_settings['keywords'],
                    'var_detection': self.analyzer_settings.get('var_detection', []),
                    'blacklist_patterns': self.analyzer_settings.get('blacklist_patterns', []),
                }
            ]

        
        combined_results = []
        for setting in multi_settings:
            results = []
            self.blacklist = setting.get('blacklist', [])
            self.margin = setting.get('margin')
            self.patterns = setting['patterns']
            self.keywords = setting['keywords']
            self.var_detection = setting.get('var_detection', [])
            blacklist_patterns = setting.get('blacklist_patterns', [])
            is_extract_line = setting.get('extract_lines', False)
            

            #need to add to Ido code
            #if not any(keyword.lower() in text.lower() for keyword in self.keywords):
                #return set()

            print("Compiling blacklist patterns...")
            
            print("starting settings")
            self.compiled_blacklist_patterns = [
                re.compile(pattern) 
                for pattern in blacklist_patterns
            ]
            print("starting extract")

            table_results = []
            if is_extract_line:
                plain_text_results = self.extract_from_lines(text=text)
            else:
                plain_text_results = self.extract_from_plain_text(text=text)
                
                for separator in self.table_row_separators:
                    current_table_results = self.extract_from_table(
                        text=text,
                        separator=separator,
                    )
                    table_results += current_table_results
            
            results += plain_text_results 
            results += table_results

            sanitized_results = [
                password
                for password in results
                if self.validate(
                    password=password,
                )
            ]
            combined_results += sanitized_results

        return set(combined_results)


    def extract_from_lines(self, text, is_table=False):
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
    
    def extract_from_plain_text(
        self,
        text,
        is_table=False,
    ):
        results = []
        words = text.split()

        keywords_found_in_text = [keyword for keyword in self.keywords if keyword.lower() in text.lower()]

        for pattern in self.patterns:
            compiled_pattern = re.compile(
                pattern=pattern,
                flags=re.IGNORECASE,
            )

            for word in words:
                password_candidates = compiled_pattern.findall(
                    string=word,
                )
                for password in password_candidates:
                    is_found_keywords = self.validations.is_keywords_found_in_surrounding(
                        text=text,
                        value=password,
                        keywords=keywords_found_in_text,
                        margin=self.margin,
                    )
                    if is_table or is_found_keywords:
                        print(f"password candidate- '{password}' match to pattern-  '{pattern}'")
                        results.append(password)

        return results

    def extract_from_table(
        self,
        text,
        separator,
    ):
        print(f"starting Extract from table with separator '{separator}'")
        results = []
        rows = text.split('\n')
        if not rows:
            return []

        columns = rows[0].split(separator)
        if len(columns) <= 1:
            return []

        column_indexes_with_keywords = [column_index for column_index in range(0, len(columns)) if columns[column_index].lower().find('password') >= 0]

        if not column_indexes_with_keywords:
            return []

        for single_row in rows[1:]:
            cells = single_row.split(separator)
            for column_index in column_indexes_with_keywords:
                if column_index < len(cells):
                    current_cell_text = cells[column_index]
                    results_in_cell = self.extract_from_plain_text(
                        text=current_cell_text,
                        is_table=True,
                    )
                    results.extend(results_in_cell)
        print(f"finished Extract from table with separator '{separator}'")
        return results

    def validate(
        self,
        password,
    ):
        print(f"validating '{password}'.")
        password_lowercase = password.lower()

        """for word in self.blacklist:
            if word == password_lowercase:
                print(f"Password '{password}' matches to blacklist word '{word}'.")
                return False"""
            
        result = [phrase for phrase in self.blacklist if password_lowercase.find(phrase.lower()) >= 0]
        if len(result) > 0:
            return False
            
        for k in self.var_detection:
            index = password_lowercase.find(k)
            if index != -1:
                after = password_lowercase[index + len(k)] if index + len(k) < len(password_lowercase) else ''
                before = password_lowercase[index - 1] if index > 0 else ''
                if not after.islower() and not before.islower():
                    print(f"Password '{password}' has a variable detection issue.")
                    return False
                
        for pattern in self.compiled_blacklist_patterns:
            if pattern.search(password):
                print(f"Password '{password}' matches a blacklist pattern- {pattern}")
                return False

        return True
    
if __name__ == "__main__":
    INPUT_DIR = "random_files_bugcrowd_txt_120k"
    OUTPUT_DIR = "output_random_files_bugcrowd_txt_120k"
    all_passwords = []

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    
    

    files = [f for f in os.listdir(INPUT_DIR) if os.path.isfile(os.path.join(INPUT_DIR, f))]
    

    if not files:
        print("❌ No text files found in the directory.")
        exit(1)

    extractor = PasswordExtractor(analyzer_settings)

    for file_name in files:
        """if file_name != "test.txt":
            continue"""

        print(f"starting file {file_name}")
        file_path = os.path.join(INPUT_DIR, file_name)

        try:
            with open(file_path, "r", encoding="utf-8") as file:
                text = file.read()
        except UnicodeDecodeError:
            print(f"⚠️ Skipping non-text or unreadable file: {file_name}")
            continue

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

# blacklist_patterns = [
#     # Former fullmatch patterns
#     '^[a-zA-Z]{3}\d{2}$',                                # Month+year format (e.g., "nov22")
#     '^[\'"\(\[\{<]*0[xX][0-9a-fA-F]+[\'"\)\]\}>]*$',     # Hex values (e.g., "0x8000")
#     '^[A-Z0-9]+$',                                       # Only uppercase and numbers (e.g., "ABC123")
#     '^[A-Za-z]{3}-\d{2,4}$',                             # 3 letters followed by 2-4 digits (e.g., "ABC-1234")
    
#     # Former match patterns (start of string)
#     '^\d+\)',                                            # Digit followed by closing parenthesis (e.g., "1)start")
#     '^[A-Z]+-',                                          # Uppercase letters followed by dash (e.g., "ABC-")
    
#     # Complex time format patterns
#     '^[\(\"\'  ]?\d{1,2}(:\d{2})?\s?(AM|PM|am|pm)\s?-\s?\d{1,2}(:\d{2})?\s?(AM|PM|am|pm)[\)\"\'\.;:]?$',  # Time range
#     '^[\(\"\'  ]?\d{1,2}(:\d{2})?\s?(AM|PM|am|pm)[\)\"\'\.;:]?$',  # Single time
    
#     # Format pattern for number-uppercase
#     '"?\d+-[A-Z]+"?',                                    # Number-uppercase format (e.g., "1-A")
    
#     # Bracket pair patterns (both characters exist)
#     '(?=.*\()(?=.*\))',                                  # Both ( and ) present
#     '(?=.*<)(?=.*>)',                                    # Both < and > present
#     '(?=.*\[)(?=.*\])',                                  # Both [ and ] present
#     '(?=.*\{)(?=.*\})',                                  # Both { and } present
#     '(?=.*&)(?=.*;)',                                    # Both & and ; present
    
#     # Invalid substring patterns
#     'px[;)\"]|<br',                                      # UI-related substrings (px;, px), px", <br)
#     'utf.*?8',                                           # UTF8 variations
#     '=',                                                 # Equals sign
#     ';$',                                                # Ends with semicolon
    
#     # Multiple character patterns
#     '-.*-',                                              # Multiple dashes
#     '_.*_',                                              # Multiple underscores
#     ';.*;',                                              # Multiple semicolons
    
#     # No lowercase with uppercase, digit and symbol
#     '(?=.*[A-Z])(?=.*\d)(?=.*[#%&*)(_\-+=\[\]{}\|\",:;\'\/\.,><`~])(?![a-z])', # Complex pattern to match strings with uppercase, digit, and symbol but no lowercase
    
#     # Common time words
#     'second|minute|hour|day|week|month|year',            # Time-related terms
# ]