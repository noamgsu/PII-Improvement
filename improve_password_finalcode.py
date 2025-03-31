import re
import json
import os
import csv
import validations
from analyzer_settings import analyzer_settings

class PasswordExtractor:
    def __init__(self, analyzer_settings):
        self.validations = validations.Validations()
        self.blacklist = analyzer_settings.get('blacklist', [])
        self.margin = analyzer_settings['margin']
        self.patterns = analyzer_settings['patterns']
        self.keywords = analyzer_settings['keywords']
        self.table_row_separators = [',', '" "']

        # Precompile all regex patterns once for performance (optimization)
        self.compiled_patterns = [re.compile(pattern, flags=re.IGNORECASE) for pattern in self.patterns]  # Precompiled for speed
        self.regex_digit_parenthesis = re.compile(r"^\d+\)")
        self.regex_upper_number = re.compile(r'"?\d+-[A-Z]+"?')
        self.regex_symbol = re.compile(r"[#%&*)(_\-+=\[\]{}\|\",:;'/\.,><`~]")
        self.regex_only_upper_num = re.compile(r"[A-Z0-9]+")
        self.regex_3letters_2to4digits = re.compile(r"[A-Za-z]{3}-\d{2,4}")
        self.regex_month_year = re.compile(r"^[a-zA-Z]{3}\d{2}$")
        self.regex_hex = re.compile(r'^[\'"\(\[\{<]*0[xX][0-9a-fA-F]+[\'"\)\]\}>]*$')
        self.regex_start_upper_dash = re.compile(r"^[A-Z]+-") 
        self.regex_time = re.compile(
            r"^[\(\"' ]?\d{1,2}(:\d{2})?\s?(AM|PM|am|pm)\s?-\s?\d{1,2}(:\d{2})?\s?(AM|PM|am|pm)[\)\"'\.:;]?$"
            r"|^[\(\"' ]?\d{1,2}(:\d{2})?\s?(AM|PM|am|pm)[\)\"'\.:;]?$")  # Precompiled complex time formats

    def validate(self, password):
        password_lowercase = password.lower()

        # Combined blacklist check into a single loop (optimization)
        if any(word in password_lowercase for word in self.blacklist):
            return False

        # Combined keywords into one loop for efficiency
        keywords = ["size", "value", "digit", "width", "max", "char", "character", "bit", "length", "temp", "text", "user", "int", "float",
                     "double", "bool", "string", "number", "num", "id", "key", "name", "email", "phone", "address","height","order", "style",
                     "index", "username", "varchar", "x000D", "sha", "service", "min", "main", "base", "border", "class", "color", "font", "code"
                     "maxlength", "minlength", "parent", "port"]
        for k in keywords:
            index = password_lowercase.find(k)
            if index != -1:
                before = password_lowercase[index - 1] if index > 0 else ''
                after = password_lowercase[index + len(k)] if index + len(k) < len(password_lowercase) else ''
                if not (after.islower()):
                    return False


        # Combined 'px' variations check
        if any(s in password_lowercase for s in ["px;", "px)", 'px"', "<br"]):
            return False

        # Combined time-related words check
        if any(t in password_lowercase for t in ["second", "minute", "hour", "day", "week", "month", "year"]):
            return False

        if "utf" in password_lowercase and "8" in password_lowercase:
            return False

        if password.endswith(";"):
            return False
        
        if "=" in password_lowercase:
            return False

        # Combined character pair checks
        if all(x in password for x in ["(", ")"]):
            return False
        if all(x in password for x in ["<", ">"]):
            return False        
        if all(x in password for x in ["[", "]"]):
            return False
        if all(x in password for x in ["{", "}"]):
            return False
        if all(x in password for x in ["&", ";"]):
            return False

        # Optimized count checks
        if password.count('-') > 1 or (password.count('_') + password.count('-')) > 1 or password.count('_') > 1 or password.count(';') > 1 :
            return False
        

        # Precompiled regex checks for performance
        if self.regex_month_year.fullmatch(password): # month + 2 digits year, e.g., nov22
            return False
        # Invalid if looks like hexadecimal number (e.g., 0x8000). Hex values are often IDs, addresses, or binary flags, not real passwords.        
        if self.regex_hex.fullmatch(password):
            return False
        # Invalid if entire password is a time format (single time or range), possibly surrounded by quotes, parentheses, or punctuation.
        # Examples: 10AM, (11:30AM), 8:30am-5pm, 9-10am, "11am-5pm", 10:00AM., 10:00AM:, 7:34am;        
        if self.regex_time.fullmatch(password):
            return False
        # If the password starts with one or more digits followed immediately by a closing parenthesis ")", mark it as invalid (e.g., 1)start, 12)        
        if self.regex_digit_parenthesis.match(password):
            return False
        # Invalid if password is in the format of "number-uppercase" (e.g., "1-A")        
        if self.regex_upper_number.fullmatch(password):
            return False
        # Invalid if contains uppercase letter, digit, and special character, but no lowercase letter e.g., "A1#"
        if (any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            self.regex_symbol.search(password) and
            not any(c.islower() for c in password)):
            return False
        # Invalid if password contains only uppercase letters and digits, but no lowercase letters e.g., "ABC123"
        if self.regex_only_upper_num.fullmatch(password):
            return False
        # Invalid if password starts with uppercase letters followed by a dash e.g., "ABC-"
        if self.regex_start_upper_dash.match(password):
            return False
        # Invalid if password contains 3 letters followed by 2 to 4 digits e.g., "ABC1234"
        if self.regex_3letters_2to4digits.fullmatch(password):
            return False

        return True

    def extract_from_plain_text(self, text, is_table=False):
        results = []
        words = text.split()
        keywords_found_in_text = [keyword for keyword in self.keywords if keyword.lower() in text.lower()]

        # Use precompiled patterns instead of compiling on each call (optimization)
        for compiled_pattern in self.compiled_patterns:
            for word in words:
                password_candidates = compiled_pattern.findall(string=word)
                for password in password_candidates:
                    is_found_keywords = self.validations.is_keywords_found_in_surrounding(
                        text=text.lower(),
                        value=password.lower(),
                        keywords=keywords_found_in_text,
                        margin=self.margin,
                    )
                    if is_table or is_found_keywords:
                        results.append(password)

        return results

    def extract_from_table(self, text, separator):
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
                    results_in_cell = self.extract_from_plain_text(text=current_cell_text, is_table=True)
                    results.extend(results_in_cell)

        return results

    def extract(self, text):
        if not text:
            return set()
        # Check if any keyword is present in the text
        if not any(keyword.lower() in text.lower() for keyword in self.keywords):
            return set()


        plain_text_results = self.extract_from_plain_text(text=text)
        table_results = []
        for separator in self.table_row_separators:
            table_results += self.extract_from_table(text=text, separator=separator)
        sanitized_results = [pwd for pwd in plain_text_results + table_results if self.validate(pwd)]
        return set(sanitized_results)

if __name__ == "__main__":
    INPUT_DIR = "Bugcrowd"
    OUTPUT_DIR = "output_Bugcrowd_test2"
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