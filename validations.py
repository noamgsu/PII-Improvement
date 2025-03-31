class Validations:
    def is_all_numbers_are_equal(self, numbers):
        if len(numbers) == 1:
            return False

        numeric_filter = filter(str.isdigit, numbers)
        numeric_string = ''.join(numeric_filter)
        list_numeric_string_chars = {char for char in numeric_string}

        return len(list_numeric_string_chars) == 1

    def is_keywords_found_in_surrounding(self, text, value, keywords, margin):
        if not keywords:
            return False

        value_positions = [value_position for value_position in range(len(text)) if text.startswith(value, value_position)]

        if not value_positions:
            return False

        for value_position in value_positions:
            start_pos = int(max(0, value_position - margin))
            end_pos = int(min(value_position + len(value) + margin, len(text) - 1))
            text_in_margin = text[start_pos:end_pos]

            is_keywords_found_in_text = self.is_keywords_found_in_text(
                text=text_in_margin,
                keywords=keywords,
            )

            if is_keywords_found_in_text:
                return True

        return False

    def is_keywords_found_in_text(self, text, keywords):
        for keyword in keywords:
            if keyword in text:
                return True

        return False