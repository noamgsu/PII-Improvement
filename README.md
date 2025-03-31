# PII-Improvement
1. improve_password_finalcode.py

    Configuration: Uses analyzer_settings

    Dependencies: Imports from validations

    Purpose: This is our first detection approach. It identifies passwords that are complex and contain combinations of:

        Lowercase letters

        Uppercase letters

        Digits

        Special characters

2. improve_password2_finalcode.py

    Configuration: Uses analyzer_settings2

    Dependencies: Also uses validations

    Purpose: This is our second detection approach. It focuses on extracting passwords that are:

        Positioned near specific keywords

        Made up of digits, letters, or letters with special characters

⚠️ Important Instructions

    Each script should be executed separately.

    After both scripts run, verify that there are no duplicate passwords (there shouldn’t be any).

    Merge the results from both into a single output list for analysis.

💡 Recommendation

I suggest running these scripts in a separate background environment to clearly track changes — whether positive or negative — and assess the impact of the new detection logic.

Let me know if you'd like help setting up the environment or integrating the outputs.
