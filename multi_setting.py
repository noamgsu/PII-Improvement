analyzer_settings = {"multi_settings": [
    {
        "patterns": [
            r"^(?!.*[\s])(?=.{6,30}$)(?=.*[a-z])(?=.*[0-9]).*$",
            r"^(?!.*[\s])(?=.{6,30}$)(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9]).*$",
            r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,30}$",
            r"^(?!.*[\s])([a-zA-Z0-9]{24})$"
        ],
        "keywords": [
            "סיסמאות", "סיסמא", "סיסמה", "password", "password:", "passwords", "pass:",
            "كلمه السر", "كلمات السر", "пароль", "паролі", "пароли", "pwd:",
            '"password:'
        ],
        "margin": 50,
        "blacklist": [
            "token", "1Password", "1pass", "@UCFLV7L5S", "@U01KVBC86Q0", "EA-2073", "@U02HTESCA3T", 
            "INF-2788", "INF-2789", "24990P", "49990P", "$1000's", "AZORuIt3", "Check", "EA-965*", 
            "PasswordResetDataBuilder", "OAuth2", "56DB72A6757F", "us-central1-a", "@nicgilligan92", 
            "stream_kafka_1b", "cadams2", "O365", "49990P", "ghost-prod-1", "11min", "emdsup1", 
            "EMD-425", "7823fde2a6e8", "selenium-emd-20", "401e2cfcf6cO", "7-days", "e28595951ef7", 
            "6549aa9a31f1", "d0685c04a1d8", "95826798c8ed", "CTN1(IW)", "dir=\"auto\">96", 
            "9fa9e0da24a5", "(mperey172)", "dir=\"auto\">524", "<br>7-Day", "<br>526", "<br>135", 
            "dir=\"auto\">526", "41dda956682f", "829ef496305d", "0724texas6835", "779eb196f236", 
            "(CCJ3-IAG)", "205ed4eb6200", "29990P", "MOB-1256", "Office365", "52min-", "userauth_1", 
            "<@U023JMQA0Q2>?", "b2da7512af9c", "EA-1692", "e9bb{080bab2", "EA-1687", "SHA-256", 
            "oasswordHash=6e", "alerting-stage-1", ".", ":", "1password", "/", "\\", ",", "2-factor", 
            "2-step", "3-digit", "9-digit", "30-Day", "POL-10", "CA-61", "CA-71", "CA-53", 
            "877-BH-CARES", "CA-49a", "401(k)", "1-password", "&#39;", "loglevel", "type", "logon_type", 
            "cpi-444", "sns-301", "cael-101", "pf-06700841", "pol-","base32", "base64", "base64url","_x000D_", "sha256","check", '="', "||"
        ],
        "var_detection": [
            "size", "value", "digit", "width", "max", "char", "character", "bit", "length", "temp", "text", "user", "int", "float",
            "double", "bool", "string", "number", "num", "id", "key", "name", "email", "phone", "address", "height", "order", "style",
            "index", "username", "varchar", "x000D", "sha", "service", "min", "main", "base", "border", "class", "color", "font", "code",
            "maxlength", "minlength", "parent", "port", "com", "docx", "xlsx","level", "quert", "http", "ituser", "there", "this", "that", "some", "any", 
            "provided", "customer", "enter", "doe", "select", "rate", "leave"
        ],
        "blacklist_patterns": [ #need to add the r to Ido code
            r'^[a-zA-Z]{3}\d{2}$',  # 3 letters and 2 digits
            r'^[\'"\(\[\{<]*0[xX][0-9a-fA-F]+[\'"\)\]\}>]*$', # hex
            r'^[A-Z0-9]+$', # upper and numbers
            r'^[A-Za-z]{3}-\d{2,4}$', # 3 letters and 2-4 digits
            r'^\d+\)', # digit and )
            r'^[A-Z]+-', # upper and -
            r'^[\(\"\'  ]?\d{1,2}(:\d{2})?\s?(AM|PM|am|pm)\s?-\s?\d{1,2}(:\d{2})?\s?(AM|PM|am|pm)[\)\"\'\.;:]?$', # 1-2 digits and AM/PM
            r'^[\(\"\'  ]?\d{1,2}(:\d{2})?\s?(AM|PM|am|pm)[\)\"\'\.;:]?$',  # 1-2 digits and AM/PM
            r'"?\d+-[A-Z]+"?', # 1-2 digits and - and upper
            r'^(?=.*[A-Z])(?=.*\d)(?=.*[#%&*)(_\-+=\[\]{}\|\",:;\'\/\.,><`~])(?!.*[a-z])[^a-z]+$', # upper and special characters
            r'(?=.*\()(?=.*\))',  # ()
            r'(?=.*<)(?=.*>)',  # <>
            r'(?=.*\[)(?=.*\])', # []
            r'(?=.*\{)(?=.*\})', # {}
            r'(?=.*&)(?=.*;)', # &;
            r'px[;)\"]|<br', # px; or px) or px" or <br
            r'utf.*?8',  # utf8
            r';$', # ;
            r'-.*-', # - and -
            r'_.*_', # _ and _ 
            r';.*;', # ; and ; 
            r'(second|minute|hour|day|week|month|year)' # time-related words
        ]
    },
    {
        "patterns": [
            r"\d{4,16}",  # digits
            r"[a-zA-Z]{4,16}",  # letters
            r"[a-zA-Z!@#$%^&*()\`~;',.?\"\\]{4,16}"  # letters and special characters
        ],
        "extract_lines": True,
        "keywords": [
            ":סיסמא", ":סיסמה", "password:",
            "كلمه السر:", "пароль:", "pwd:"
        ],
        "blacklist": [
            "token", "1Password", "1pass", "@UCFLV7L5S", "@U01KVBC86Q0", "EA-2073", "@U02HTESCA3T", 
            "INF-2788", "INF-2789", "24990P", "49990P", "$1000's", "AZORuIt3", "Check", "EA-965*", 
            "PasswordResetDataBuilder", "OAuth2", "56DB72A6757F", "us-central1-a", "@nicgilligan92", 
            "stream_kafka_1b", "cadams2", "O365", "49990P", "ghost-prod-1", "11min", "emdsup1", 
            "EMD-425", "7823fde2a6e8", "selenium-emd-20", "401e2cfcf6cO", "7-days", "e28595951ef7", 
            "6549aa9a31f1", "d0685c04a1d8", "95826798c8ed", "CTN1(IW)", "dir=\"auto\">96", 
            "9fa9e0da24a5", "(mperey172)", "dir=\"auto\">524", "<br>7-Day", "<br>526", "<br>135", 
            "dir=\"auto\">526", "41dda956682f", "829ef496305d", "0724texas6835", "779eb196f236", 
            "(CCJ3-IAG)", "205ed4eb6200", "29990P", "MOB-1256", "Office365", "52min-", "userauth_1", 
            "<@U023JMQA0Q2>?", "b2da7512af9c", "EA-1692", "e9bb{080bab2", "EA-1687", "SHA-256", 
            "oasswordHash=6e", "alerting-stage-1", ".", ":", "1password", "/", "\\", ",", "2-factor", 
            "2-step", "3-digit", "9-digit", "30-Day", "POL-10", "CA-61", "CA-71", "CA-53", 
            "877-BH-CARES", "CA-49a", "401(k)", "1-password", "&#39;", "loglevel", "type", "logon_type", 
            "cpi-444", "sns-301", "cael-101", "pf-06700841", "pol-","base32", "base64", "base64url","_x000D_", "sha256","check","=",
            "size", "value", "digit", "width", "max", "char", "character", "bit", "length", "temp", "text", "user", "int", "float",
            "double", "bool", "string", "number", "num", "id", "key", "name", "email", "phone", "address", "height", "order", "style",
            "index", "username", "varchar", "x000D", "sha", "service", "min", "main", "base", "border", "class", "color", "font", "code",
            "maxlength", "minlength", "parent", "port", "com", "docx", "xlsx","level", "quert", "http", "ituser", "there", "this", "that", "some", "any", 
            "provided", "customer", "enter", "doe", "select", "rate", "leave"
        ]
    }
]
}