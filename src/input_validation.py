"""
Input Validatie Module - Urban Mobility Backend
STRICT WHITELISTING - geen input modificatie!
"""

import re
from datetime import datetime

def validate_username(username: str) -> bool:
    """Valideer gebruikersnaam: 8-10 tekens, begint met letter/underscore"""
    if not username or len(username) < 8 or len(username) > 10:
        return False

    # Moet beginnen met letter of underscore
    if not re.match(r'^[A-Za-z_]', username):
        return False

    # Mag alleen toegestane karakters bevatten
    if not re.fullmatch(r"[A-Za-z0-9_'.]{8,10}", username):
        return False

    return True

def validate_password(password: str) -> bool:
    """Valideer wachtwoord: 12-30 tekens, uppercase, lowercase, cijfer, speciaal teken"""
    if not password or len(password) < 12 or len(password) > 30:
        return False

    # Controleer voor verplichte karaktertypes
    has_lower = bool(re.search(r'[a-z]', password))  # Minimaal 1 kleine letter
    has_upper = bool(re.search(r'[A-Z]', password))  # Minimaal 1 hoofdletter
    has_digit = bool(re.search(r'\d', password))     # Minimaal 1 cijfer
    has_special = bool(re.search(r'[~!@#$%&_\-+=`|\\(){}[\]:;\'<>,.?/]', password))  # Minimaal 1 speciaal teken

    return has_lower and has_upper and has_digit and has_special

def validate_zip_code(zipcode: str) -> bool:
    """Valideer postcode format: DDDDXX (4 cijfers + 2 hoofdletters)"""
    return bool(re.fullmatch(r'[1-9][0-9]{3}[A-Z]{2}', zipcode))

def validate_mobile_phone(phone: str) -> bool:
    """Valideer mobiel nummer: 8 cijfers (+31-6- wordt automatisch toegevoegd)"""
    return bool(re.fullmatch(r'[0-9]{8}', phone))

def validate_driving_license(license_number: str) -> bool:
    """Valideer rijbewijs: XXDDDDDDD of XDDDDDDDD formaat"""
    pattern1 = r'[A-Z]{2}[0-9]{7}'  # XXDDDDDDD (2 letters + 7 cijfers)
    pattern2 = r'[A-Z][0-9]{8}'     # XDDDDDDDD (1 letter + 8 cijfers)
    return bool(re.fullmatch(pattern1, license_number) or re.fullmatch(pattern2, license_number))

def validate_email(email: str) -> bool:
    """Valideer email format met regex"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.fullmatch(pattern, email))

def validate_gps_coordinates(latitude: str, longitude: str) -> bool:
    """Valideer GPS coördinaten voor Rotterdam (5 decimalen)"""
    try:
        lat = float(latitude)
        lon = float(longitude)
        
        # Check if coordinates are in Rotterdam region (rough bounds)
        if not (51.8 <= lat <= 52.1 and 4.2 <= lon <= 4.8):
            return False
        
        # Check 5 decimal places precision
        lat_str = f"{lat:.5f}"
        lon_str = f"{lon:.5f}"
        
        return lat_str == latitude and lon_str == longitude
    except ValueError:
        return False

def validate_flexible_gps_coordinate(coord_str: str, coord_type: str) -> bool:
    """Valideer GPS coördinaat flexibel (lat/lon voor Nederland gebied)"""
    if not coord_str:
        return False
    
    try:
        coord = float(coord_str)
        
        if coord_type == 'lat':
            # Latitude: flexible range around Netherlands
            return 50.0 <= coord <= 54.0
        elif coord_type == 'lon':
            # Longitude: flexible range around Netherlands
            return 3.0 <= coord <= 8.0
        
        return True
    except ValueError:
        return False

def validate_serial_number(serial: str) -> bool:
    """Valideer scooter serienummer: 10-17 alfanumerieke tekens"""
    if not serial or len(serial) < 10 or len(serial) > 17:
        return False
    return bool(re.fullmatch(r'[A-Za-z0-9]{10,17}', serial))

def validate_date_iso(date_str: str) -> bool:
    """Valideer datum in ISO formaat: YYYY-MM-DD"""
    try:
        datetime.strptime(date_str, '%Y-%m-%d')
        return True
    except ValueError:
        return False

def validate_date_dutch(date_str: str) -> bool:
    """Valideer datum in Nederlands formaat: DD-MM-YYYY"""
    try:
        datetime.strptime(date_str, '%d-%m-%Y')
        return True
    except ValueError:
        return False

def validate_flexible_date(date_str: str) -> bool:
    """Valideer datum in flexibele formaten (DD-MM-YYYY, DD/MM/YY, etc.)"""
    if not date_str:
        return False
    
    # Try different date formats
    formats = [
        '%d-%m-%Y',   # 15-03-2024
        '%d/%m/%Y',   # 15/03/2024
        '%d.%m.%Y',   # 15.03.2024
        '%d-%m-%y',   # 15-03-24
        '%d/%m/%y',   # 15/03/24
        '%d.%m.%y',   # 15.03.24
        '%d %m %Y',   # 15 03 2024
        '%d %m %y',   # 15 03 24
    ]
    
    for fmt in formats:
        try:
            parsed_date = datetime.strptime(date_str, fmt)
            # Convert 2-digit years to 4-digit (assume 20xx for years 00-30, 19xx for 31-99)
            if parsed_date.year < 100:
                if parsed_date.year <= 30:
                    parsed_date = parsed_date.replace(year=parsed_date.year + 2000)
                else:
                    parsed_date = parsed_date.replace(year=parsed_date.year + 1900)
            return True
        except ValueError:
            continue
    
    return False

def convert_dutch_to_iso(dutch_date: str) -> str:
    """Converteer Nederlandse datum (DD-MM-YYYY) naar ISO (YYYY-MM-DD)"""
    try:
        date_obj = datetime.strptime(dutch_date, '%d-%m-%Y')
        return date_obj.strftime('%Y-%m-%d')
    except ValueError:
        return ""

def convert_iso_to_dutch(iso_date: str) -> str:
    """Converteer ISO datum (YYYY-MM-DD) naar Nederlands (DD-MM-YYYY)"""
    try:
        date_obj = datetime.strptime(iso_date, '%Y-%m-%d')
        return date_obj.strftime('%d-%m-%Y')
    except ValueError:
        return iso_date

def convert_flexible_date_to_iso(date_str: str) -> str:
    """Converteer flexibele datum naar ISO formaat (YYYY-MM-DD)"""
    if not date_str:
        return ""
    
    formats = [
        '%d-%m-%Y', '%d/%m/%Y', '%d.%m.%Y', '%d-%m-%y', 
        '%d/%m/%y', '%d.%m.%y', '%d %m %Y', '%d %m %y'
    ]
    
    for fmt in formats:
        try:
            parsed_date = datetime.strptime(date_str, fmt)
            # Convert 2-digit years
            if parsed_date.year < 100:
                if parsed_date.year <= 30:
                    parsed_date = parsed_date.replace(year=parsed_date.year + 2000)
                else:
                    parsed_date = parsed_date.replace(year=parsed_date.year + 1900)
            return parsed_date.strftime('%Y-%m-%d')
        except ValueError:
            continue
    
    return ""

def validate_birthday_dutch(birthday: str) -> bool:
    """Valideer geboortedatum: 16-120 jaar oud, DD-MM-YYYY formaat"""
    if not validate_date_dutch(birthday):
        return False
    
    try:
        birth_date = datetime.strptime(birthday, '%d-%m-%Y')
        current_date = datetime.now()
        
        # Must be in the past
        if birth_date >= current_date:
            return False
        
        # Must be reasonable (not older than 120 years)
        age_days = (current_date - birth_date).days
        if age_days > 120 * 365:
            return False
        
        # Must be at least 16 years old (for scooter license)
        if age_days < 16 * 365:
            return False
        
        return True
    except ValueError:
        return False

def validate_gender(gender: str) -> bool:
    """Valideer geslacht: 'male' of 'female' (case-sensitive)"""
    return gender in ['male', 'female']

def validate_city(city: str) -> bool:
    """Valideer stad: alleen steden uit vaste whitelist"""
    valid_cities = [
        'Rotterdam', 'Amsterdam', 'Den Haag', 'Utrecht', 'Eindhoven',
        'Groningen', 'Tilburg', 'Almere', 'Breda', 'Nijmegen'
    ]
    return city in valid_cities

def get_valid_cities() -> list:
    """Retourneer lijst van geldige steden"""
    return [
        'Rotterdam', 'Amsterdam', 'Den Haag', 'Utrecht', 'Eindhoven',
        'Groningen', 'Tilburg', 'Almere', 'Breda', 'Nijmegen'
    ]

def validate_percentage(value: str) -> bool:
    """Valideer percentage waarde: 0-100"""
    try:
        val = int(value)
        return 0 <= val <= 100
    except ValueError:
        return False

def validate_positive_integer(value: str) -> bool:
    """Valideer positief geheel getal"""
    try:
        val = int(value)
        return val > 0
    except ValueError:
        return False

def validate_positive_float(value: str) -> bool:
    """Valideer positief decimaal getal"""
    try:
        val = float(value)
        return val >= 0.0
    except ValueError:
        return False

def validate_soc_range(min_soc: str, max_soc: str) -> bool:
    """Valideer batterij bereik: min < max, beide 0-100"""
    try:
        min_val = int(min_soc)
        max_val = int(max_soc)
        return 0 <= min_val < max_val <= 100
    except ValueError:
        return False

def validate_name(name: str) -> bool:
    """Valideer naam: alleen letters, spaties, apostroffen, koppeltekens"""
    if not name or len(name) < 1:
        return False

    # Only letters, spaces, apostrophes, hyphens
    return bool(re.fullmatch(r"[A-Za-z\s'\-]{1,50}", name))

def validate_street_name(street: str) -> bool:
    """Valideer straatnaam: letters, cijfers, spaties, punt, koppelteken"""
    if not street or len(street) < 1:
        return False

    # Letters, numbers, spaces, common punctuation
    return bool(re.fullmatch(r"[A-Za-z0-9\s.\-']{1,100}", street))

def validate_house_number(house_num: str) -> bool:
    """Valideer huisnummer: cijfers, optioneel gevolgd door letter"""
    if not house_num or len(house_num) < 1:
        return False

    # Numbers, possibly followed by letters
    return bool(re.fullmatch(r'[0-9]+[A-Za-z]?', house_num))

def validate_brand_model(text: str) -> bool:
    """Valideer merk/model: alfanumeriek met spaties, koppelteken, punt"""
    if not text or len(text) < 1:
        return False

    return bool(re.fullmatch(r"[A-Za-z0-9\s\-_.]{1,50}", text))

def detect_injection_attempts(input_str: str) -> tuple[bool, str]:
    """Detecteer SQL/XSS/command injection aanvallen - retourneert (veilig, reden)"""
    if not input_str:
        return True, "Empty input"

    # 1. SQL Injection patterns
    sql_patterns = [
        r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+",  # OR 1=1, AND 1=1
        r";\s*(DROP|DELETE|UPDATE|INSERT|ALTER|EXEC|EXECUTE)\s+",  # ; DROP TABLE
        r"--",  # SQL comments
        r"/\*.*\*/",  # SQL multi-line comments
        r"\bUNION\b.*\bSELECT\b",  # UNION SELECT
        r"\bexec\s*\(",  # exec(
        r"\bxp_cmdshell\b",  # xp_cmdshell
        r"'\s*(OR|AND)\s*'",  # ' OR ', ' AND '
    ]

    for pattern in sql_patterns:
        if re.search(pattern, input_str, re.IGNORECASE):
            return False, "Possible SQL injection detected"

    # 2. Path traversal
    if re.search(r"\.\.[/\\]", input_str):
        return False, "Path traversal attempt detected"

    # 3. Command injection (alleen als het verdachte tekens zijn in verkeerde context)
    cmd_chars = ['|', '$', '`', '\n', '\r']
    if any(char in input_str for char in cmd_chars):
        return False, "Command injection characters detected"

    # 4. Null byte injection
    if '\x00' in input_str:
        return False, "Null byte detected"

    # 5. Script injection
    if re.search(r"<script|javascript:|onerror=|onclick=", input_str, re.IGNORECASE):
        return False, "Script injection detected"

    return True, "Input is safe"

def sanitize_input(text: str) -> str:
    """
    LEGACY FUNCTION - NOT USED
    Enhanced input sanitization with injection detection
    WARNING: This function modifies input and is not compliant with strict whitelisting
    """
    if not text:
        return ""

    # FIX: Check for injection attempts FIRST
    is_safe, reason = detect_injection_attempts(str(text))
    if not is_safe:
        # Log suspicious activity but don't import here to avoid circular dependency
        # This will be logged at the UI level
        raise ValueError(f"Security violation: {reason}")

    # Remove null bytes and control characters
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', str(text))

    # Limit length
    return sanitized[:1000]

def validate_search_term(search_term: str) -> bool:
    """Valideer zoekterm: alfanumeriek, spaties, basis leestekens (max 100 tekens)"""
    if not search_term or len(search_term) < 1:
        return False

    # Prevent excessively long search terms
    if len(search_term) > 100:
        return False

    # Allow alphanumeric, spaces, and common punctuation
    return bool(re.fullmatch(r"[A-Za-z0-9\s@.\-_']{1,100}", search_term))

def check_back_command(user_input: str) -> bool:
    """Check terug-commando: strikte case-sensitive whitelist"""
    return user_input in ['terug', 'back', 'b', 't', 'exit', 'quit',
                          'Terug', 'Back', 'B', 'T', 'Exit', 'Quit',
                          'TERUG', 'BACK', 'EXIT', 'QUIT']

# Validation helper functions
def get_validation_error_message(field: str, value: str) -> str:
    """Retourneer passende foutmelding voor gefaalde validatie"""
    error_messages = {
        'username': 'Gebruikersnaam moet 8-10 tekens zijn, beginnen met letter/underscore, en mag alleen letters, cijfers, _, \', . bevatten',
        'password': 'Wachtwoord moet 12-30 tekens zijn met minimaal 1 kleine letter, 1 hoofdletter, 1 cijfer en 1 speciaal teken',
        'zip_code': 'Postcode moet format DDDDXX hebben (bijv. 1234AB)',
        'mobile_phone': 'Telefoonnummer moet 8 cijfers zijn',
        'driving_license': 'Rijbewijsnummer moet format XXDDDDDDD of XDDDDDDDD hebben',
        'email': 'Ongeldig email adres',
        'birthday': 'Geboortedatum moet geldig zijn en tussen 16-120 jaar geleden (DD-MM-YYYY)',
        'birthday_dutch': 'Geboortedatum moet geldig zijn en tussen 16-120 jaar geleden (DD-MM-YYYY)',
        'flexible_date': 'Datum moet geldig zijn (bijv. 15-03-2024, 15/03/24, 15.03.2024)',
        'gender': 'Geslacht moet \'male\' of \'female\' zijn',
        'city': 'Stad moet een van de geldige steden zijn',
        'gps': 'GPS coördinaten moeten geldig zijn voor Rotterdam gebied met 5 decimalen',
        'serial_number': 'Serienummer moet 10-17 alfanumerieke tekens zijn',
        'date': 'Datum moet format YYYY-MM-DD hebben',
        'date_dutch': 'Datum moet format DD-MM-YYYY hebben',
        'percentage': 'Waarde moet tussen 0 en 100 zijn',
        'positive_integer': 'Waarde moet een positief getal zijn',
        'positive_float': 'Waarde moet een positief getal zijn',
        'name': 'Naam mag alleen letters, spaties, apostroffen en koppeltekens bevatten',
        'search_term': 'Zoekterm bevat ongeldige tekens'
    }
    return error_messages.get(field, f'Ongeldige waarde voor {field}: {value}')

def get_validated_input_with_back(prompt: str, validator_func, validation_type: str, allow_empty: bool = False, max_attempts: int = 3) -> str:
    """Vraag gevalideerde input met max pogingen en terug-optie - bevat injection detectie"""
    for attempt in range(1, max_attempts + 1):
        # Show attempt counter if more than 1 attempt allowed
        if max_attempts > 1:
            attempt_info = f" (poging {attempt}/{max_attempts})"
        else:
            attempt_info = ""

        value = input(f"{prompt}{attempt_info}: ").strip()

        # Check back command
        if check_back_command(value):
            return None

        # Check if empty is allowed
        if allow_empty and not value:
            return ""

        # FIX: Check for injection attempts
        try:
            is_safe, reason = detect_injection_attempts(value)
            if not is_safe:
                print(f"🚨 SECURITY WAARSCHUWING: {reason}")
                print(f"❌ Ongeldige invoer gedetecteerd. Dit incident wordt gelogd.")
                # Don't count as normal attempt, immediately return None
                return None
        except:
            pass  # Continue with normal validation

        # Validate input
        if validator_func(value):
            return value
        else:
            error_msg = get_validation_error_message(validation_type, value)
            print(f"❌ {error_msg}")

            if attempt < max_attempts:
                print(f"Probeer opnieuw. Nog {max_attempts - attempt} poging(en).")
            else:
                print(f"❌ Maximum aantal pogingen ({max_attempts}) bereikt.")
                return None  # Failed after max attempts

    return None