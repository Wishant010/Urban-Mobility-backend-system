import bcrypt
import time
from datetime import datetime, timedelta
from db import get_user_by_username, add_user, log_event, reset_user_password
from input_validation import validate_username, validate_password
from encryption import encrypt_data, decrypt_data

SUPER_ADMIN = {'username': 'super_admin', 'password': 'Admin_123?', 'role': 'super_admin'}

# Track failed login attempts for suspicious activity detection
failed_attempts = {}

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode(), hashed.encode())

def is_suspicious_login_attempt(username: str) -> bool:
    """Check if login attempts are suspicious (multiple failed attempts)"""
    current_time = datetime.now()
    
    # Clean old attempts (older than 15 minutes)
    cutoff_time = current_time - timedelta(minutes=15)
    if username in failed_attempts:
        failed_attempts[username] = [
            attempt_time for attempt_time in failed_attempts[username] 
            if attempt_time > cutoff_time
        ]
    
    # Check if more than 3 attempts in last 15 minutes
    if username in failed_attempts:
        return len(failed_attempts[username]) >= 3
    return False

def record_failed_attempt(username: str):
    """Record a failed login attempt"""
    current_time = datetime.now()
    if username not in failed_attempts:
        failed_attempts[username] = []
    failed_attempts[username].append(current_time)

def login(username: str, password: str) -> tuple[str, str] | None:
    """
    Authenticate user and return (role, username) if successful
    Returns None if authentication fails
    """
    # Check for suspicious activity
    suspicious = is_suspicious_login_attempt(username)
    
    # Handle super admin login
    if username == SUPER_ADMIN['username'] and password == SUPER_ADMIN['password']:
        log_event(f"Succesvol ingelogd", username, f"Rol: {SUPER_ADMIN['role']}", suspicious)
        # Clear failed attempts on successful login
        if username in failed_attempts:
            del failed_attempts[username]
        return SUPER_ADMIN['role'], username
    
    # Handle regular user login
    user = get_user_by_username(username)
    if user and check_password(password, user['password_hash']):
        log_event(f"Succesvol ingelogd", username, f"Rol: {user['role']}", suspicious)
        # Clear failed attempts on successful login
        if username in failed_attempts:
            del failed_attempts[username]
        return user['role'], username
    else:
        # Record failed attempt
        record_failed_attempt(username)
        additional_info = f"Gebruikersnaam: {username}"
        if is_suspicious_login_attempt(username):
            additional_info += " - Meerdere mislukte pogingen gedetecteerd"
        log_event(f"Mislukte inlogpoging", "", additional_info, suspicious)
        return None

def register_user(username: str, password: str, role: str, first_name: str, last_name: str, 
                 current_user_role: str) -> tuple[bool, str]:
    """
    Register a new user with role-based permissions
    Returns (success, message)
    """
    # Check role permissions
    if not can_create_user(current_user_role, role):
        return False, f"Geen toestemming om {role} aan te maken"
    
    # Validate input
    if not validate_username(username):
        return False, "Ongeldige gebruikersnaam format"
    
    if not validate_password(password):
        return False, "Wachtwoord voldoet niet aan eisen (12-30 tekens, uppercase, lowercase, cijfer, speciaal teken)"
    
    if role not in ['super_admin', 'system_admin', 'service_engineer']:
        return False, "Ongeldige rol"
    
    if not first_name or not last_name:
        return False, "Voor- en achternaam zijn verplicht"
    
    # Try to create user
    password_hash = hash_password(password)
    result = add_user(username, password_hash, role, first_name, last_name)
    
    if result:
        log_event(f"Nieuwe gebruiker aangemaakt", username, f"Rol: {role}, Naam: {first_name} {last_name}")
        return True, "Gebruiker succesvol aangemaakt"
    else:
        log_event(f"Mislukte gebruiker aanmaak", "", f"Gebruikersnaam: {username} (mogelijk al in gebruik)")
        return False, "Gebruiker aanmaken mislukt (gebruikersnaam mogelijk al in gebruik)"

def can_create_user(current_role: str, target_role: str) -> bool:
    """Check if current user role can create target user role"""
    if current_role == 'super_admin':
        return True  # Super admin can create anyone
    elif current_role == 'system_admin':
        return target_role == 'service_engineer'  # System admin can only create service engineers
    else:
        return False  # Service engineers cannot create users

def can_manage_user(current_role: str, target_role: str) -> bool:
    """Check if current user role can manage (update/delete) target user role"""
    if current_role == 'super_admin':
        return True  # Super admin can manage anyone except other super admins
    elif current_role == 'system_admin':
        return target_role == 'service_engineer'  # System admin can only manage service engineers
    else:
        return False  # Service engineers cannot manage other users

def reset_password(username: str, current_user_role: str) -> tuple[bool, str]:
    """
    Reset user password (generate temporary password)
    Returns (success, new_password_or_error_message)
    """
    user = get_user_by_username(username)
    if not user:
        return False, "Gebruiker niet gevonden"
    
    if not can_manage_user(current_user_role, user['role']):
        return False, "Geen toestemming om dit account te beheren"
    
    # Generate temporary password
    import secrets
    import string
    temp_password = ''.join(secrets.choice(string.ascii_letters + string.digits + "!@#$%") for _ in range(12))
    temp_password = "Temp" + temp_password + "1!"  # Ensure it meets complexity requirements
    
    # Hash and update password
    password_hash = hash_password(temp_password)
    if reset_user_password(username, password_hash):
        log_event(f"Wachtwoord gereset", username, f"Voor gebruiker: {username}")
        return True, temp_password
    else:
        return False, "Fout bij wachtwoord reset"

def change_own_password(username: str, old_password: str, new_password: str) -> tuple[bool, str]:
    """
    Allow user to change their own password
    Returns (success, message)
    """
    # Skip validation for super admin (hardcoded)
    if username == SUPER_ADMIN['username']:
        return False, "Super admin wachtwoord kan niet gewijzigd worden"

    # Verify old password
    user = get_user_by_username(username)
    if not user or not check_password(old_password, user['password_hash']):
        log_event(f"Mislukte wachtwoord wijziging", username, "Verkeerd huidig wachtwoord")
        return False, "Huidig wachtwoord is incorrect"

    # FIX: Check if new password is same as old password
    if old_password == new_password:
        log_event(f"Mislukte wachtwoord wijziging", username, "Nieuw wachtwoord is hetzelfde als oud wachtwoord")
        return False, "Nieuw wachtwoord mag niet hetzelfde zijn als het huidige wachtwoord"

    # Validate new password
    if not validate_password(new_password):
        return False, "Nieuw wachtwoord voldoet niet aan eisen"

    # Update password
    password_hash = hash_password(new_password)
    if reset_user_password(username, password_hash):
        log_event(f"Wachtwoord succesvol gewijzigd", username)
        return True, "Wachtwoord succesvol gewijzigd"
    else:
        return False, "Fout bij wachtwoord wijziging"

def get_role_permissions(role: str) -> dict:
    """Get permissions for each role"""
    permissions = {
        'super_admin': {
            'manage_users': True,
            'manage_system_admins': True,
            'manage_service_engineers': True,
            'manage_travellers': True,
            'manage_scooters': True,
            'view_logs': True,
            'create_backup': True,
            'restore_backup': True,
            'generate_restore_codes': True,
            'revoke_restore_codes': True
        },
        'system_admin': {
            'manage_users': False,
            'manage_system_admins': False,
            'manage_service_engineers': True,
            'manage_travellers': True,
            'manage_scooters': True,
            'view_logs': True,
            'create_backup': True,
            'restore_backup': True,  # With restore code
            'generate_restore_codes': False,
            'revoke_restore_codes': False
        },
        'service_engineer': {
            'manage_users': False,
            'manage_system_admins': False,
            'manage_service_engineers': False,
            'manage_travellers': False,
            'manage_scooters': True,  # Limited updates only
            'view_logs': False,
            'create_backup': False,
            'restore_backup': False,
            'generate_restore_codes': False,
            'revoke_restore_codes': False
        }
    }
    return permissions.get(role, {})

def has_permission(role: str, permission: str) -> bool:
    """Check if role has specific permission"""
    permissions = get_role_permissions(role)
    return permissions.get(permission, False)

def validate_role_action(current_role: str, action: str) -> bool:
    """Validate if current role can perform the action"""
    role_actions = {
        'super_admin': [
            'create_user', 'update_user', 'delete_user', 'reset_password',
            'create_traveller', 'update_traveller', 'delete_traveller', 'search_traveller',
            'create_scooter', 'update_scooter', 'delete_scooter', 'search_scooter',
            'view_logs', 'create_backup', 'restore_backup', 'generate_restore_code', 'revoke_restore_code'
        ],
        'system_admin': [
            'create_service_engineer', 'update_service_engineer', 'delete_service_engineer', 'reset_service_engineer_password',
            'create_traveller', 'update_traveller', 'delete_traveller', 'search_traveller',
            'create_scooter', 'update_scooter', 'delete_scooter', 'search_scooter',
            'view_logs', 'create_backup', 'restore_backup'
        ],
        'service_engineer': [
            'search_traveller', 'search_scooter', 'update_scooter_limited'
        ]
    }
    
    allowed_actions = role_actions.get(current_role, [])
    return action in allowed_actions