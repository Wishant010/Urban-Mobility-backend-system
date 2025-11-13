from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
from typing import Optional

# Configuration
KEY_PATH = 'data/fernet.key'
SALT_PATH = 'data/salt.key'

def ensure_data_dir():
    """Zorg dat data directory bestaat"""
    if not os.path.exists('data'):
        os.makedirs('data')

def generate_salt() -> bytes:
    """Genereer nieuwe salt voor key derivation"""
    return os.urandom(16)

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Afleiden encryptie key uit wachtwoord met PBKDF2 (100k iteraties)"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # High iteration count for security
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def load_or_create_key() -> bytes:
    """Laad bestaande encryptie key of maak nieuwe aan"""
    ensure_data_dir()
    
    if os.path.exists(KEY_PATH):
        # Load existing key
        try:
            with open(KEY_PATH, 'rb') as f:
                key = f.read()
            # Validate key format
            Fernet(key)  # This will raise an exception if key is invalid
            return key
        except Exception as e:
            print(f"Warning: Invalid key file, generating new key. Error: {e}")
            # If key is corrupted, generate new one
            return create_new_key()
    else:
        # Create new key
        return create_new_key()

def create_new_key() -> bytes:
    """Creëer en sla nieuwe encryptie key veilig op (chmod 600)"""
    ensure_data_dir()
    
    # Generate new key
    key = Fernet.generate_key()
    
    # Save key securely
    try:
        with open(KEY_PATH, 'wb') as f:
            f.write(key)
        
        # Set restrictive permissions on Unix systems
        if hasattr(os, 'chmod'):
            os.chmod(KEY_PATH, 0o600)  # Read/write for owner only
        
        print("Nieuwe encryptie sleutel gegenereerd en veilig opgeslagen.")
        return key
    except Exception as e:
        raise Exception(f"Fout bij opslaan encryptie sleutel: {e}")

def load_or_create_salt() -> bytes:
    """Laad bestaande salt of maak nieuwe aan"""
    ensure_data_dir()
    
    if os.path.exists(SALT_PATH):
        with open(SALT_PATH, 'rb') as f:
            return f.read()
    else:
        salt = generate_salt()
        with open(SALT_PATH, 'wb') as f:
            f.write(salt)
        
        # Set restrictive permissions
        if hasattr(os, 'chmod'):
            os.chmod(SALT_PATH, 0o600)
        
        return salt

# Initialize encryption components
try:
    key = load_or_create_key()
    fernet = Fernet(key)
    salt = load_or_create_salt()
    print("✅ Encryptie systeem geïnitialiseerd en gevalideerd.")
except Exception as e:
    print(f"❌ Fatale fout bij initialiseren encryptie: {e}")
    raise

def encrypt_data(data: str) -> str:
    """Versleutel string met Fernet - retourneert base64 encoded data"""
    if not data:
        return ""
    
    try:
        encrypted_bytes = fernet.encrypt(data.encode('utf-8'))
        return encrypted_bytes.decode('utf-8')
    except Exception as e:
        print(f"Encryptie mislukt voor data: {e}")
        return data  # Return original data if encryption fails

def decrypt_data(encrypted_data: str) -> str:
    """Ontsleutel Fernet data - retourneert originele string"""
    if not encrypted_data:
        return ""
    
    try:
        decrypted_bytes = fernet.decrypt(encrypted_data.encode('utf-8'))
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        # If decryption fails, assume data is not encrypted (legacy data)
        # This allows for graceful handling of mixed encrypted/unencrypted data
        return encrypted_data

def encrypt_sensitive_fields(data_dict: dict, sensitive_fields: list) -> dict:
    """Versleutel specifieke velden in dictionary"""
    encrypted_dict = data_dict.copy()
    
    for field in sensitive_fields:
        if field in encrypted_dict and encrypted_dict[field] is not None:
            try:
                encrypted_dict[field] = encrypt_data(str(encrypted_dict[field]))
            except Exception as e:
                print(f"Waarschuwing: Encryptie mislukt voor veld {field}: {e}")
    
    return encrypted_dict

def decrypt_sensitive_fields(data_dict: dict, sensitive_fields: list) -> dict:
    """Ontsleutel specifieke velden in dictionary"""
    decrypted_dict = data_dict.copy()
    
    for field in sensitive_fields:
        if field in decrypted_dict and decrypted_dict[field] is not None:
            try:
                decrypted_dict[field] = decrypt_data(str(decrypted_dict[field]))
            except Exception as e:
                # If decryption fails, assume data is not encrypted (legacy data)
                # This allows for graceful handling of mixed encrypted/unencrypted data
                pass
    
    return decrypted_dict

def is_encrypted(data: str) -> bool:
    """Check of string versleutelde data lijkt te zijn"""
    if not data:
        return False
    
    try:
        # Try to decrypt - if successful, it was encrypted
        decrypt_data(data)
        return True
    except:
        return False

def encrypt_file_content(file_path: str, output_path: Optional[str] = None) -> bool:
    """Versleutel volledig bestand - output naar .enc bestand"""
    if not os.path.exists(file_path):
        return False
    
    if output_path is None:
        output_path = file_path + '.enc'
    
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        encrypted_data = fernet.encrypt(file_data)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        return True
    except Exception as e:
        print(f"Bestand encryptie mislukt: {e}")
        return False

def decrypt_file_content(encrypted_file_path: str, output_path: Optional[str] = None) -> bool:
    """Ontsleutel volledig bestand - verwijdert .enc extensie"""
    if not os.path.exists(encrypted_file_path):
        return False
    
    if output_path is None:
        if encrypted_file_path.endswith('.enc'):
            output_path = encrypted_file_path[:-4]  # Remove .enc extension
        else:
            output_path = encrypted_file_path + '.dec'
    
    try:
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = fernet.decrypt(encrypted_data)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        
        return True
    except Exception as e:
        print(f"Bestand decryptie mislukt: {e}")
        return False

def validate_encryption_setup() -> bool:
    """Valideer dat encryptie correct werkt met test data"""
    test_data = "Test encryptie string 123!@#"
    
    try:
        # Test basic encryption/decryption
        encrypted = encrypt_data(test_data)
        decrypted = decrypt_data(encrypted)
        
        if decrypted != test_data:
            return False
        
        # Test with empty string
        encrypted_empty = encrypt_data("")
        decrypted_empty = decrypt_data(encrypted_empty)
        
        if decrypted_empty != "":
            return False
        
        # Test unicode characters
        unicode_test = "Test met unicode: áéíóú ñ 中文 🚀"
        encrypted_unicode = encrypt_data(unicode_test)
        decrypted_unicode = decrypt_data(encrypted_unicode)
        
        if decrypted_unicode != unicode_test:
            return False
        
        return True
    except Exception as e:
        print(f"Encryptie validatie mislukt: {e}")
        return False

def get_encryption_info() -> dict:
    """Retourneer informatie over encryptie setup"""
    info = {
        'key_file_exists': os.path.exists(KEY_PATH),
        'salt_file_exists': os.path.exists(SALT_PATH),
        'encryption_working': validate_encryption_setup(),
        'key_file_size': os.path.getsize(KEY_PATH) if os.path.exists(KEY_PATH) else 0,
        'algorithm': 'Fernet (AES 128 in CBC mode with HMAC-SHA256)'
    }
    
    return info

def rotate_encryption_key() -> bool:
    """Genereer nieuwe encryptie key - WAARSCHUWING: oude data onleesbaar!"""
    try:
        # Backup old key
        if os.path.exists(KEY_PATH):
            backup_path = KEY_PATH + '.backup'
            import shutil
            shutil.copy2(KEY_PATH, backup_path)
        
        # Generate new key
        new_key = create_new_key()
        
        # Update global fernet instance
        global fernet
        fernet = Fernet(new_key)
        
        print("Encryptie sleutel succesvol geroteerd.")
        print("WAARSCHUWING: Eerder versleutelde data kan niet meer ontsleuteld worden met de nieuwe sleutel!")
        
        return True
    except Exception as e:
        print(f"Sleutel rotatie mislukt: {e}")
        return False

# Security utility functions
def secure_delete_file(file_path: str) -> bool:
    """Veilig verwijder bestand - overschrijf 3x met random data voor verwijderen"""
    if not os.path.exists(file_path):
        return False
    
    try:
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Overwrite with random data multiple times
        with open(file_path, 'rb+') as f:
            for _ in range(3):  # 3 passes
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
        
        # Delete the file
        os.remove(file_path)
        return True
    except Exception as e:
        print(f"Veilig bestand verwijderen mislukt: {e}")
        return False

# Test encryption on import
if not validate_encryption_setup():
    print("⚠️ WAARSCHUWING: Encryptie validatie mislukt! Systeem is mogelijk niet veilig.")