import os
import zipfile
import shutil
from datetime import datetime
from db import log_event, get_restore_code, use_restore_code

BACKUP_DIR = 'backups/'
DATA_DIR = 'data/'
DB_FILE = 'data/data.db'
LOG_FILE = 'logs.db'

def ensure_backup_dir():
    """Zorg dat backup directory bestaat"""
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

def ensure_data_dir():
    """Zorg dat data directory bestaat"""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

def create_backup(username: str) -> str:
    """Maak backup van database, encryptie keys en logs - retourneert filename"""
    ensure_backup_dir()
    ensure_data_dir()
    
    # Generate backup filename with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_name = f"backup_{timestamp}.zip"
    backup_path = os.path.join(BACKUP_DIR, backup_name)
    
    try:
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add main database file
            if os.path.exists(DB_FILE):
                zipf.write(DB_FILE, os.path.basename(DB_FILE))
            
            # Add encryption key
            key_file = 'data/fernet.key'
            if os.path.exists(key_file):
                zipf.write(key_file, os.path.basename(key_file))
            
            # Add salt file
            salt_file = 'data/salt.key'
            if os.path.exists(salt_file):
                zipf.write(salt_file, os.path.basename(salt_file))
            
            # Add log file if it exists
            if os.path.exists(LOG_FILE):
                zipf.write(LOG_FILE, os.path.basename(LOG_FILE))
            
            # Add backup metadata
            metadata = f"""Backup Informatie
Aangemaakt: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}
Aangemaakt door: {username}
Database: {DB_FILE}
Grootte: {os.path.getsize(DB_FILE) if os.path.exists(DB_FILE) else 0} bytes
Versie: Urban Mobility Backend System v1.0
"""
            zipf.writestr("backup_info.txt", metadata)
        
        log_event(f"Backup succesvol aangemaakt", username, f"Backup bestand: {backup_name}")
        return backup_name
        
    except Exception as e:
        log_event(f"Backup aanmaken mislukt", username, f"Fout: {str(e)}", suspicious=False)
        raise Exception(f"Fout bij aanmaken backup: {e}")

def list_backups() -> list:
    """Lijst alle beschikbare backups met info (gesorteerd op datum)"""
    ensure_backup_dir()
    
    backups = []
    
    try:
        for filename in os.listdir(BACKUP_DIR):
            if filename.endswith('.zip') and filename.startswith('backup_'):
                filepath = os.path.join(BACKUP_DIR, filename)
                
                # Get file stats
                stat = os.stat(filepath)
                size = stat.st_size
                created = datetime.fromtimestamp(stat.st_ctime)
                
                # Try to read backup info from zip
                backup_info = {
                    'filename': filename,
                    'filepath': filepath,
                    'size': size,
                    'created': created,
                    'creator': 'Onbekend',
                    'size_mb': round(size / (1024 * 1024), 2)
                }
                
                try:
                    with zipfile.ZipFile(filepath, 'r') as zipf:
                        if 'backup_info.txt' in zipf.namelist():
                            info_content = zipf.read('backup_info.txt').decode('utf-8')
                            # Parse creator from backup info
                            for line in info_content.split('\n'):
                                if 'Aangemaakt door:' in line:
                                    backup_info['creator'] = line.split(':', 1)[1].strip()
                                    break
                                elif 'Created by:' in line:  # Fallback for English
                                    backup_info['creator'] = line.split(':', 1)[1].strip()
                                    break
                except:
                    pass  # If we can't read info, use defaults
                
                backups.append(backup_info)
        
        # Sort by creation date (newest first)
        backups.sort(key=lambda x: x['created'], reverse=True)
        
    except Exception as e:
        log_event(f"Fout bij ophalen backup lijst", "", f"Fout: {str(e)}")
    
    return backups

def restore_backup(backup_filename: str, username: str, restore_code: str = None, is_super_admin: bool = False) -> bool:
    """Herstel backup - super_admin zonder code, system_admin met éénmalige restore code"""
    backup_path = os.path.join(BACKUP_DIR, backup_filename)
    
    # Check if backup file exists
    if not os.path.exists(backup_path):
        log_event(f"Restore mislukt - backup niet gevonden", username, f"Backup: {backup_filename}")
        return False
    
    # Check permissions
    if not is_super_admin:
        if not restore_code:
            log_event(f"Restore geweigerd - geen restore code", username, f"Backup: {backup_filename}")
            return False
        
        # Validate restore code
        code_info = get_restore_code(restore_code)
        if not code_info:
            log_event(f"Restore geweigerd - ongeldige restore code", username, f"Code: {restore_code}", suspicious=True)
            return False
        
        if code_info['system_admin_username'] != username:
            log_event(f"Restore geweigerd - restore code niet voor deze gebruiker", username, f"Code voor: {code_info['system_admin_username']}", suspicious=True)
            return False
        
        if code_info['backup_name'] != backup_filename:
            log_event(f"Restore geweigerd - restore code niet voor deze backup", username, f"Code voor: {code_info['backup_name']}")
            return False
    
    try:
        # Create backup of current state before restoring
        current_backup = create_backup(f"auto_voor_restore_{username}")
        
        # Extract backup
        ensure_data_dir()
        
        with zipfile.ZipFile(backup_path, 'r') as zipf:
            # List contents to see what we're restoring
            contents = zipf.namelist()
            
            # Extract database file
            if 'data.db' in contents:
                zipf.extract('data.db', DATA_DIR)
            
            # Extract encryption key if present
            if 'fernet.key' in contents:
                zipf.extract('fernet.key', DATA_DIR)
            
            # Extract salt if present
            if 'salt.key' in contents:
                zipf.extract('salt.key', DATA_DIR)
            
            # Extract logs if present
            if 'logs.db' in contents:
                zipf.extract('logs.db', '.')
        
        # Mark restore code as used (if applicable)
        if not is_super_admin and restore_code:
            use_restore_code(restore_code)
        
        log_event(f"Backup succesvol hersteld", username, f"Backup: {backup_filename}, Auto-backup: {current_backup}")
        return True
        
    except Exception as e:
        log_event(f"Restore mislukt", username, f"Backup: {backup_filename}, Fout: {str(e)}")
        return False

def delete_backup(backup_filename: str, username: str) -> bool:
    """Verwijder backup bestand (alleen super_admin)"""
    backup_path = os.path.join(BACKUP_DIR, backup_filename)
    
    try:
        if os.path.exists(backup_path):
            os.remove(backup_path)
            log_event(f"Backup verwijderd", username, f"Backup: {backup_filename}")
            return True
        else:
            return False
    except Exception as e:
        log_event(f"Backup verwijderen mislukt", username, f"Backup: {backup_filename}, Fout: {str(e)}")
        return False

def get_backup_info(backup_filename: str) -> dict:
    """Retourneer gedetailleerde informatie over backup bestand"""
    backup_path = os.path.join(BACKUP_DIR, backup_filename)
    
    if not os.path.exists(backup_path):
        return None
    
    info = {
        'filename': backup_filename,
        'size': os.path.getsize(backup_path),
        'size_mb': round(os.path.getsize(backup_path) / (1024 * 1024), 2),
        'created': datetime.fromtimestamp(os.path.getctime(backup_path)),
        'contents': [],
        'metadata': {}
    }
    
    try:
        with zipfile.ZipFile(backup_path, 'r') as zipf:
            info['contents'] = zipf.namelist()
            
            # Read backup metadata if available
            if 'backup_info.txt' in zipf.namelist():
                metadata_content = zipf.read('backup_info.txt').decode('utf-8')
                for line in metadata_content.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        info['metadata'][key.strip()] = value.strip()
    except:
        pass
    
    return info

def cleanup_old_backups(keep_count: int = 10, username: str = "systeem") -> int:
    """Ruim oude backups op - behoud alleen N meest recente"""
    backups = list_backups()
    
    if len(backups) <= keep_count:
        return 0
    
    # Delete oldest backups
    backups_to_delete = backups[keep_count:]
    deleted_count = 0
    
    for backup in backups_to_delete:
        try:
            os.remove(backup['filepath'])
            deleted_count += 1
        except Exception as e:
            log_event(f"Fout bij verwijderen oude backup", username, f"Backup: {backup['filename']}, Fout: {str(e)}")
    
    if deleted_count > 0:
        log_event(f"Oude backups opgeruimd", username, f"{deleted_count} backups verwijderd, {keep_count} behouden")
    
    return deleted_count

def verify_backup(backup_filename: str) -> bool:
    """Verifieer backup integriteit - test zip en controleer data.db aanwezig"""
    backup_path = os.path.join(BACKUP_DIR, backup_filename)
    
    if not os.path.exists(backup_path):
        return False
    
    try:
        with zipfile.ZipFile(backup_path, 'r') as zipf:
            # Test the zip file
            result = zipf.testzip()
            if result is not None:
                return False
            
            # Check if essential files are present
            contents = zipf.namelist()
            if 'data.db' not in contents:
                return False
            
            return True
    except:
        return False

def get_backup_size_mb(backup_filename: str) -> float:
    """Retourneer backup grootte in MB"""
    backup_path = os.path.join(BACKUP_DIR, backup_filename)
    
    if not os.path.exists(backup_path):
        return 0.0
    
    size_bytes = os.path.getsize(backup_path)
    return round(size_bytes / (1024 * 1024), 2)

def create_incremental_backup(username: str, last_backup_date: datetime = None) -> str:
    """Maak incrementele backup (momenteel volledige backup met andere log)"""
    backup_name = create_backup(username)
    log_event(f"Incrementele backup aangemaakt", username, f"Backup: {backup_name}")
    return backup_name

def get_backup_statistics() -> dict:
    """Retourneer backup statistieken (aantal, grootte, oudste/nieuwste)"""
    backups = list_backups()
    
    if not backups:
        return {
            'total_backups': 0,
            'total_size_mb': 0,
            'oldest_backup': None,
            'newest_backup': None,
            'average_size_mb': 0
        }
    
    total_size = sum(backup['size'] for backup in backups)
    
    return {
        'total_backups': len(backups),
        'total_size_mb': round(total_size / (1024 * 1024), 2),
        'oldest_backup': backups[-1]['created'].strftime('%d-%m-%Y %H:%M'),
        'newest_backup': backups[0]['created'].strftime('%d-%m-%Y %H:%M'),
        'average_size_mb': round((total_size / len(backups)) / (1024 * 1024), 2)
    }