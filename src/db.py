import sqlite3
import os
from datetime import datetime
from encryption import encrypt_data, decrypt_data

DB_PATH = 'data/data.db'

def ensure_data_dir():
    """Ensure data directory exists"""
    if not os.path.exists('data'):
        os.makedirs('data')

def get_db():
    """Get database connection"""
    ensure_data_dir()
    return sqlite3.connect(DB_PATH)

def init_db():
    """Initialize database with all required tables"""
    with get_db() as conn:
        c = conn.cursor()
        
        # Users table
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            registration_date TEXT
        )''')
        
        # Travellers table with all required fields (sensitive data encrypted)
        c.execute('''CREATE TABLE IF NOT EXISTS travellers (
            customer_id TEXT PRIMARY KEY,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            birthday TEXT NOT NULL,
            gender TEXT NOT NULL,
            street_name TEXT NOT NULL,
            house_number TEXT NOT NULL,
            zip_code TEXT NOT NULL,
            city TEXT NOT NULL,
            email_address TEXT NOT NULL,
            mobile_phone TEXT NOT NULL,
            driving_license_number TEXT NOT NULL,
            registration_date TEXT NOT NULL
        )''')
        
        # Scooters table with all required fields
        c.execute('''CREATE TABLE IF NOT EXISTS scooters (
            serial_number TEXT PRIMARY KEY,
            brand TEXT NOT NULL,
            model TEXT NOT NULL,
            top_speed INTEGER NOT NULL,
            battery_capacity INTEGER NOT NULL,
            state_of_charge INTEGER NOT NULL,
            target_range_soc TEXT NOT NULL,
            location TEXT NOT NULL,
            out_of_service_status INTEGER DEFAULT 0,
            mileage REAL DEFAULT 0.0,
            last_maintenance_date TEXT,
            in_service_date TEXT NOT NULL
        )''')
        
        # Logs table
        c.execute('''CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT,
            description TEXT NOT NULL,
            additional_info TEXT,
            suspicious INTEGER DEFAULT 0
        )''')
        
        # Restore codes table
        c.execute('''CREATE TABLE IF NOT EXISTS restore_codes (
            code TEXT PRIMARY KEY,
            system_admin_username TEXT NOT NULL,
            backup_name TEXT NOT NULL,
            created_date TEXT NOT NULL,
            used INTEGER DEFAULT 0
        )''')
        
        conn.commit()

# Helper function to find user by username (handles both encrypted and unencrypted)
def _find_user_row(username):
    """Find user row by username (handles encryption)"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT username, password_hash, role, first_name, last_name, registration_date FROM users')
        rows = c.fetchall()

        for row in rows:
            try:
                # Try to decrypt the stored username
                decrypted_username = decrypt_data(row[0])
                # FIX: Use casefold() for case-insensitive comparison without modifying input
                if decrypted_username.casefold() == username.casefold():
                    return row
            except:
                # Handle legacy unencrypted data
                if row[0].casefold() == username.casefold():
                    return row
        return None

# ============================================================================
# USER MANAGEMENT FUNCTIONS
# ============================================================================

def get_user_by_username(username: str):
    """Get user by username"""
    try:
        row = _find_user_row(username)
        if row:
            try:
                decrypted_username = decrypt_data(row[0])
            except:
                decrypted_username = row[0]  # Legacy unencrypted data
                
            return {
                'username': decrypted_username,
                'password_hash': row[1],
                'role': row[2],
                'first_name': row[3],
                'last_name': row[4],
                'registration_date': row[5]
            }
    except Exception as e:
        print(f"Error getting user: {e}")
    return None

def add_user(username, password_hash, role, first_name, last_name):
    """Add new user to database with uniqueness check and validation"""
    try:
        # FIX: Whitelisting validation - validate ALL inputs before database operation
        from input_validation import validate_username, validate_name

        # Validate username format
        if not validate_username(username):
            print(f"Invalid username format: {username}")
            return False

        # Validate role (whitelist)
        valid_roles = ['super_admin', 'system_admin', 'service_engineer']
        if role not in valid_roles:
            print(f"Invalid role: {role}")
            return False

        # Validate names
        if not validate_name(first_name) or not validate_name(last_name):
            print(f"Invalid name format")
            return False

        # Check if username already exists (case-insensitive)
        existing_user = get_user_by_username(username)
        if existing_user:
            return False  # Username already exists

        with get_db() as conn:
            c = conn.cursor()
            # Encrypt sensitive data
            encrypted_username = encrypt_data(username)
            # FIX: SQL Query Logging for audit trail
            log_event(f"SQL INSERT executed", "", f"Table: users, Username: {username}, Role: {role}")
            c.execute('''INSERT INTO users (username, password_hash, role, first_name, last_name, registration_date)
                        VALUES (?, ?, ?, ?, ?, ?)''',
                      (encrypted_username, password_hash, role, first_name, last_name, datetime.now().isoformat()))
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        log_event(f"SQL INSERT failed", "", f"Table: users, Username: {username}, Reason: Duplicate", suspicious=True)
        return False
    except Exception as e:
        print(f"Error adding user: {e}")
        log_event(f"SQL INSERT failed", "", f"Table: users, Error: {str(e)}", suspicious=True)
        return False

def get_all_users():
    """Get all users from database"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT username, role, first_name, last_name, registration_date FROM users')
            rows = c.fetchall()
            users = []
            for row in rows:
                try:
                    decrypted_username = decrypt_data(row[0])
                    users.append({
                        'username': decrypted_username,
                        'role': row[1],
                        'first_name': row[2],
                        'last_name': row[3],
                        'registration_date': row[4]
                    })
                except:
                    # Handle legacy unencrypted data
                    users.append({
                        'username': row[0],
                        'role': row[1],
                        'first_name': row[2],
                        'last_name': row[3],
                        'registration_date': row[4]
                    })
            return users
    except Exception as e:
        print(f"Error getting all users: {e}")
        return []

def update_user(username, **kwargs):
    """Update user information - supports all fields including role"""
    try:
        # FIX: SQL Injection Prevention - Explicit field whitelist (already present, enhanced with logging)
        allowed_fields = ['first_name', 'last_name', 'role']

        # Find the actual stored username (encrypted or unencrypted)
        row = _find_user_row(username)
        if not row:
            return False

        stored_username = row[0]  # Use the actual stored username

        with get_db() as conn:
            c = conn.cursor()
            update_fields = []
            values = []

            # Handle all possible update fields
            for field, value in kwargs.items():
                # FIX: Validate field name against whitelist (SQL injection prevention)
                if field not in allowed_fields:
                    print(f"Security warning: Attempt to update invalid field '{field}' blocked")
                    log_event(f"Invalid field update attempt", "", f"Field: {field}, Table: users", suspicious=True)
                    continue

                update_fields.append(f"{field}=?")
                values.append(value)

            if not update_fields:
                return False

            values.append(stored_username)
            query = f"UPDATE users SET {', '.join(update_fields)} WHERE username=?"

            # FIX: SQL Query Logging for audit trail
            log_event(f"SQL UPDATE executed", "", f"Table: users, Fields: {', '.join([f.split('=')[0] for f in update_fields])}, Username: {username}")

            c.execute(query, values)
            conn.commit()
            return c.rowcount > 0
    except Exception as e:
        print(f"Error updating user: {e}")
        log_event(f"SQL UPDATE failed", "", f"Table: users, Error: {str(e)}", suspicious=True)
        return False

def delete_user(username):
    """Delete user from database"""
    try:
        # Find the actual stored username (encrypted or unencrypted)
        row = _find_user_row(username)
        if not row:
            return False

        stored_username = row[0]  # Use the actual stored username

        with get_db() as conn:
            c = conn.cursor()
            # FIX: SQL Query Logging for audit trail
            log_event(f"SQL DELETE executed", "", f"Table: users, Username: {username}")
            c.execute('DELETE FROM users WHERE username=?', (stored_username,))
            conn.commit()
        return c.rowcount > 0
    except Exception as e:
        print(f"Error deleting user: {e}")
        log_event(f"SQL DELETE failed", "", f"Table: users, Error: {str(e)}", suspicious=True)
        return False

def reset_user_password(username, new_password_hash):
    """Reset user password"""
    try:
        # Find the actual stored username (encrypted or unencrypted)
        row = _find_user_row(username)
        if not row:
            return False
            
        stored_username = row[0]  # Use the actual stored username
        
        with get_db() as conn:
            c = conn.cursor()
            c.execute('UPDATE users SET password_hash=? WHERE username=?', (new_password_hash, stored_username))
            conn.commit()
        return c.rowcount > 0
    except Exception as e:
        print(f"Error resetting password: {e}")
        return False

# ============================================================================
# TRAVELLER MANAGEMENT FUNCTIONS
# ============================================================================

def add_traveller(first_name, last_name, birthday, gender, street_name, house_number,
                 zip_code, city, email_address, mobile_phone, driving_license_number):
    """Add new traveller to database with validation"""
    try:
        # FIX: Whitelisting validation - validate ALL inputs before database operation
        from input_validation import (validate_name, validate_gender, validate_street_name,
                                     validate_house_number, validate_zip_code, validate_city,
                                     validate_email, validate_mobile_phone, validate_driving_license)

        # Validate all inputs
        if not validate_name(first_name):
            print(f"Invalid first name: {first_name}")
            return None

        if not validate_name(last_name):
            print(f"Invalid last name: {last_name}")
            return None

        if not validate_gender(gender):
            print(f"Invalid gender: {gender}")
            return None

        if not validate_street_name(street_name):
            print(f"Invalid street name: {street_name}")
            return None

        if not validate_house_number(house_number):
            print(f"Invalid house number: {house_number}")
            return None

        if not validate_zip_code(zip_code):
            print(f"Invalid zip code: {zip_code}")
            return None

        if not validate_city(city):
            print(f"Invalid city: {city}")
            return None

        if not validate_email(email_address):
            print(f"Invalid email: {email_address}")
            return None

        if not validate_mobile_phone(mobile_phone):
            print(f"Invalid mobile phone: {mobile_phone}")
            return None

        if not validate_driving_license(driving_license_number):
            print(f"Invalid driving license: {driving_license_number}")
            return None

        import uuid
        customer_id = str(uuid.uuid4())[:12]  # Generate unique customer ID

        with get_db() as conn:
            c = conn.cursor()
            # Encrypt sensitive data
            encrypted_email = encrypt_data(email_address)
            encrypted_phone = encrypt_data(mobile_phone)
            encrypted_street = encrypt_data(street_name)
            encrypted_house_number = encrypt_data(house_number)

            c.execute('''INSERT INTO travellers
                        (customer_id, first_name, last_name, birthday, gender, street_name,
                         house_number, zip_code, city, email_address, mobile_phone,
                         driving_license_number, registration_date)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (customer_id, first_name, last_name, birthday, gender, encrypted_street,
                       encrypted_house_number, zip_code, city, encrypted_email, encrypted_phone,
                       driving_license_number, datetime.now().isoformat()))
            conn.commit()
        return customer_id
    except Exception as e:
        print(f"Error adding traveller: {e}")
        return None

def get_traveller_by_id(customer_id):
    """Get a single traveller by customer_id"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM travellers WHERE customer_id=?', (customer_id,))
            row = c.fetchone()
            if row:
                try:
                    return {
                        'customer_id': row[0],
                        'first_name': row[1],
                        'last_name': row[2],
                        'birthday': row[3],
                        'gender': row[4],
                        'street_name': decrypt_data(row[5]),
                        'house_number': decrypt_data(row[6]),
                        'zip_code': row[7],
                        'city': row[8],
                        'email_address': decrypt_data(row[9]),
                        'mobile_phone': decrypt_data(row[10]),
                        'driving_license_number': row[11],
                        'registration_date': row[12]
                    }
                except:
                    # Handle legacy unencrypted data
                    return {
                        'customer_id': row[0],
                        'first_name': row[1],
                        'last_name': row[2],
                        'birthday': row[3],
                        'gender': row[4],
                        'street_name': row[5],
                        'house_number': row[6],
                        'zip_code': row[7],
                        'city': row[8],
                        'email_address': row[9],
                        'mobile_phone': row[10],
                        'driving_license_number': row[11],
                        'registration_date': row[12]
                    }
    except Exception as e:
        print(f"Error getting traveller: {e}")
    return None

def get_all_travellers():
    """Get all travellers from database"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM travellers ORDER BY last_name, first_name')
            rows = c.fetchall()
            travellers = []
            for row in rows:
                try:
                    travellers.append({
                        'customer_id': row[0],
                        'first_name': row[1],
                        'last_name': row[2],
                        'birthday': row[3],
                        'gender': row[4],
                        'street_name': decrypt_data(row[5]),
                        'house_number': decrypt_data(row[6]),
                        'zip_code': row[7],
                        'city': row[8],
                        'email_address': decrypt_data(row[9]),
                        'mobile_phone': decrypt_data(row[10]),
                        'driving_license_number': row[11],
                        'registration_date': row[12]
                    })
                except:
                    # Handle legacy unencrypted data
                    travellers.append({
                        'customer_id': row[0],
                        'first_name': row[1],
                        'last_name': row[2],
                        'birthday': row[3],
                        'gender': row[4],
                        'street_name': row[5],
                        'house_number': row[6],
                        'zip_code': row[7],
                        'city': row[8],
                        'email_address': row[9],
                        'mobile_phone': row[10],
                        'driving_license_number': row[11],
                        'registration_date': row[12]
                    })
            return travellers
    except Exception as e:
        print(f"Error getting all travellers: {e}")
        return []

def search_travellers(search_term):
    """Search travellers by multiple criteria"""
    try:
        travellers = get_all_travellers()
        results = []
        # FIX 9: Use casefold() for case-insensitive comparison without modifying data
        search_folded = search_term.casefold()

        for traveller in travellers:
            # Search in multiple fields
            searchable_text = f"{traveller['first_name']} {traveller['last_name']} {traveller['customer_id']} {traveller['email_address']}".casefold()
            if search_folded in searchable_text:
                results.append(traveller)
        return results
    except Exception as e:
        print(f"Error searching travellers: {e}")
        return []

def update_traveller(customer_id, **kwargs):
    """Update traveller information"""
    try:
        # FIX: SQL Injection Prevention - Explicit field whitelist for defence-in-depth
        allowed_fields = [
            'first_name', 'last_name', 'birthday', 'gender',
            'street_name', 'house_number', 'zip_code', 'city',
            'email_address', 'mobile_phone', 'driving_license_number'
        ]

        with get_db() as conn:
            c = conn.cursor()
            update_fields = []
            values = []

            for field, value in kwargs.items():
                # FIX: Validate field name against whitelist (SQL injection prevention)
                if field not in allowed_fields:
                    print(f"Security warning: Attempt to update invalid field '{field}' blocked")
                    log_event(f"Invalid field update attempt", "", f"Field: {field}, Table: travellers", suspicious=True)
                    continue

                if field in ['street_name', 'house_number', 'email_address', 'mobile_phone']:
                    # Encrypt sensitive fields
                    values.append(encrypt_data(value))
                else:
                    values.append(value)
                update_fields.append(f"{field}=?")

            if not update_fields:
                return False

            values.append(customer_id)
            query = f"UPDATE travellers SET {', '.join(update_fields)} WHERE customer_id=?"

            # FIX: SQL Query Logging for audit trail
            log_event(f"SQL UPDATE executed", "", f"Table: travellers, Fields: {', '.join([f.split('=')[0] for f in update_fields])}, ID: {customer_id}")

            c.execute(query, values)
            conn.commit()

            # Check if any rows were affected
            return c.rowcount > 0
    except Exception as e:
        print(f"Error updating traveller: {e}")
        log_event(f"SQL UPDATE failed", "", f"Table: travellers, Error: {str(e)}", suspicious=True)
        return False

def delete_traveller(customer_id):
    """Delete traveller from database"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            # FIX: SQL Query Logging for audit trail
            log_event(f"SQL DELETE executed", "", f"Table: travellers, ID: {customer_id}")
            c.execute('DELETE FROM travellers WHERE customer_id=?', (customer_id,))
            conn.commit()

            # Check if any rows were affected
            return c.rowcount > 0
    except Exception as e:
        print(f"Error deleting traveller: {e}")
        log_event(f"SQL DELETE failed", "", f"Table: travellers, Error: {str(e)}", suspicious=True)
        return False

# ============================================================================
# SCOOTER MANAGEMENT FUNCTIONS
# ============================================================================

def add_scooter(brand, model, serial_number, top_speed, battery_capacity,
               state_of_charge, target_range_soc, location, last_maintenance_date=None,
               out_of_service_status=0, mileage=0.0):
    """Add a new scooter to the database with validation"""
    try:
        # FIX: Whitelisting validation - validate ALL inputs before database operation
        from input_validation import (validate_brand_model, validate_serial_number,
                                     validate_positive_integer, validate_percentage,
                                     validate_positive_float)

        # Validate brand and model
        if not validate_brand_model(brand):
            print(f"Invalid brand: {brand}")
            return False

        if not validate_brand_model(model):
            print(f"Invalid model: {model}")
            return False

        # Validate serial number
        if not validate_serial_number(serial_number):
            print(f"Invalid serial number: {serial_number}")
            return False

        # Validate numeric fields
        if not validate_positive_integer(str(top_speed)):
            print(f"Invalid top speed: {top_speed}")
            return False

        if not validate_positive_integer(str(battery_capacity)):
            print(f"Invalid battery capacity: {battery_capacity}")
            return False

        if not validate_percentage(str(state_of_charge)):
            print(f"Invalid state of charge: {state_of_charge}")
            return False

        if not validate_positive_float(str(mileage)):
            print(f"Invalid mileage: {mileage}")
            return False

        # Validate out_of_service_status (should be 0 or 1)
        if out_of_service_status not in [0, 1]:
            print(f"Invalid out_of_service_status: {out_of_service_status}")
            return False

        with get_db() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO scooters
                        (serial_number, brand, model, top_speed, battery_capacity,
                         state_of_charge, target_range_soc, location, last_maintenance_date,
                         out_of_service_status, mileage, in_service_date)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (serial_number, brand, model, top_speed, battery_capacity, state_of_charge,
                       target_range_soc, location, last_maintenance_date, out_of_service_status,
                       mileage, datetime.now().isoformat()))
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Serial number already exists
    except Exception as e:
        print(f"Error adding scooter: {e}")
        return False

def get_scooter_by_serial(serial_number):
    """Get a single scooter by serial number"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM scooters WHERE serial_number=?', (serial_number,))
            row = c.fetchone()
            if row:
                return {
                    'serial_number': row[0],
                    'brand': row[1],
                    'model': row[2],
                    'top_speed': row[3],
                    'battery_capacity': row[4],
                    'state_of_charge': row[5],
                    'target_range_soc': row[6],
                    'location': row[7],
                    'out_of_service_status': row[8],
                    'mileage': row[9],
                    'last_maintenance_date': row[10],
                    'in_service_date': row[11]
                }
    except Exception as e:
        print(f"Error getting scooter: {e}")
    return None

def get_all_scooters():
    """Get all scooters from database"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM scooters ORDER BY brand, model, serial_number')
            rows = c.fetchall()
            scooters = []
            for row in rows:
                scooters.append({
                    'serial_number': row[0],
                    'brand': row[1],
                    'model': row[2],
                    'top_speed': row[3],
                    'battery_capacity': row[4],
                    'state_of_charge': row[5],
                    'target_range_soc': row[6],
                    'location': row[7],
                    'out_of_service_status': row[8],
                    'mileage': row[9],
                    'last_maintenance_date': row[10],
                    'in_service_date': row[11]
                })
            return scooters
    except Exception as e:
        print(f"Error getting all scooters: {e}")
        return []

def search_scooters(search_term):
    """Search scooters by multiple criteria"""
    try:
        scooters = get_all_scooters()
        results = []
        # FIX 9: Use casefold() for case-insensitive comparison without modifying data
        search_folded = search_term.casefold()

        for scooter in scooters:
            searchable_text = f"{scooter['brand']} {scooter['model']} {scooter['serial_number']}".casefold()
            if search_folded in searchable_text:
                results.append(scooter)
        return results
    except Exception as e:
        print(f"Error searching scooters: {e}")
        return []

def update_scooter(serial_number, user_role, **kwargs):
    """Update scooter information based on user role permissions"""
    # Define which fields each role can update
    # FIX: Added target_range_soc to service_engineer_fields (per requirements Table 3)
    service_engineer_fields = ['state_of_charge', 'target_range_soc', 'location', 'out_of_service_status', 'mileage', 'last_maintenance_date']
    admin_fields = service_engineer_fields + ['brand', 'model', 'top_speed', 'battery_capacity']

    # FIX: SQL Injection Prevention - Complete field whitelist for all possible scooter fields
    all_allowed_fields = ['brand', 'model', 'top_speed', 'battery_capacity', 'state_of_charge',
                          'target_range_soc', 'location', 'out_of_service_status', 'mileage', 'last_maintenance_date']

    try:
        with get_db() as conn:
            c = conn.cursor()
            update_fields = []
            values = []

            for field, value in kwargs.items():
                # FIX: First check if field is valid at all (SQL injection prevention)
                if field not in all_allowed_fields:
                    print(f"Security warning: Attempt to update invalid field '{field}' blocked")
                    log_event(f"Invalid field update attempt", "", f"Field: {field}, Table: scooters, Role: {user_role}", suspicious=True)
                    continue

                # Check role permissions
                if user_role == 'service_engineer' and field not in service_engineer_fields:
                    log_event(f"Permission denied", "", f"Field: {field}, Table: scooters, Role: {user_role}")
                    continue
                elif user_role in ['system_admin', 'super_admin'] and field not in admin_fields:
                    log_event(f"Permission denied", "", f"Field: {field}, Table: scooters, Role: {user_role}")
                    continue

                values.append(value)
                update_fields.append(f"{field}=?")

            if not update_fields:
                return False

            values.append(serial_number)
            query = f"UPDATE scooters SET {', '.join(update_fields)} WHERE serial_number=?"

            # FIX: SQL Query Logging for audit trail
            log_event(f"SQL UPDATE executed", "", f"Table: scooters, Fields: {', '.join([f.split('=')[0] for f in update_fields])}, Serial: {serial_number}, Role: {user_role}")

            c.execute(query, values)
            conn.commit()

            # Check if any rows were affected
            return c.rowcount > 0
    except Exception as e:
        print(f"Error updating scooter: {e}")
        log_event(f"SQL UPDATE failed", "", f"Table: scooters, Error: {str(e)}", suspicious=True)
        return False

def delete_scooter(serial_number):
    """Delete scooter from database"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            # FIX: SQL Query Logging for audit trail
            log_event(f"SQL DELETE executed", "", f"Table: scooters, Serial: {serial_number}")
            c.execute('DELETE FROM scooters WHERE serial_number=?', (serial_number,))
            conn.commit()

            # Check if any rows were affected
            return c.rowcount > 0
    except Exception as e:
        print(f"Error deleting scooter: {e}")
        log_event(f"SQL DELETE failed", "", f"Table: scooters, Error: {str(e)}", suspicious=True)
        return False

# ============================================================================
# RESTORE CODE MANAGEMENT
# ============================================================================

def add_restore_code(code, system_admin_username, backup_name):
    """Add restore code to database"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO restore_codes (code, system_admin_username, backup_name, created_date) 
                        VALUES (?, ?, ?, ?)''',
                      (code, system_admin_username, backup_name, datetime.now().isoformat()))
            conn.commit()
        return True
    except Exception as e:
        print(f"Error adding restore code: {e}")
        return False

def get_restore_code(code):
    """Get restore code information"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM restore_codes WHERE code=? AND used=0', (code,))
            row = c.fetchone()
            if row:
                return {
                    'code': row[0],
                    'system_admin_username': row[1],
                    'backup_name': row[2],
                    'created_date': row[3],
                    'used': row[4]
                }
    except Exception as e:
        print(f"Error getting restore code: {e}")
    return None

def use_restore_code(code):
    """Mark restore code as used"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('UPDATE restore_codes SET used=1 WHERE code=?', (code,))
            conn.commit()
        return c.rowcount > 0
    except Exception as e:
        print(f"Error using restore code: {e}")
        return False

def revoke_restore_code(code):
    """Delete restore code from database"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('DELETE FROM restore_codes WHERE code=?', (code,))
            conn.commit()
        return c.rowcount > 0
    except Exception as e:
        print(f"Error revoking restore code: {e}")
        return False

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

def log_event(description, username="", additional_info="", suspicious=False):
    """Log an event to the database"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            encrypted_description = encrypt_data(description)
            encrypted_additional = encrypt_data(additional_info) if additional_info else ""
            c.execute('''INSERT INTO logs (timestamp, username, description, additional_info, suspicious) 
                        VALUES (?, ?, ?, ?, ?)''',
                      (datetime.now().isoformat(), username, encrypted_description, 
                       encrypted_additional, 1 if suspicious else 0))
            conn.commit()
    except Exception as e:
        print(f"Error logging event: {e}")

def get_logs():
    """Get all logs from database"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM logs ORDER BY timestamp DESC')
            rows = c.fetchall()
            logs = []
            for row in rows:
                try:
                    logs.append({
                        'id': row[0],
                        'timestamp': row[1],
                        'username': row[2],
                        'description': decrypt_data(row[3]),
                        'additional_info': decrypt_data(row[4]) if row[4] else "",
                        'suspicious': bool(row[5])
                    })
                except:
                    # Handle legacy unencrypted logs
                    logs.append({
                        'id': row[0],
                        'timestamp': row[1],
                        'username': row[2],
                        'description': row[3],
                        'additional_info': row[4] if row[4] else "",
                        'suspicious': bool(row[5])
                    })
            return logs
    except Exception as e:
        print(f"Error getting logs: {e}")
        return []

def get_suspicious_logs():
    """Get only suspicious logs"""
    try:
        logs = get_logs()
        return [log for log in logs if log['suspicious']]
    except Exception as e:
        print(f"Error getting suspicious logs: {e}")
        return []

def get_logs_summary():
    """Get summary statistics of logs"""
    try:
        logs = get_logs()
        total_logs = len(logs)
        suspicious_count = len([log for log in logs if log['suspicious']])
        
        # Get last 24 hours activity
        from datetime import datetime, timedelta
        yesterday = datetime.now() - timedelta(days=1)
        recent_logs = [log for log in logs if datetime.fromisoformat(log['timestamp']) > yesterday]
        
        return {
            'total_logs': total_logs,
            'suspicious_count': suspicious_count,
            'recent_logs': len(recent_logs),
            'last_activity': logs[0]['timestamp'] if logs else None
        }
    except Exception as e:
        print(f"Error getting logs summary: {e}")
        return {
            'total_logs': 0,
            'suspicious_count': 0,
            'recent_logs': 0,
            'last_activity': None
        }

# ============================================================================
# DATABASE UTILITIES
# ============================================================================

def get_database_stats():
    """Get database statistics"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            
            # Count records in each table
            c.execute('SELECT COUNT(*) FROM users')
            user_count = c.fetchone()[0]
            
            c.execute('SELECT COUNT(*) FROM travellers')
            traveller_count = c.fetchone()[0]
            
            c.execute('SELECT COUNT(*) FROM scooters')
            scooter_count = c.fetchone()[0]
            
            c.execute('SELECT COUNT(*) FROM logs')
            log_count = c.fetchone()[0]
            
            c.execute('SELECT COUNT(*) FROM restore_codes WHERE used=0')
            active_codes = c.fetchone()[0]
            
            return {
                'users': user_count,
                'travellers': traveller_count,
                'scooters': scooter_count,
                'logs': log_count,
                'active_restore_codes': active_codes
            }
    except Exception as e:
        print(f"Error getting database stats: {e}")
        return {
            'users': 0,
            'travellers': 0,
            'scooters': 0,
            'logs': 0,
            'active_restore_codes': 0
        }

def cleanup_old_logs(days_to_keep=90):
    """Clean up old log entries (older than specified days)"""
    try:
        from datetime import datetime, timedelta
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        cutoff_iso = cutoff_date.isoformat()
        
        with get_db() as conn:
            c = conn.cursor()
            c.execute('DELETE FROM logs WHERE timestamp < ? AND suspicious = 0', (cutoff_iso,))
            deleted_count = c.rowcount
            conn.commit()
            
        return deleted_count
    except Exception as e:
        print(f"Error cleaning up logs: {e}")
        return 0

def backup_database(backup_path):
    """Create a backup copy of the database"""
    try:
        import shutil
        shutil.copy2(DB_PATH, backup_path)
        return True
    except Exception as e:
        print(f"Error backing up database: {e}")
        return False

def verify_database_integrity():
    """Verify database integrity"""
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('PRAGMA integrity_check')
            result = c.fetchone()
            return result[0] == 'ok'
    except Exception as e:
        print(f"Error verifying database integrity: {e}")
        return False