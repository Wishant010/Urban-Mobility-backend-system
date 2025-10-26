import sys
import os
import getpass  # FIX: Added for password masking
from datetime import datetime

# Import all modules
from auth import (login, register_user, reset_password, change_own_password,
                 validate_role_action, has_permission)
from db import (init_db, get_all_users, update_user, delete_user, log_event,
               add_traveller, get_all_travellers, search_travellers, update_traveller, delete_traveller,
               add_scooter, get_all_scooters, search_scooters, update_scooter, delete_scooter,
               get_logs, get_suspicious_logs, add_restore_code, get_restore_code,
               use_restore_code, revoke_restore_code)
from backup import create_backup, restore_backup, list_backups, get_backup_statistics
from input_validation import *
import uuid
import secrets

def get_terminal_width():
    """Get current terminal width"""
    try:
        import shutil
        return shutil.get_terminal_size().columns
    except:
        return 80  # Default fallback

def adjust_table_widths_for_terminal(base_widths: list) -> list:
    """Adjust table widths based on terminal size"""
    terminal_width = get_terminal_width()
    
    # Calculate total table width needed
    total_width = sum(base_widths) + len(base_widths) * 3 + 1  # +3 for " | ", +1 for final |
    
    # If table is too wide for terminal, reduce widths proportionally
    if total_width > terminal_width - 5:  # Leave some margin
        reduction_factor = (terminal_width - 5 - len(base_widths) * 3 - 1) / sum(base_widths)
        adjusted_widths = [max(3, int(width * reduction_factor)) for width in base_widths]
        return adjusted_widths
    
    return base_widths

def clear_screen():
    """Clear terminal screen properly"""
    import os
    import sys
    
    # Force flush any pending output
    sys.stdout.flush()
    sys.stderr.flush()
    
    # Clear screen using appropriate command
    if os.name == 'nt':  # Windows
        os.system('cls')
    else:  # Unix/Linux/Mac
        os.system('clear')
    
    # Additional method to ensure clean screen
    print('\033[2J\033[H', end='', flush=True)
    
    # Small delay to ensure screen is cleared
    import time
    time.sleep(0.01)

def pause():
    """Wait for user input and clear any lingering output"""
    try:
        input("\nDruk Enter om door te gaan...")
    except KeyboardInterrupt:
        pass  # Handle Ctrl+C gracefully
    
    # Extra clear to prevent double output
    import sys
    sys.stdout.flush()
    sys.stderr.flush()

def show_header(title: str, show_back_info: bool = True):
    """Show formatted header"""
    print("=" * 80)
    print(f"  {title}")
    print("=" * 80)
    if show_back_info:
        print("💡 Tip: Typ 'terug' om terug te gaan naar het vorige menu")
        print("-" * 80)

def show_table_header(headers: list, widths: list):
    """Show formatted table header with vertical lines"""
    header_line = "| "
    separator_line = "+"
    
    for i, (header, width) in enumerate(zip(headers, widths)):
        # Use the specified width consistently
        header_line += f"{header:<{width}} | "
        separator_line += "-" * (width + 2) + "+"
    
    print(separator_line)
    print(header_line)
    print(separator_line)

def format_table_row(values: list, widths: list) -> str:
    """Format a table row with proper spacing and vertical lines"""
    row = "| "
    for i, (value, width) in enumerate(zip(values, widths)):
        str_value = str(value) if value is not None else "..."
        # Truncate if too long, otherwise pad to width
        if len(str_value) > width:
            str_value = str_value[:width-2] + ".."
        row += f"{str_value:<{width}} | "
    return row

def show_table_footer(widths: list):
    """Show table footer line"""
    footer_line = "+"
    for width in widths:
        footer_line += "-" * (width + 2) + "+"
    print(footer_line)

def show_suspicious_alerts(username: str, role: str):
    """Show alerts for suspicious activities"""
    if role in ['super_admin', 'system_admin']:
        try:
            suspicious = get_suspicious_logs()
            if suspicious:
                print(f"\n⚠️  WAARSCHUWING: {len(suspicious)} verdachte activiteiten gedetecteerd!")
                print("   Bekijk de logs voor meer details.")
        except:
            pass  # Skip if logs not available

def get_role_menu(role: str) -> list:
    """Get menu options for user role"""
    menus = {
        'super_admin': [
            ("Gebruikersbeheer", "user_management"),
            ("Reiziger beheer", "traveller_management"), 
            ("Scooter beheer", "scooter_management"),
            ("Systeem logs bekijken", "view_logs"),
            ("Backup beheer", "backup_management"),
            ("Restore-code beheer", "restore_code_management"),
            ("Wachtwoord wijzigen", "change_password"),
            ("Systeem statistieken", "show_statistics"),
            ("Uitloggen", "logout")
        ],
        'system_admin': [
            ("Gebruikersbeheer", "user_management"),
            ("Reiziger beheer", "traveller_management"),
            ("Scooter beheer", "scooter_management"), 
            ("Systeem logs bekijken", "view_logs"),
            ("Backup beheer", "backup_management"),
            ("Wachtwoord wijzigen", "change_password"),
            ("Systeem statistieken", "show_statistics"),
            ("Uitloggen", "logout")
        ],
        'service_engineer': [
            ("Scooter informatie zoeken", "search_scooters"),
            ("Scooter informatie bijwerken", "update_scooter_info"),
            ("Wachtwoord wijzigen", "change_password"),
            ("Uitloggen", "logout")
        ]
    }
    return menus.get(role, [])

def show_main_menu(username: str, role: str):
    """Display main menu and get user choice"""
    clear_screen()
    show_header(f"Urban Mobility Backend - Welkom {username} ({role})", False)
    
    # Show suspicious activity alerts
    show_suspicious_alerts(username, role)
    
    menu_items = get_role_menu(role)
    print("\nBeschikbare opties:")
    for i, (desc, _) in enumerate(menu_items, 1):
        print(f"  {i}. {desc}")
    
    print(f"  {len(menu_items) + 1}. Afsluiten")
    
    while True:
        try:
            choice = input(f"\nKies een optie (1-{len(menu_items) + 1}): ")
            
            if check_back_command(choice):
                return "logout"
            
            choice_num = int(choice)
            if 1 <= choice_num <= len(menu_items):
                return menu_items[choice_num - 1][1]
            elif choice_num == len(menu_items) + 1:
                return "exit"
            else:
                print(f"Ongeldige keuze, kies tussen 1 en {len(menu_items) + 1}.")
        except ValueError:
            print("Voer een geldig nummer in.")

# ============================================================================
# USER MANAGEMENT FUNCTIONS
# ============================================================================

def user_management_menu(username: str, role: str):
    """User management submenu"""
    while True:
        clear_screen()
        show_header("Gebruikersbeheer")
        
        print("1. Alle gebruikers bekijken")
        print("2. Nieuwe gebruiker aanmaken")
        print("3. Gebruiker bijwerken") 
        print("4. Gebruiker verwijderen")
        print("5. Wachtwoord resetten")
        print("6. Terug naar hoofdmenu")
        
        choice = input("\nKies een optie (1-6): ")
        
        if check_back_command(choice) or choice == "6":
            break
        elif choice == "1":
            view_all_users()
        elif choice == "2":
            create_new_user(username, role)
        elif choice == "3":
            update_existing_user(username, role)
        elif choice == "4":
            result = delete_existing_user(username, role)
            if result == "force_logout":
                return "force_logout"  # Propagate logout signal
        elif choice == "5":
            reset_user_password_interactive(username, role)
        else:
            print("Ongeldige keuze.")
            pause()

def view_all_users():
    """Display all users in formatted table"""
    clear_screen()
    show_header("Alle Gebruikers")
    
    try:
        users = get_all_users()
        if not users:
            print("Geen gebruikers gevonden.")
        else:
            # Define column widths and adjust for terminal
            base_widths = [15, 20, 25, 15]
            widths = adjust_table_widths_for_terminal(base_widths)
            headers = ['Gebruikersnaam', 'Rol', 'Naam', 'Registratie']
            
            show_table_header(headers, widths)
            
            for user in users:
                name = f"{user['first_name']} {user['last_name']}"
                values = [
                    user['username'], 
                    user['role'], 
                    name, 
                    user['registration_date']
                ]
                print(format_table_row(values, widths))
            
            show_table_footer(widths)
            print(f"\nTotaal: {len(users)} gebruikers")
    except Exception as e:
        print(f"❌ Fout bij ophalen gebruikers: {e}")
    
    pause()

def create_new_user(current_username: str, current_role: str):
    """Create new user with validation and back option"""
    clear_screen()
    show_header("Nieuwe Gebruiker Aanmaken")
    
    try:
        # Get user details with back option and username uniqueness check
        while True:
            username = get_validated_input_with_back("Gebruikersnaam (8-10 tekens)", validate_username, "username")
            if username is None:
                return

            # FIX: Check if username already exists (case-insensitive without modifying input)
            existing_users = get_all_users()
            username_exists = any(u['username'].casefold() == username.casefold() for u in existing_users)

            if username_exists:
                print(f"❌ Gebruikersnaam '{username}' bestaat al. Kies een andere gebruikersnaam.")
                continue
            else:
                print(f"✅ Gebruikersnaam '{username}' is beschikbaar.")
                break

        # FIX: Use getpass for password masking with max attempts
        max_attempts = 3
        password = None
        for attempt in range(1, max_attempts + 1):
            print(f"\nWachtwoord invoeren (poging {attempt}/{max_attempts})")
            temp_password = getpass.getpass("Wachtwoord (12-30 tekens, complex): ")

            if check_back_command(temp_password):
                return

            if validate_password(temp_password):
                password = temp_password
                break
            else:
                print("❌ Wachtwoord voldoet niet aan eisen (12-30 tekens met uppercase, lowercase, cijfer, speciaal teken)")
                if attempt < max_attempts:
                    print(f"Probeer opnieuw. Nog {max_attempts - attempt} poging(en).")
                else:
                    print("❌ Maximum aantal pogingen bereikt.")
                    pause()
                    return
        
        # Role selection based on permissions
        available_roles = []
        if current_role == 'super_admin':
            available_roles = ['super_admin', 'system_admin', 'service_engineer']
        elif current_role == 'system_admin':
            available_roles = ['service_engineer']
        
        if not available_roles:
            print("❌ Je hebt geen rechten om gebruikers aan te maken.")
            pause()
            return
        
        print(f"\nBeschikbare rollen: {', '.join(available_roles)}")
        while True:
            role = input("Rol: ").strip()
            if check_back_command(role):
                return
            if role in available_roles:
                break
            print(f"❌ Ongeldige rol. Kies uit: {', '.join(available_roles)}")
        
        first_name = get_validated_input_with_back("Voornaam", validate_name, "name")
        if first_name is None:
            return
        
        last_name = get_validated_input_with_back("Achternaam", validate_name, "name")
        if last_name is None:
            return
        
        # Final validation before creating user
        if not all([username, password, role, first_name, last_name]):
            print("❌ Niet alle verplichte velden zijn ingevuld. Gebruiker wordt niet aangemaakt.")
            pause()
            return
        
        # Create user
        success, message = register_user(username, password, role, first_name, last_name, current_role)
        if success:
            print(f"\n✅ {message}")
        else:
            print(f"\n❌ {message}")
    except Exception as e:
        print(f"❌ Fout bij aanmaken gebruiker: {e}")
    
    pause()

def update_existing_user(current_username: str, current_role: str):
    """Update existing user - all fields editable"""
    clear_screen()
    show_header("Gebruiker Bijwerken")
    
    username = input("Gebruikersnaam om bij te werken: ").strip()
    
    if check_back_command(username):
        return
    
    if not username:
        print("❌ Gebruikersnaam is verplicht")
        pause()
        return
    
    try:
        # Get current user info
        users = get_all_users()
        user_to_update = None
        
        for u in users:
            # FIX 9: Use casefold() for case-insensitive comparison
            if u['username'].casefold() == username.casefold():
                user_to_update = u
                break
        
        if not user_to_update:
            print(f"❌ Gebruiker {username} niet gevonden")
            pause()
            return
        
        print(f"\nHuidige gegevens:")
        print(f"👤 Naam: {user_to_update['first_name']} {user_to_update['last_name']}")
        print(f"🎭 Rol: {user_to_update['role']}")
        print(f"📧 Username: {user_to_update['username']}")
        print(f"📅 Geregistreerd: {user_to_update['registration_date']}")
        
        print("\nVoer nieuwe waarden in (laat leeg om ongewijzigd te laten):")
        
        updates = {}
        
        # First name validation
        while True:
            new_first_name = input(f"Voornaam ({user_to_update['first_name']}): ").strip()
            if check_back_command(new_first_name):
                return
            
            if not new_first_name:
                break
            elif validate_name(new_first_name):
                updates['first_name'] = new_first_name
                break
            else:
                print("❌ Ongeldige voornaam. Alleen letters, spaties, apostroffen en koppeltekens toegestaan.")
        
        # Last name validation
        while True:
            new_last_name = input(f"Achternaam ({user_to_update['last_name']}): ").strip()
            if check_back_command(new_last_name):
                return
            
            if not new_last_name:
                break
            elif validate_name(new_last_name):
                updates['last_name'] = new_last_name
                break
            else:
                print("❌ Ongeldige achternaam. Alleen letters, spaties, apostroffen en koppeltekens toegestaan.")
        
        # Role validation (only if super admin)
        if current_role == 'super_admin':
            available_roles = ['super_admin', 'system_admin', 'service_engineer']
            while True:
                new_role = input(f"Rol ({user_to_update['role']}) - opties: {', '.join(available_roles)}: ").strip()
                if check_back_command(new_role):
                    return
                
                if not new_role:
                    break
                elif new_role in available_roles:
                    updates['role'] = new_role
                    break
                else:
                    print(f"❌ Ongeldige rol. Kies uit: {', '.join(available_roles)}")
        
        if not updates:
            print("Geen wijzigingen opgegeven")
            pause()
            return
        
        # Apply updates
        success = update_user(username, **updates)
        
        if success:
            print("✅ Gebruiker succesvol bijgewerkt")
            log_event(f"Gebruiker bijgewerkt", current_username, f"Gebruiker: {username}, Velden: {list(updates.keys())}")
        else:
            print("❌ Fout bij bijwerken gebruiker")
    except Exception as e:
        print(f"❌ Fout bij bijwerken gebruiker: {e}")
    
    pause()

def delete_existing_user(current_username: str, current_role: str):
    """Delete existing user"""
    clear_screen()
    show_header("Gebruiker Verwijderen")
    
    username = input("Gebruikersnaam om te verwijderen: ").strip()
    
    if check_back_command(username):
        return
    
    if not username:
        print("❌ Gebruikersnaam is verplicht")
        pause()
        return
    
    # Check if user wants to delete themselves
    # FIX 9: Use casefold() for case-insensitive comparison
    is_self_deletion = username.casefold() == current_username.casefold()
    
    # Super admin cannot delete themselves, but system admin can
    if is_self_deletion and current_role == 'super_admin':
        print("❌ Super Administrator kan zichzelf niet verwijderen")
        pause()
        return
    
    try:
        # Get user info
        users = get_all_users()
        user_to_delete = None
        
        for u in users:
            # FIX 9: Use casefold() for case-insensitive comparison
            if u['username'].casefold() == username.casefold():
                user_to_delete = u
                break
        
        if not user_to_delete:
            print(f"❌ Gebruiker {username} niet gevonden")
            pause()
            return
        
        # Show user details
        name = f"{user_to_delete['first_name']} {user_to_delete['last_name']}"
        print(f"\nGebruiker gegevens:")
        print(f"👤 Naam: {name}")
        print(f"🎭 Rol: {user_to_delete['role']}")
        print(f"📧 Username: {username}")
        
        # Extra confirmation for self-deletion
        if is_self_deletion:
            print("\n⚠️  WAARSCHUWING: Je staat op het punt je eigen account te verwijderen!")
            print("   Dit betekent dat je direct wordt uitgelogd en geen toegang meer hebt tot het systeem.")
            
            # First confirmation with retry loop
            while True:
                confirm1 = input("\n⚠️  Weet je ZEKER dat je je eigen account wilt verwijderen? (typ 'ja zeker' of 'nee'): ").strip()
                if confirm1.strip().casefold() == 'JA ZEKER':
                    break  # Continue to next confirmation
                elif confirm1.strip().casefold() == 'NEE' or confirm1.strip().casefold() == 'N':
                    print("Verwijdering geannuleerd")
                    pause()
                    return
                else:
                    print("❌ Ongeldige input. Typ 'ja zeker' om door te gaan of 'nee' om te annuleren.")
                    continue
            
            # Second confirmation with retry loop
            while True:
                confirm2 = input(f"\n⚠️  Laatste bevestiging: Typ je gebruikersnaam '{username}' om te bevestigen (of 'nee' om te annuleren): ").strip()
                if confirm2 == username:
                    break  # Continue to deletion
                elif confirm2.strip().casefold() == 'NEE' or confirm2.strip().casefold() == 'N':
                    print("Verwijdering geannuleerd")
                    pause()
                    return
                else:
                    print(f"❌ Ongeldige input. Typ exact '{username}' om te bevestigen of 'nee' om te annuleren.")
                    continue
        else:
            # Regular confirmation for other users
            confirm = input(f"\n⚠️  Weet je zeker dat je gebruiker {name} ({username}) wilt verwijderen? (ja/nee): ").strip().casefold()
            
            if confirm not in ['ja', 'j', 'yes', 'y']:
                print("Verwijdering geannuleerd")
                pause()
                return
        
        # Delete user
        success = delete_user(username)
        
        if success:
            print("✅ Gebruiker succesvol verwijderd")
            log_event(f"Gebruiker verwijderd", current_username, f"Verwijderde gebruiker: {username}")
            
            # If user deleted themselves, force logout
            if is_self_deletion:
                print("\n🔓 Je bent automatisch uitgelogd omdat je je eigen account hebt verwijderd.")
                print("👋 Tot ziens!")
                pause()
                return "force_logout"  # Return special value to trigger logout
        else:
            print("❌ Fout bij verwijderen gebruiker")
    except Exception as e:
        print(f"❌ Fout bij verwijderen gebruiker: {e}")
    
    pause()

def reset_user_password_interactive(current_username: str, current_role: str):
    """Reset user password interactively"""
    clear_screen()
    show_header("Wachtwoord Resetten")
    
    username = input("Gebruikersnaam voor wachtwoord reset: ").strip()
    
    if check_back_command(username):
        return
    
    if not username:
        print("❌ Gebruikersnaam is verplicht")
        pause()
        return
    
    try:
        success, result = reset_password(username, current_role)
        
        if success:
            print(f"✅ Wachtwoord succesvol gereset voor {username}")
            print(f"🔑 Tijdelijk wachtwoord: {result}")
            print("⚠️  Gebruiker moet dit wachtwoord bij eerste login wijzigen")
        else:
            print(f"❌ Fout bij resetten wachtwoord: {result}")
    except Exception as e:
        print(f"❌ Fout bij resetten wachtwoord: {e}")
    
    pause()

# ============================================================================
# TRAVELLER MANAGEMENT FUNCTIONS
# ============================================================================

def traveller_management_menu(username: str, role: str):
    """Traveller management submenu"""
    while True:
        clear_screen()
        show_header("Reiziger Beheer")
        
        print("1. Alle reizigers bekijken")
        print("2. Reiziger zoeken")
        print("3. Nieuwe reiziger toevoegen")
        print("4. Reiziger bijwerken")
        print("5. Reiziger verwijderen") 
        print("6. Terug naar hoofdmenu")
        
        choice = input("\nKies een optie (1-6): ")
        
        if check_back_command(choice) or choice == "6":
            break
        elif choice == "1":
            view_all_travellers_menu()
        elif choice == "2":
            search_travellers_menu()
        elif choice == "3":
            create_traveller_menu(username)
        elif choice == "4":
            update_traveller_menu(username)
        elif choice == "5":
            delete_traveller_menu(username)
        else:
            print("Ongeldige keuze.")
            pause()

def view_all_travellers_menu():
    """Display all travellers in formatted table"""
    clear_screen()
    show_header("Alle Reizigers")
    
    try:
        travellers = get_all_travellers()
        if not travellers:
            print("Geen reizigers gevonden.")
        else:
            # Define column widths and adjust for terminal
            base_widths = [12, 25, 30, 15, 12]
            widths = adjust_table_widths_for_terminal(base_widths)
            headers = ['Customer ID', 'Naam', 'Email', 'Telefoon', 'Stad']
            
            show_table_header(headers, widths)
            
            for t in travellers:
                name = f"{t['first_name']} {t['last_name']}"
                phone = f"+31-6-{t['mobile_phone']}"
                values = [t['customer_id'], name, t['email_address'], phone, t['city']]
                print(format_table_row(values, widths))
            
            show_table_footer(widths)
            print(f"\nTotaal: {len(travellers)} reizigers")
    except Exception as e:
        print(f"❌ Fout bij ophalen reizigers: {e}")
    
    pause()

def search_travellers_menu():
    """Search travellers"""
    clear_screen()
    show_header("Reiziger Zoeken")
    
    try:
        search_term = get_validated_input_with_back("Zoekterm (naam, email, customer ID)", validate_search_term, "search_term")
        if search_term is None:
            return
        
        results = search_travellers(search_term)
        
        if not results:
            print(f"Geen reizigers gevonden voor '{search_term}'.")
        else:
            print(f"\n{len(results)} resultaten gevonden voor '{search_term}':")
            
            base_widths = [12, 25, 30, 15]
            widths = adjust_table_widths_for_terminal(base_widths)
            headers = ['Customer ID', 'Naam', 'Email', 'Telefoon']
            
            show_table_header(headers, widths)
            
            for t in results:
                name = f"{t['first_name']} {t['last_name']}"
                phone = f"+31-6-{t['mobile_phone']}"
                values = [t['customer_id'], name, t['email_address'], phone]
                print(format_table_row(values, widths))
            
            show_table_footer(widths)
    except Exception as e:
        print(f"❌ Fout bij zoeken reizigers: {e}")
    
    pause()

def create_traveller_menu(username: str):
    """Add new traveller with Dutch date format"""
    clear_screen()
    show_header("Nieuwe Reiziger Toevoegen")
    
    try:
        # Collect all required information with back option
        first_name = get_validated_input_with_back("Voornaam", validate_name, "name")
        if first_name is None: return
        
        last_name = get_validated_input_with_back("Achternaam", validate_name, "name")
        if last_name is None: return
        
        birthday = get_validated_input_with_back("Geboortedatum (bijv. 15-03-1990, 15/03/90)", validate_flexible_date, "flexible_date")
        if birthday is None: return
        # Convert to ISO for storage
        birthday = convert_flexible_date_to_iso(birthday)
        
        # Gender validation with options
        print("\nGeslacht opties: male, female")
        gender = get_validated_input_with_back("Geslacht (male of female)", validate_gender, "gender")
        if gender is None: return
        # FIX 9: No input modification - store exactly as entered
        
        street_name = get_validated_input_with_back("Straatnaam", validate_street_name, "name")
        if street_name is None: return
        
        house_number = get_validated_input_with_back("Huisnummer", validate_house_number, "house_number")
        if house_number is None: return
        
        zip_code = get_validated_input_with_back("Postcode (1234AB - uppercase letters)", validate_zip_code, "zip_code")
        if zip_code is None: return
        # FIX 9: No input modification - validation requires uppercase
        
        # Show available cities
        cities = get_valid_cities()
        print(f"\nBeschikbare steden: {', '.join(cities)}")
        city = get_validated_input_with_back("Stad", validate_city, "city")
        if city is None: return
        
        email = get_validated_input_with_back("Email adres", validate_email, "email")
        if email is None: return
        
        mobile_phone = get_validated_input_with_back("Mobiel (8 cijfers, +31-6- wordt toegevoegd)", validate_mobile_phone, "mobile_phone")
        if mobile_phone is None: return
        
        license_number = get_validated_input_with_back("Rijbewijsnummer (XXDDDDDDD of XDDDDDDDD - uppercase letters)", validate_driving_license, "driving_license")
        if license_number is None: return
        # FIX 9: No input modification - validation requires uppercase
        
        # Final validation before adding traveller
        if not all([first_name, last_name, birthday, gender, street_name, house_number, zip_code, city, email, mobile_phone, license_number]):
            print("❌ Niet alle verplichte velden zijn ingevuld. Reiziger wordt niet toegevoegd.")
            pause()
            return
        
        # Add traveller
        customer_id = add_traveller(first_name, last_name, birthday, gender, street_name, 
                                   house_number, zip_code, city, email, mobile_phone, license_number)
        
        if customer_id:
            print(f"\n✅ Reiziger succesvol toegevoegd!")
            print(f"📋 Customer ID: {customer_id}")
            print(f"👤 Naam: {first_name} {last_name}")
            print(f"📧 Email: {email}")
            log_event(f"Nieuwe reiziger toegevoegd", username, f"Customer ID: {customer_id}, Naam: {first_name} {last_name}")
        else:
            print("\n❌ Fout bij toevoegen reiziger.")
    except Exception as e:
        print(f"❌ Fout bij toevoegen reiziger: {e}")
    
    pause()

def update_traveller_menu(username: str):
    """Update traveller - all fields editable"""
    clear_screen()
    show_header("Reiziger Bijwerken")
    
    customer_id = input("Customer ID van reiziger om bij te werken: ").strip()
    
    if check_back_command(customer_id):
        return
    
    if not customer_id:
        print("❌ Customer ID is verplicht")
        pause()
        return
    
    try:
        # Get current traveller info
        travellers = get_all_travellers()
        current_traveller = None
        
        for t in travellers:
            if t['customer_id'] == customer_id:
                current_traveller = t
                break
        
        if not current_traveller:
            print(f"❌ Reiziger met ID {customer_id} niet gevonden")
            pause()
            return
        
        print(f"\nHuidige gegevens van {current_traveller['first_name']} {current_traveller['last_name']}:")
        print(f"👤 Naam: {current_traveller['first_name']} {current_traveller['last_name']}")
        print(f"🎂 Geboortedatum: {current_traveller['birthday']}")
        print(f"⚧️ Geslacht: {current_traveller['gender']}")
        print(f"🏠 Adres: {current_traveller['street_name']} {current_traveller['house_number']}, {current_traveller['zip_code']} {current_traveller['city']}")
        print(f"📧 Email: {current_traveller['email_address']}")
        print(f"📱 Telefoon: +31-6-{current_traveller['mobile_phone']}")
        print(f"🪪 Rijbewijs: {current_traveller['driving_license_number']}")
        
        # Collect updates
        updates = {}
        
        print("\nVoer nieuwe waarden in (laat leeg om ongewijzigd te laten):")
        
        # First name validation
        while True:
            new_first_name = input(f"Voornaam ({current_traveller['first_name']}): ").strip()
            if check_back_command(new_first_name):
                return
            
            if not new_first_name:
                break
            elif validate_name(new_first_name):
                updates['first_name'] = new_first_name
                break
            else:
                print("❌ Ongeldige voornaam. Alleen letters, spaties, apostroffen en koppeltekens toegestaan.")
        
        # Last name validation
        while True:
            new_last_name = input(f"Achternaam ({current_traveller['last_name']}): ").strip()
            if check_back_command(new_last_name):
                return
            
            if not new_last_name:
                break
            elif validate_name(new_last_name):
                updates['last_name'] = new_last_name
                break
            else:
                print("❌ Ongeldige achternaam. Alleen letters, spaties, apostroffen en koppeltekens toegestaan.")
        
        # Birthday validation
        while True:
            new_birthday = input(f"Geboortedatum ({current_traveller['birthday']}) (bijv. 15-03-1990): ").strip()
            if check_back_command(new_birthday):
                return
            
            if not new_birthday:
                break
            elif validate_flexible_date(new_birthday):
                updates['birthday'] = convert_flexible_date_to_iso(new_birthday)
                break
            else:
                print("❌ Ongeldige datum. Gebruik formaat dd-mm-jjjj of dd/mm/jj.")
        
        # Gender validation
        while True:
            new_gender = input(f"Geslacht ({current_traveller['gender']}) (male/female/m/f): ").strip()
            if check_back_command(new_gender):
                return
            
            if not new_gender:
                break
            elif validate_gender(new_gender):
                # FIX 9: No input modification - store exactly as entered
                updates['gender'] = new_gender
                break
            else:
                print("❌ Ongeldig geslacht. Gebruik male of female.")
        
        # Street name validation
        while True:
            new_street = input(f"Straatnaam ({current_traveller['street_name']}): ").strip()
            if check_back_command(new_street):
                return
            
            if not new_street:
                break
            elif validate_street_name(new_street):
                updates['street_name'] = new_street
                break
            else:
                print("❌ Ongeldige straatnaam.")
        
        # House number validation
        while True:
            new_house_number = input(f"Huisnummer ({current_traveller['house_number']}): ").strip()
            if check_back_command(new_house_number):
                return
            
            if not new_house_number:
                break
            elif validate_house_number(new_house_number):
                updates['house_number'] = new_house_number
                break
            else:
                print("❌ Ongeldig huisnummer.")
        
        # Zip code validation
        while True:
            new_zip = input(f"Postcode ({current_traveller['zip_code']}): ").strip()
            if check_back_command(new_zip):
                return
            
            if not new_zip:
                break
            elif validate_zip_code(new_zip):
                # FIX 9: No input modification - validation requires uppercase
                updates['zip_code'] = new_zip
                break
            else:
                print("❌ Ongeldige postcode. Gebruik formaat 1234AB.")
        
        # City validation
        while True:
            new_city = input(f"Stad ({current_traveller['city']}): ").strip()
            if check_back_command(new_city):
                return
            
            if not new_city:
                break
            elif validate_city(new_city):
                updates['city'] = new_city
                break
            else:
                cities = get_valid_cities()
                print(f"❌ Ongeldige stad. Beschikbare steden: {', '.join(cities)}")
        
        # Email validation
        while True:
            new_email = input(f"Email ({current_traveller['email_address']}): ").strip()
            if check_back_command(new_email):
                return
            
            if not new_email:
                break
            elif validate_email(new_email):
                updates['email_address'] = new_email
                break
            else:
                print("❌ Ongeldig email format.")
        
        # Phone validation
        while True:
            new_phone = input(f"Mobiel nummer ({current_traveller['mobile_phone']}): ").strip()
            if check_back_command(new_phone):
                return
            
            if not new_phone:
                break
            elif validate_mobile_phone(new_phone):
                updates['mobile_phone'] = new_phone
                break
            else:
                print("❌ Ongeldig telefoonnummer. Voer 8 cijfers in.")
        
        # Driving license validation
        while True:
            new_license = input(f"Rijbewijsnummer ({current_traveller['driving_license_number']}): ").strip()
            if check_back_command(new_license):
                return
            
            if not new_license:
                break
            elif validate_driving_license(new_license):
                # FIX 9: No input modification - validation requires uppercase
                updates['driving_license_number'] = new_license
                break
            else:
                print("❌ Ongeldig rijbewijsnummer. Gebruik formaat XXDDDDDDD of XDDDDDDDD.")
        
        if not updates:
            print("Geen wijzigingen opgegeven")
            pause()
            return
        
        # Apply updates
        success = update_traveller(customer_id, **updates)
        
        if success:
            print("✅ Reiziger succesvol bijgewerkt")
            log_event(f"Reiziger bijgewerkt", username, f"ID: {customer_id}, Velden: {list(updates.keys())}")
        else:
            print("❌ Fout bij bijwerken reiziger")
    except Exception as e:
        print(f"❌ Fout bij bijwerken reiziger: {e}")
    
    pause()

def delete_traveller_menu(username: str):
    """Delete traveller"""
    clear_screen()
    show_header("Reiziger Verwijderen")
    
    customer_id = input("Customer ID van reiziger om te verwijderen: ").strip()
    
    if check_back_command(customer_id):
        return
    
    if not customer_id:
        print("❌ Customer ID is verplicht")
        pause()
        return
    
    try:
        # Get traveller info for confirmation
        travellers = get_all_travellers()
        traveller_to_delete = None
        
        for t in travellers:
            if t['customer_id'] == customer_id:
                traveller_to_delete = t
                break
        
        if not traveller_to_delete:
            print(f"❌ Reiziger met ID {customer_id} niet gevonden")
            pause()
            return
        
        # Show traveller details
        print(f"\nReiziger gegevens:")
        print(f"📋 ID: {customer_id}")
        print(f"👤 Naam: {traveller_to_delete['first_name']} {traveller_to_delete['last_name']}")
        print(f"📧 Email: {traveller_to_delete['email_address']}")
        print(f"🏠 Adres: {traveller_to_delete['street_name']} {traveller_to_delete['house_number']}")
        
        # Confirmation
        name = f"{traveller_to_delete['first_name']} {traveller_to_delete['last_name']}"
        confirm = input(f"\n⚠️  Weet je zeker dat je reiziger {name} (ID: {customer_id}) wilt verwijderen? (ja/nee): ").strip().casefold()
        
        if confirm not in ['ja', 'j', 'yes', 'y']:
            print("Verwijdering geannuleerd")
            pause()
            return
        
        # Delete traveller
        success = delete_traveller(customer_id)
        
        if success:
            print("✅ Reiziger succesvol verwijderd")
            log_event(f"Reiziger verwijderd", username, f"ID: {customer_id}, Naam: {name}")
        else:
            print("❌ Fout bij verwijderen reiziger")
    except Exception as e:
        print(f"❌ Fout bij verwijderen reiziger: {e}")
    
    pause()

# ============================================================================
# SCOOTER MANAGEMENT FUNCTIONS  
# ============================================================================

def scooter_management_menu(username: str, role: str):
    """Scooter management submenu"""
    while True:
        clear_screen()
        show_header("Scooter Beheer")
        
        options = ["Alle scooters bekijken", "Scooter zoeken"]
        
        if role in ['super_admin', 'system_admin']:
            options.extend(["Nieuwe scooter toevoegen", "Scooter bijwerken", "Scooter verwijderen"])
        elif role == 'service_engineer':
            options.append("Scooter status bijwerken")
        
        options.append("Terug naar hoofdmenu")
        
        for i, option in enumerate(options, 1):
            print(f"{i}. {option}")
        
        choice = input(f"\nKies een optie (1-{len(options)}): ")
        
        if check_back_command(choice) or choice == str(len(options)):
            break
        
        try:
            choice_num = int(choice)
            if choice_num == 1:
                view_all_scooters_menu()
            elif choice_num == 2:
                search_scooters_menu()
            elif choice_num == 3 and role in ['super_admin', 'system_admin']:
                create_scooter_menu(username)
            elif choice_num == 4 and role in ['super_admin', 'system_admin']:
                update_scooter_menu(username, role)
            elif choice_num == 3 and role == 'service_engineer':
                update_scooter_menu(username, role)
            elif choice_num == 5 and role in ['super_admin', 'system_admin']:
                delete_scooter_menu(username)
            else:
                print("Ongeldige keuze.")
                pause()
        except ValueError:
            print("Voer een geldig nummer in.")
            pause()

def view_all_scooters_menu():
    """Display all scooters in formatted table"""
    clear_screen()
    show_header("Alle Scooters")
    
    try:
        scooters = get_all_scooters()
        if not scooters:
            print("Geen scooters gevonden.")
        else:
            # Define column widths and adjust for terminal
            base_widths = [17, 12, 15, 10, 10, 20, 12]
            widths = adjust_table_widths_for_terminal(base_widths)
            headers = ['Serienummer', 'Merk', 'Model', 'Batterij %', 'Km-stand', 'Locatie', 'Status']
            
            show_table_header(headers, widths)
            
            for s in scooters:
                status = "Buiten dienst" if s['out_of_service_status'] else "In dienst"
                location = s['location'][:18] + "..." if len(s['location']) > 20 else s['location']
                mileage = f"{s['mileage']:.1f}"
                values = [
                    s['serial_number'], s['brand'], s['model'], 
                    f"{s['state_of_charge']}%", f"{mileage} km", 
                    location, status
                ]
                print(format_table_row(values, widths))
            
            show_table_footer(widths)
            print(f"\nTotaal: {len(scooters)} scooters")
            
            # Quick statistics
            in_service = sum(1 for s in scooters if not s['out_of_service_status'])
            avg_battery = sum(s['state_of_charge'] for s in scooters) / len(scooters)
            print(f"In dienst: {in_service}, Buiten dienst: {len(scooters)-in_service}")
            print(f"Gemiddelde batterij: {avg_battery:.1f}%")
    except Exception as e:
        print(f"❌ Fout bij ophalen scooters: {e}")
    
    pause()

def search_scooters_menu():
    """Search scooters"""
    clear_screen()
    show_header("Scooter Zoeken")
    
    try:
        search_term = get_validated_input_with_back("Zoekterm (merk, model, serienummer)", validate_search_term, "search_term")
        if search_term is None:
            return
        
        results = search_scooters(search_term)
        
        if not results:
            print(f"Geen scooters gevonden voor '{search_term}'.")
        else:
            print(f"\n{len(results)} resultaten gevonden voor '{search_term}':")
            
            base_widths = [17, 12, 15, 10, 12]
            widths = adjust_table_widths_for_terminal(base_widths)
            headers = ['Serienummer', 'Merk', 'Model', 'Batterij %', 'Status']
            
            show_table_header(headers, widths)
            
            for s in results:
                status = "Buiten dienst" if s['out_of_service_status'] else "In dienst"
                values = [s['serial_number'], s['brand'], s['model'], f"{s['state_of_charge']}%", status]
                print(format_table_row(values, widths))
            
            show_table_footer(widths)
    except Exception as e:
        print(f"❌ Fout bij zoeken scooters: {e}")
    
    pause()

def create_scooter_menu(username: str):
    """Add new scooter with all required fields"""
    clear_screen()
    show_header("Nieuwe Scooter Toevoegen")
    
    try:
        brand = get_validated_input_with_back("Merk", validate_brand_model, "brand")
        if brand is None: return
        
        model = get_validated_input_with_back("Model", validate_brand_model, "model")
        if model is None: return
        
        serial_number = get_validated_input_with_back("Serienummer (10-17 tekens)", validate_serial_number, "serial_number")
        if serial_number is None: return
        
        top_speed = get_validated_input_with_back("Topsnelheid (km/h)", validate_positive_integer, "positive_integer")
        if top_speed is None: return
        
        battery_capacity = get_validated_input_with_back("Batterijcapaciteit (Wh)", validate_positive_integer, "positive_integer")
        if battery_capacity is None: return
        
        state_of_charge = get_validated_input_with_back("Huidige batterijlading (0-100%)", validate_percentage, "percentage")
        if state_of_charge is None: return
        
        # Target range SoC
        print("\nBatterijbereik instelling:")
        min_soc = get_validated_input_with_back("Minimum batterijniveau (%)", validate_percentage, "percentage")
        if min_soc is None: return
        
        max_soc = get_validated_input_with_back("Maximum batterijniveau (%)", validate_percentage, "percentage")
        if max_soc is None: return
        
        if not validate_soc_range(min_soc, max_soc):
            print("❌ Minimum moet kleiner zijn dan maximum")
            pause()
            return
        
        target_range_soc = f"{min_soc}-{max_soc}%"
        
        # GPS location - much easier now
        print("\nGPS locatie:")
        print("Voorbeelden: 51.92250, 4.47917 of 51.9, 4.5")
        
        latitude = input("Latitude: ").strip()
        if check_back_command(latitude):
            return
        
        longitude = input("Longitude: ").strip()
        if check_back_command(longitude):
            return
        
        # Flexible validation - if they enter something reasonable, accept it
        if validate_flexible_gps_coordinate(latitude, 'lat') and validate_flexible_gps_coordinate(longitude, 'lon'):
            location = f"{latitude},{longitude}"
        else:
            print("⚠️  GPS coördinaten lijken niet correct voor Nederland, maar worden toch opgeslagen.")
            location = f"{latitude},{longitude}"
        
        # Service status
        print("\nService status:")
        print("1. In dienst (beschikbaar voor gebruik)")
        print("2. Buiten dienst (niet beschikbaar)")
        while True:
            service_choice = input("Kies service status (1 of 2): ").strip()
            if check_back_command(service_choice):
                return
            if service_choice == "1":
                out_of_service_status = 0  # In service
                print("✓ Scooter wordt ingesteld als 'In dienst'")
                break
            elif service_choice == "2":
                out_of_service_status = 1  # Out of service
                print("✓ Scooter wordt ingesteld als 'Buiten dienst'")
                break
            else:
                print("❌ Ongeldige keuze, voer 1 of 2 in")
        
        # Mileage
        mileage = get_validated_input_with_back("Huidige kilometerstand (km)", validate_positive_float, "positive_float")
        if mileage is None: return
        
        # Flexible maintenance date
        maintenance_date = input("Laatste onderhoudsdatum (bijv. 2024-03-15): ").strip()
        if check_back_command(maintenance_date):
            return
        
        if maintenance_date:
            if validate_flexible_date(maintenance_date):
                # Convert to ISO format for storage
                maintenance_date = convert_flexible_date_to_iso(maintenance_date)
            else:
                print("⚠️  Datum format niet herkend, maar wordt toch opgeslagen als tekst.")
                # Keep as-is if not recognized
        else:
            maintenance_date = None
        
        # Final validation before adding scooter
        if not all([brand, model, serial_number, top_speed, battery_capacity, state_of_charge, location, mileage]):
            print("❌ Niet alle verplichte velden zijn ingevuld. Scooter wordt niet toegevoegd.")
            pause()
            return
        
        # Add scooter with all fields including out_of_service_status and mileage
        success = add_scooter(
            brand, model, serial_number, int(top_speed), int(battery_capacity),
            int(state_of_charge), target_range_soc, location, maintenance_date,
            out_of_service_status, float(mileage)
        )
        
        if success:
            status_text = "Buiten dienst" if out_of_service_status else "In dienst"
            print(f"\n✅ Scooter succesvol toegevoegd!")
            print(f"🛴 Serienummer: {serial_number}")
            print(f"🏭 Merk/Model: {brand} {model}")
            print(f"🔋 Batterij: {state_of_charge}%")
            print(f"📍 Locatie: {location}")
            print(f"🚦 Status: {status_text}")
            print(f"🛣️  Kilometerstand: {mileage} km")
            log_event(f"Nieuwe scooter toegevoegd", username, 
                     f"Serienummer: {serial_number}, Merk: {brand} {model}, Locatie: {location}, Status: {status_text}, Km: {mileage}")
        else:
            print("\n❌ Fout bij toevoegen scooter (serienummer mogelijk al in gebruik)")
    except Exception as e:
        print(f"❌ Fout bij toevoegen scooter: {e}")
    
    pause()

def update_scooter_menu(username: str, role: str):
    """Update scooter based on user role - all fields editable"""
    clear_screen()
    show_header("Scooter Bijwerken")
    
    serial_number = input("Serienummer van scooter om bij te werken: ").strip()
    
    if check_back_command(serial_number):
        return
    
    if not serial_number:
        print("❌ Serienummer is verplicht")
        pause()
        return
    
    try:
        # Get current scooter info
        scooters = get_all_scooters()
        current_scooter = None
        
        for s in scooters:
            if s['serial_number'] == serial_number:
                current_scooter = s
                break
        
        if not current_scooter:
            print(f"❌ Scooter met serienummer {serial_number} niet gevonden")
            pause()
            return
        
        # Display current info
        print(f"\nHuidige gegevens van scooter {serial_number}:")
        print(f"🏭 Merk/Model: {current_scooter['brand']} {current_scooter['model']}")
        print(f"⚡ Topsnelheid: {current_scooter['top_speed']} km/h")
        print(f"🔋 Batterijcapaciteit: {current_scooter['battery_capacity']} Wh")
        print(f"🔋 Batterijlading: {current_scooter['state_of_charge']}%")
        print(f"🎯 Batterijbereik: {current_scooter['target_range_soc']}")
        print(f"📍 Locatie: {current_scooter['location']}")
        print(f"🚦 Status: {'Buiten dienst' if current_scooter['out_of_service_status'] else 'In dienst'}")
        print(f"🛣️  Kilometerstand: {current_scooter['mileage']} km")
        if current_scooter['last_maintenance_date']:
            print(f"🔧 Laatste onderhoud: {current_scooter['last_maintenance_date']}")
        
        # Define which fields can be updated based on role
        if role == 'service_engineer':
            print("\n🔧 Als Service Engineer kun je bijwerken: batterijlading, locatie, status, kilometerstand, onderhoudsdatum")
            allowed_fields = ['state_of_charge', 'location', 'out_of_service_status', 'mileage', 'last_maintenance_date']
        else:  # super_admin or system_admin
            print("\n👑 Als Administrator kun je alle velden bijwerken")
            allowed_fields = ['brand', 'model', 'top_speed', 'battery_capacity', 'state_of_charge', 'target_range_soc', 'location', 'out_of_service_status', 'mileage', 'last_maintenance_date']
        
        # Collect updates
        updates = {}
        
        print("\nVoer nieuwe waarden in (laat leeg om ongewijzigd te laten):")
        
        # Brand (admin only)
        if 'brand' in allowed_fields:
            while True:
                new_brand = input(f"Merk ({current_scooter['brand']}): ").strip()
                if check_back_command(new_brand):
                    return
                
                if not new_brand:
                    break
                elif validate_brand_model(new_brand):
                    updates['brand'] = new_brand
                    break
                else:
                    print("❌ Ongeldige merk naam.")
        
        # Model (admin only)
        if 'model' in allowed_fields:
            while True:
                new_model = input(f"Model ({current_scooter['model']}): ").strip()
                if check_back_command(new_model):
                    return
                
                if not new_model:
                    break
                elif validate_brand_model(new_model):
                    updates['model'] = new_model
                    break
                else:
                    print("❌ Ongeldige model naam.")
        
        # Top speed (admin only)
        if 'top_speed' in allowed_fields:
            while True:
                new_top_speed = input(f"Topsnelheid ({current_scooter['top_speed']} km/h): ").strip()
                if check_back_command(new_top_speed):
                    return
                
                if not new_top_speed:
                    break
                elif validate_positive_integer(new_top_speed):
                    updates['top_speed'] = int(new_top_speed)
                    break
                else:
                    print("❌ Moet een positief getal zijn.")
        
        # Battery capacity (admin only)
        if 'battery_capacity' in allowed_fields:
            while True:
                new_capacity = input(f"Batterijcapaciteit ({current_scooter['battery_capacity']} Wh): ").strip()
                if check_back_command(new_capacity):
                    return
                
                if not new_capacity:
                    break
                elif validate_positive_integer(new_capacity):
                    updates['battery_capacity'] = int(new_capacity)
                    break
                else:
                    print("❌ Moet een positief getal zijn.")
        
        # Battery charge
        if 'state_of_charge' in allowed_fields:
            new_soc = input(f"Batterijlading ({current_scooter['state_of_charge']}%): ").strip()
            if check_back_command(new_soc):
                return
            
            if new_soc:
                try:
                    soc_value = int(new_soc)
                    if 0 <= soc_value <= 100:
                        updates['state_of_charge'] = soc_value
                    else:
                        print("⚠️  Batterijlading buiten normale range, maar wordt toch opgeslagen.")
                        updates['state_of_charge'] = soc_value
                except ValueError:
                    print("❌ Moet een getal zijn voor batterijlading.")
        
        # Target range SoC (admin only)
        if 'target_range_soc' in allowed_fields:
            new_target_range = input(f"Batterijbereik ({current_scooter['target_range_soc']}): ").strip()
            if check_back_command(new_target_range):
                return
            
            if new_target_range:
                updates['target_range_soc'] = new_target_range
        
        # GPS location
        if 'location' in allowed_fields:
            print("Nieuwe GPS locatie (laat beide leeg om ongewijzigd te laten):")
            current_coords = current_scooter['location'].split(',') if ',' in current_scooter['location'] else ['', '']
            
            while True:
                new_lat = input(f"Latitude (huidig: {current_coords[0] if len(current_coords) > 0 else ''}): ").strip()
                if check_back_command(new_lat):
                    return
                
                new_lon = input(f"Longitude (huidig: {current_coords[1] if len(current_coords) > 1 else ''}): ").strip()
                if check_back_command(new_lon):
                    return
                
                if not new_lat and not new_lon:
                    break
                elif new_lat and new_lon:
                    updates['location'] = f"{new_lat},{new_lon}"
                    break
                else:
                    print("❌ Voer beide coördinaten in of laat beide leeg.")
        
        # Service status
        if 'out_of_service_status' in allowed_fields:
            current_status = "buiten dienst" if current_scooter['out_of_service_status'] else "in dienst"
            new_status = input(f"Status ({current_status}) - voer 'uit' in voor buiten dienst, 'in' voor in dienst: ").strip().casefold()
            if check_back_command(new_status):
                return
            if new_status in ['uit', 'buiten', 'out']:
                updates['out_of_service_status'] = 1
            elif new_status in ['in', 'actief', 'active']:
                updates['out_of_service_status'] = 0
        
        # Mileage
        if 'mileage' in allowed_fields:
            new_mileage = input(f"Kilometerstand ({current_scooter['mileage']} km): ").strip()
            if check_back_command(new_mileage):
                return
            
            if new_mileage:
                try:
                    mileage_value = float(new_mileage)
                    if mileage_value >= 0:
                        updates['mileage'] = mileage_value
                    else:
                        print("⚠️  Negatieve kilometerstand, maar wordt toch opgeslagen.")
                        updates['mileage'] = mileage_value
                except ValueError:
                    print("❌ Moet een getal zijn voor kilometerstand.")
        
        # Maintenance date
        if 'last_maintenance_date' in allowed_fields:
            new_maintenance = input(f"Laatste onderhoudsdatum ({current_scooter['last_maintenance_date'] or 'Niet bekend'}) (bijv. 2024-03-15): ").strip()
            if check_back_command(new_maintenance):
                return
            
            if new_maintenance:
                if validate_flexible_date(new_maintenance):
                    updates['last_maintenance_date'] = convert_flexible_date_to_iso(new_maintenance)
                else:
                    print("⚠️  Datum format niet herkend, maar wordt toch opgeslagen.")
                    updates['last_maintenance_date'] = new_maintenance
        
        if not updates:
            print("Geen wijzigingen opgegeven")
            pause()
            return
        
        # Apply updates
        success = update_scooter(serial_number, role, **updates)
        
        if success:
            print("✅ Scooter succesvol bijgewerkt")
            log_event(f"Scooter bijgewerkt", username, f"Serienummer: {serial_number}, Velden: {list(updates.keys())}")
        else:
            print("❌ Fout bij bijwerken scooter")
    except Exception as e:
        print(f"❌ Fout bij bijwerken scooter: {e}")
    
    pause()

def delete_scooter_menu(username: str):
    """Delete scooter"""
    clear_screen()
    show_header("Scooter Verwijderen")
    
    serial_number = input("Serienummer van scooter om te verwijderen: ").strip()
    
    if check_back_command(serial_number):
        return
    
    if not serial_number:
        print("❌ Serienummer is verplicht")
        pause()
        return
    
    try:
        # Get scooter info for confirmation
        scooters = get_all_scooters()
        scooter_to_delete = None
        
        for s in scooters:
            if s['serial_number'] == serial_number:
                scooter_to_delete = s
                break
        
        if not scooter_to_delete:
            print(f"❌ Scooter met serienummer {serial_number} niet gevonden")
            pause()
            return
        
        # Show scooter details
        print(f"\nScooter gegevens:")
        print(f"🛴 Serienummer: {serial_number}")
        print(f"🏭 Merk/Model: {scooter_to_delete['brand']} {scooter_to_delete['model']}")
        print(f"🔋 Batterij: {scooter_to_delete['state_of_charge']}%")
        print(f"📍 Locatie: {scooter_to_delete['location']}")
        print(f"🛣️  Kilometerstand: {scooter_to_delete['mileage']} km")
        
        # Confirmation
        brand_model = f"{scooter_to_delete['brand']} {scooter_to_delete['model']}"
        confirm = input(f"\n⚠️  Weet je zeker dat je scooter {brand_model} (serienummer: {serial_number}) wilt verwijderen? (ja/nee): ").strip().casefold()
        
        if confirm not in ['ja', 'j', 'yes', 'y']:
            print("Verwijdering geannuleerd")
            pause()
            return
        
        # Delete scooter
        success = delete_scooter(serial_number)
        
        if success:
            print("✅ Scooter succesvol verwijderd")
            log_event(f"Scooter verwijderd", username, f"Serienummer: {serial_number}, Merk: {brand_model}")
        else:
            print("❌ Fout bij verwijderen scooter")
    except Exception as e:
        print(f"❌ Fout bij verwijderen scooter: {e}")
    
    pause()

# ============================================================================
# BACKUP MANAGEMENT FUNCTIONS
# ============================================================================

def backup_management_menu(username: str, role: str):
    """Backup management submenu"""
    while True:
        clear_screen()
        show_header("Backup Beheer")
        
        print("1. Backup maken")
        print("2. Beschikbare backups bekijken")
        print("3. Backup herstellen")
        if role == 'super_admin':
            print("4. Backup verwijderen")
            print("5. Backup statistieken")
        print("0. Terug naar hoofdmenu")
        
        choice = input("\nKies een optie: ")
        
        if check_back_command(choice) or choice == "0":
            break
        elif choice == "1":
            create_new_backup(username)
        elif choice == "2":
            view_available_backups()
        elif choice == "3":
            restore_from_backup_interactive(username, role)
        elif choice == "4" and role == 'super_admin':
            delete_backup_interactive(username)
        elif choice == "5" and role == 'super_admin':
            show_backup_statistics()
        else:
            print("Ongeldige keuze.")
            pause()

def create_new_backup(username: str):
    """Create new backup"""
    clear_screen()
    show_header("Backup Maken")
    
    try:
        print("🔄 Backup wordt aangemaakt...")
        backup_name = create_backup(username)
        print(f"✅ Backup succesvol aangemaakt: {backup_name}")
        log_event(f"Backup aangemaakt", username, f"Backup: {backup_name}")
    except Exception as e:
        print(f"❌ Fout bij maken backup: {e}")
    
    pause()

def view_available_backups():
    """View available backups in formatted table"""
    clear_screen()
    show_header("Beschikbare Backups")
    
    try:
        backups = list_backups()
        
        if not backups:
            print("Geen backups gevonden.")
        else:
            # Define column widths and adjust for terminal
            base_widths = [25, 20, 12, 15]
            widths = adjust_table_widths_for_terminal(base_widths)
            headers = ['Bestandsnaam', 'Aangemaakt', 'Grootte (MB)', 'Door']
            
            show_table_header(headers, widths)
            
            for backup in backups:
                created_date = backup['created'].strftime('%d-%m-%Y %H:%M')
                values = [
                    backup['filename'], 
                    created_date, 
                    f"{backup['size_mb']:.2f}", 
                    backup['creator']
                ]
                print(format_table_row(values, widths))
            
            show_table_footer(widths)
            print(f"\nTotaal: {len(backups)} backups")
    except Exception as e:
        print(f"❌ Fout bij ophalen backups: {e}")
    
    pause()

def restore_from_backup_interactive(username: str, role: str):
    """Restore from backup interactively"""
    clear_screen()
    show_header("Backup Herstellen")
    
    try:
        # Show available backups
        backups = list_backups()
        
        if not backups:
            print("Geen backups beschikbaar.")
            pause()
            return
        
        print("Beschikbare backups:")
        for i, backup in enumerate(backups, 1):
            created_date = backup['created'].strftime('%d-%m-%Y %H:%M')
            print(f"{i}. {backup['filename']} (aangemaakt: {created_date}, {backup['size_mb']:.1f}MB)")
        
        while True:
            choice_input = input(f"\nKies backup (1-{len(backups)}): ")
            if check_back_command(choice_input):
                return
            
            try:
                choice = int(choice_input) - 1
                if 0 <= choice < len(backups):
                    break
                else:
                    print("❌ Ongeldige keuze.")
            except ValueError:
                print("❌ Voer een geldig nummer in.")
        
        selected_backup = backups[choice]['filename']
        
        # Check if restore code is needed
        restore_code = None
        if role != 'super_admin':
            restore_code = input("Voer restore-code in: ").strip()
            if check_back_command(restore_code):
                return
            if not restore_code:
                print("❌ Restore-code is verplicht voor System Administrators.")
                pause()
                return
        
        # Confirm restore
        confirm = input(f"⚠️  Weet je zeker dat je backup {selected_backup} wilt herstellen?\nDit overschrijft de huidige data! (ja/nee): ").strip().casefold()
        
        if confirm not in ['ja', 'j', 'yes', 'y']:
            print("Restore geannuleerd.")
            pause()
            return
        
        # Perform restore
        print("🔄 Backup wordt hersteld...")
        success = restore_backup(selected_backup, username, restore_code, role == 'super_admin')
        
        if success:
            print("✅ Backup succesvol hersteld!")
            print("⚠️  Herstart het systeem om de wijzigingen te activeren.")
        else:
            print("❌ Backup herstellen mislukt.")
    except Exception as e:
        print(f"❌ Fout bij herstellen backup: {e}")
    
    pause()

def delete_backup_interactive(username: str):
    """Delete backup interactively (super admin only)"""
    clear_screen()
    show_header("Backup Verwijderen")
    
    try:
        backups = list_backups()
        
        if not backups:
            print("Geen backups beschikbaar.")
            pause()
            return
        
        print("Beschikbare backups:")
        for i, backup in enumerate(backups, 1):
            created_date = backup['created'].strftime('%d-%m-%Y %H:%M')
            print(f"{i}. {backup['filename']} (aangemaakt: {created_date})")
        
        while True:
            choice_input = input(f"\nKies backup om te verwijderen (1-{len(backups)}): ")
            if check_back_command(choice_input):
                return
            
            try:
                choice = int(choice_input) - 1
                if 0 <= choice < len(backups):
                    break
                else:
                    print("❌ Ongeldige keuze.")
            except ValueError:
                print("❌ Voer een geldig nummer in.")
        
        selected_backup = backups[choice]['filename']
        
        # Confirm deletion
        confirm = input(f"⚠️  Weet je zeker dat je backup {selected_backup} wilt verwijderen? (ja/nee): ").strip().casefold()
        
        if confirm not in ['ja', 'j', 'yes', 'y']:
            print("Verwijdering geannuleerd.")
            pause()
            return
        
        # Delete backup
        backup_path = os.path.join('backups', selected_backup)
        if os.path.exists(backup_path):
            os.remove(backup_path)
            print("✅ Backup succesvol verwijderd!")
            log_event(f"Backup verwijderd", username, f"Backup: {selected_backup}")
        else:
            print("❌ Backup bestand niet gevonden.")
    except Exception as e:
        print(f"❌ Fout bij verwijderen backup: {e}")
    
    pause()

def show_backup_statistics():
    """Show backup statistics"""
    clear_screen()
    show_header("Backup Statistieken")
    
    try:
        stats = get_backup_statistics()
        
        print(f"📊 Backup Overzicht:")
        print(f"Totaal aantal backups: {stats['total_backups']}")
        print(f"Totale grootte: {stats['total_size_mb']:.2f} MB")
        
        if stats['total_backups'] > 0:
            print(f"Gemiddelde grootte: {stats['average_size_mb']:.2f} MB")
            print(f"Nieuwste backup: {stats['newest_backup']}")
            print(f"Oudste backup: {stats['oldest_backup']}")
        
        print(f"\n💾 Schijfruimte:")
        print(f"Backup directory: {os.path.abspath('backups/')}")
        
    except Exception as e:
        print(f"❌ Fout bij ophalen statistieken: {e}")
    
    pause()

# ============================================================================
# RESTORE CODE MANAGEMENT
# ============================================================================

def restore_code_management_menu(username: str, role: str):
    """Restore code management (super admin only)"""
    while True:
        clear_screen()
        show_header("Restore-Code Beheer")
        
        print("1. Restore-code genereren")
        print("2. Restore-code intrekken")
        print("3. Terug naar hoofdmenu")
        
        choice = input("\nKies een optie (1-3): ")
        
        if check_back_command(choice) or choice == "3":
            break
        elif choice == "1":
            generate_restore_code_interactive(username)
        elif choice == "2":
            revoke_restore_code_interactive_menu(username)
        else:
            print("Ongeldige keuze.")
            pause()

def generate_restore_code_interactive(username: str):
    """Generate restore code interactively"""
    clear_screen()
    show_header("Restore-Code Genereren")
    
    try:
        # Show available backups
        backups = list_backups()
        
        if not backups:
            print("Geen backups beschikbaar.")
            pause()
            return
        
        # Show system admins
        users = get_all_users()
        system_admins = [u for u in users if u['role'] == 'system_admin']
        
        if not system_admins:
            print("Geen System Administrators gevonden.")
            pause()
            return
        
        print("System Administrators:")
        for i, admin in enumerate(system_admins, 1):
            print(f"{i}. {admin['username']} ({admin['first_name']} {admin['last_name']})")
        
        while True:
            admin_input = input(f"\nKies System Administrator (1-{len(system_admins)}): ")
            if check_back_command(admin_input):
                return
            
            try:
                admin_choice = int(admin_input) - 1
                if 0 <= admin_choice < len(system_admins):
                    break
                else:
                    print("❌ Ongeldige keuze.")
            except ValueError:
                print("❌ Voer een geldig nummer in.")
        
        selected_admin = system_admins[admin_choice]['username']
        
        print("\nBeschikbare backups:")
        for i, backup in enumerate(backups, 1):
            created_date = backup['created'].strftime('%d-%m-%Y %H:%M')
            print(f"{i}. {backup['filename']} (aangemaakt: {created_date})")
        
        while True:
            backup_input = input(f"\nKies backup (1-{len(backups)}): ")
            if check_back_command(backup_input):
                return
            
            try:
                backup_choice = int(backup_input) - 1
                if 0 <= backup_choice < len(backups):
                    break
                else:
                    print("❌ Ongeldige keuze.")
            except ValueError:
                print("❌ Voer een geldig nummer in.")
        
        selected_backup = backups[backup_choice]['filename']
        
        # Generate code
        code = ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(12))
        success = add_restore_code(code, selected_admin, selected_backup)
        
        if success:
            print(f"\n✅ Restore-code succesvol gegenereerd!")
            print(f"🔑 Code: {code}")
            print(f"👤 Voor: {selected_admin}")
            print(f"💾 Backup: {selected_backup}")
            print("\n⚠️  Deze code is eenmalig bruikbaar!")
            log_event(f"Restore-code gegenereerd", username, f"Code voor {selected_admin}, Backup: {selected_backup}")
        else:
            print("❌ Fout bij genereren restore-code.")
    except Exception as e:
        print(f"❌ Fout bij genereren restore-code: {e}")
    
    pause()

def revoke_restore_code_interactive_menu(username: str):
    """Revoke restore code"""
    clear_screen()
    show_header("Restore-Code Intrekken")
    
    code = input("Restore-code om in te trekken (uppercase): ").strip()
    # FIX 9: No input modification - user must enter uppercase
    
    if check_back_command(code):
        return
    
    if not code:
        print("❌ Restore-code is verplicht")
        pause()
        return
    
    try:
        # Check if code exists
        code_info = get_restore_code(code)
        if not code_info:
            print("❌ Restore-code niet gevonden of al gebruikt")
            pause()
            return
        
        # Show code info
        print(f"Code informatie:")
        print(f"👤 Voor gebruiker: {code_info['system_admin_username']}")
        print(f"💾 Voor backup: {code_info['backup_name']}")
        print(f"📅 Aangemaakt: {code_info['created_date'][:10]}")
        
        # Confirmation
        confirm = input("⚠️  Weet je zeker dat je deze code wilt intrekken? (ja/nee): ").strip().casefold()
        
        if confirm not in ['ja', 'j', 'yes', 'y']:
            print("Intrekking geannuleerd")
            pause()
            return
        
        # Revoke code
        success = revoke_restore_code(code)
        
        if success:
            print("✅ Restore-code succesvol ingetrokken")
            log_event(f"Restore-code ingetrokken", username, f"Code: {code}, Was voor: {code_info['system_admin_username']}")
        else:
            print("❌ Fout bij intrekken restore-code")
    except Exception as e:
        print(f"❌ Fout bij intrekken restore-code: {e}")
    
    pause()

# ============================================================================
# VERBETERDE LOGGING FUNCTIONS
# ============================================================================

def view_logs_menu(username: str, role: str):
    """View system logs in formatted table with pagination"""
    clear_screen()
    show_header("Systeem Logs")
    
    try:
        logs = get_logs()
        if not logs:
            print("Geen logs gevonden.")
            pause()
            return
        
        # Pagination settings
        logs_per_page = 25
        total_pages = (len(logs) + logs_per_page - 1) // logs_per_page
        current_page = 1
        
        while True:
            clear_screen()
            show_header("Systeem Logs")
            
            # Calculate start and end indices for current page
            start_idx = (current_page - 1) * logs_per_page
            end_idx = min(start_idx + logs_per_page, len(logs))
            current_logs = logs[start_idx:end_idx]
            
            # Show page info
            print(f"📄 Pagina {current_page} van {total_pages} (logs {start_idx + 1}-{end_idx} van {len(logs)})")
            print()
            
            # Define column widths - ZONDER Info kolom
            base_widths = [3, 12, 8, 15, 35, 8]
            widths = adjust_table_widths_for_terminal(base_widths)
            headers = ['Nr', 'Datum', 'Tijd', 'Gebruiker', 'Beschrijving', 'Verdacht']
            
            show_table_header(headers, widths)
            
            # Show current page logs
            for i, log in enumerate(current_logs, start_idx + 1):
                # Split timestamp into date and time
                timestamp_parts = log['timestamp'][:19].split('T') if log['timestamp'] else ['...', '...']
                date_part = timestamp_parts[0] if len(timestamp_parts) > 0 and timestamp_parts[0] else "..."
                time_part = timestamp_parts[1] if len(timestamp_parts) > 1 and timestamp_parts[1] else "..."
                
                username_display = log['username'] if log['username'] and log['username'].strip() else "..."
                description = log['description'] if log['description'] and log['description'].strip() else "..."
                suspicious = "Ja" if log['suspicious'] else "Nee"
                
                values = [i, date_part, time_part, username_display, description, suspicious]
                print(format_table_row(values, widths))
            
            show_table_footer(widths)
            
            # Show suspicious activity summary
            suspicious_logs = [log for log in logs if log['suspicious']]
            if suspicious_logs:
                print(f"\n⚠️  Totaal verdachte activiteiten: {len(suspicious_logs)}")
            
            # Show navigation options - ALLEEN HIER, GEEN DUBBELE
            print("\nNavigatie opties:")
            nav_options = []
            
            if current_page > 1:
                nav_options.append("(v) Vorige pagina")
            if current_page < total_pages:
                nav_options.append("(n) Volgende pagina")
            
            nav_options.extend([
                "(a) Alle logs tonen",
                "(s) Alleen verdachte logs tonen", 
                "(g) Ga naar pagina",
                "(t) Terug naar hoofdmenu"
            ])
            
            for option in nav_options:
                print(f"  {option}")
            
            # Get user choice
            choice = input("\nKies een optie: ").strip().casefold()
            
            if choice == 't' or check_back_command(choice):
                break
            elif choice == 'v' and current_page > 1:
                current_page -= 1
            elif choice == 'n' and current_page < total_pages:
                current_page += 1
            elif choice == 'g':
                try:
                    page_num = int(input(f"Ga naar pagina (1-{total_pages}): "))
                    if 1 <= page_num <= total_pages:
                        current_page = page_num
                    else:
                        print(f"❌ Ongeldige pagina. Kies tussen 1 en {total_pages}.")
                        pause()
                except ValueError:
                    print("❌ Voer een geldig paginanummer in.")
                    pause()
            elif choice == 'a':
                show_all_logs(logs)
            elif choice == 's':
                show_suspicious_logs_only(suspicious_logs)
            else:
                print("❌ Ongeldige keuze.")
                pause()
    
    except Exception as e:
        print(f"❌ Fout bij ophalen logs: {e}")
        pause()

def show_all_logs(logs):
    """Show all logs without pagination"""
    clear_screen()
    show_header("Alle Systeem Logs")
    
    print(f"📋 Totaal {len(logs)} logs:\n")
    
    # Define column widths - ZONDER Info kolom
    base_widths = [3, 12, 8, 15, 35, 8]
    widths = adjust_table_widths_for_terminal(base_widths)
    headers = ['Nr', 'Datum', 'Tijd', 'Gebruiker', 'Beschrijving', 'Verdacht']
    
    show_table_header(headers, widths)
    
    for i, log in enumerate(logs, 1):
        # Split timestamp into date and time
        timestamp_parts = log['timestamp'][:19].split('T') if log['timestamp'] else ['...', '...']
        date_part = timestamp_parts[0] if len(timestamp_parts) > 0 and timestamp_parts[0] else "..."
        time_part = timestamp_parts[1] if len(timestamp_parts) > 1 and timestamp_parts[1] else "..."
        
        username_display = log['username'] if log['username'] and log['username'].strip() else "..."
        description = log['description'] if log['description'] and log['description'].strip() else "..."
        suspicious = "Ja" if log['suspicious'] else "Nee"
        
        values = [i, date_part, time_part, username_display, description, suspicious]
        print(format_table_row(values, widths))
    
    show_table_footer(widths)
    print(f"\n📊 Overzicht: {len(logs)} logs getoond")
    pause()

def show_suspicious_logs_only(suspicious_logs):
    """Show only suspicious logs"""
    clear_screen()
    show_header("Verdachte Activiteiten")
    
    if not suspicious_logs:
        print("✅ Geen verdachte activiteiten gevonden.")
        pause()
        return
    
    print(f"⚠️  {len(suspicious_logs)} verdachte activiteiten gevonden:\n")
    
    # Define column widths - ZONDER Info kolom
    base_widths = [3, 12, 8, 15, 35, 8]
    widths = adjust_table_widths_for_terminal(base_widths)
    headers = ['Nr', 'Datum', 'Tijd', 'Gebruiker', 'Beschrijving', 'Verdacht']
    
    show_table_header(headers, widths)
    
    for i, log in enumerate(suspicious_logs, 1):
        # Split timestamp into date and time
        timestamp_parts = log['timestamp'][:19].split('T') if log['timestamp'] else ['...', '...']
        date_part = timestamp_parts[0] if len(timestamp_parts) > 0 and timestamp_parts[0] else "..."
        time_part = timestamp_parts[1] if len(timestamp_parts) > 1 and timestamp_parts[1] else "..."
        
        username_display = log['username'] if log['username'] and log['username'].strip() else "..."
        description = log['description'] if log['description'] and log['description'].strip() else "..."
        suspicious = "Ja"  # All logs in this function are suspicious
        
        values = [i, date_part, time_part, username_display, description, suspicious]
        print(format_table_row(values, widths))
    
    show_table_footer(widths)
    print(f"\n⚠️  Totaal {len(suspicious_logs)} verdachte activiteiten")
    pause()

# ============================================================================
# PASSWORD CHANGE FUNCTION
# ============================================================================

def change_password_menu(username: str, role: str):
    """Change user password"""
    clear_screen()
    show_header("Wachtwoord Wijzigen")

    if username == 'super_admin':
        print("⚠️  Super admin wachtwoord kan niet gewijzigd worden.")
        pause()
        return

    try:
        # FIX: Use getpass for password masking
        old_password = getpass.getpass("Huidig wachtwoord: ")
        if check_back_command(old_password):
            return

        # FIX: Max 3 attempts for new password validation
        max_attempts = 3
        new_password = None
        for attempt in range(1, max_attempts + 1):
            print(f"\nNieuw wachtwoord (poging {attempt}/{max_attempts})")
            temp_new_password = getpass.getpass("Nieuw wachtwoord: ")

            if check_back_command(temp_new_password):
                return

            if validate_password(temp_new_password):
                new_password = temp_new_password
                break
            else:
                print("❌ Nieuw wachtwoord voldoet niet aan eisen (12-30 tekens, complex)")
                if attempt < max_attempts:
                    print(f"Probeer opnieuw. Nog {max_attempts - attempt} poging(en).")
                else:
                    print("❌ Maximum aantal pogingen bereikt.")
                    pause()
                    return

        # FIX: Use getpass for confirmation
        confirm_password = getpass.getpass("Bevestig nieuw wachtwoord: ")
        if check_back_command(confirm_password):
            return

        if new_password != confirm_password:
            print("❌ Wachtwoorden komen niet overeen.")
            pause()
            return

        success, message = change_own_password(username, old_password, new_password)
        if success:
            print(f"\n✅ {message}")
        else:
            print(f"\n❌ {message}")
    except Exception as e:
        print(f"❌ Fout bij wijzigen wachtwoord: {e}")

    pause()

# ============================================================================
# STATISTICS FUNCTION
# ============================================================================

def show_statistics_menu():
    """Show system statistics in formatted layout"""
    clear_screen()
    show_header("Systeem Statistieken")
    
    try:
        travellers = get_all_travellers()
        scooters = get_all_scooters()
        users = get_all_users()
        
        print("📊 ALGEMEEN OVERZICHT")
        print("=" * 50)
        print(f"👥 Totaal aantal gebruikers:     {len(users):>8}")
        print(f"🧳 Totaal aantal reizigers:      {len(travellers):>8}")
        print(f"🛴 Totaal aantal scooters:       {len(scooters):>8}")
        
        if scooters:
            in_service = sum(1 for s in scooters if not s['out_of_service_status'])
            out_of_service = len(scooters) - in_service
            avg_battery = sum(s['state_of_charge'] for s in scooters) / len(scooters)
            total_mileage = sum(s['mileage'] for s in scooters)
            avg_mileage = total_mileage / len(scooters)
            
            print(f"\n🛴 SCOOTER STATISTIEKEN")
            print("=" * 50)
            print(f"✅ Scooters in dienst:           {in_service:>8}")
            print(f"❌ Scooters buiten dienst:       {out_of_service:>8}")
            print(f"🔋 Gemiddelde batterijlading:    {avg_battery:>7.1f}%")
            print(f"🛣️  Totale kilometerstand:       {total_mileage:>7.1f} km")
            print(f"📊 Gemiddelde km per scooter:    {avg_mileage:>7.1f} km")
            
            # Battery status distribution
            low_battery = sum(1 for s in scooters if s['state_of_charge'] < 20)
            medium_battery = sum(1 for s in scooters if 20 <= s['state_of_charge'] < 80)
            high_battery = sum(1 for s in scooters if s['state_of_charge'] >= 80)
            
            print(f"\n🔋 BATTERIJ VERDELING")
            print("=" * 50)
            print(f"🔴 Laag (< 20%):                 {low_battery:>8}")
            print(f"🟡 Gemiddeld (20-80%):           {medium_battery:>8}")
            print(f"🟢 Hoog (> 80%):                 {high_battery:>8}")
        
        if travellers:
            cities = {}
            for t in travellers:
                cities[t['city']] = cities.get(t['city'], 0) + 1
            
            print(f"\n🏙️  REIZIGERS PER STAD")
            print("=" * 50)
            for city, count in sorted(cities.items(), key=lambda x: x[1], reverse=True):
                print(f"{city:<25} {count:>8}")
        
        # User role distribution
        if users:
            roles = {}
            for u in users:
                role_name = {
                    'super_admin': 'Super Administrator',
                    'system_admin': 'System Administrator', 
                    'service_engineer': 'Service Engineer'
                }.get(u['role'], u['role'])
                roles[role_name] = roles.get(role_name, 0) + 1
            
            print(f"\n👤 GEBRUIKERS PER ROL")
            print("=" * 50)
            for role, count in sorted(roles.items()):
                print(f"{role:<25} {count:>8}")
        
        # Show backup information
        try:
            stats = get_backup_statistics()
            if stats['total_backups'] > 0:
                print(f"\n💾 BACKUP INFORMATIE")
                print("=" * 50)
                print(f"Aantal backups:               {stats['total_backups']:>8}")
                print(f"Totale grootte:               {stats['total_size_mb']:>7.1f} MB")
                print(f"Nieuwste backup:              {stats['newest_backup']}")
        except:
            pass  # Skip if backup info not available
        
    except Exception as e:
        print(f"❌ Fout bij ophalen statistieken: {e}")
    
    pause()

# ============================================================================
# MAIN APPLICATION LOOP
# ============================================================================

def main():
    """Main application function"""
    # Initialize database
    print("🚀 Urban Mobility Backend System wordt gestart...")
    
    try:
        init_db()
        print("✅ Database geïnitialiseerd")
    except Exception as e:
        print(f"❌ Fout bij database initialisatie: {e}")
        sys.exit(1)
    
    while True:
        clear_screen()
        show_header("Urban Mobility Backend System - Inloggen", False)

        print("🔐 Voor demonstratie doeleinden:")
        print("   Username: super_admin")
        print("   Password: Admin_123?")
        print()
        print("1. Inloggen")
        print("2. Afsluiten")

        choice = input("\nKies een optie (1-2): ")

        if choice == "1":
            # FIX: Max 3 login attempts
            max_login_attempts = 3
            login_success = False

            for attempt in range(1, max_login_attempts + 1):
                print(f"\n📝 Login poging {attempt}/{max_login_attempts}")

                username = input("Gebruikersnaam: ").strip()
                if not username:
                    print("❌ Gebruikersnaam is verplicht")
                    if attempt < max_login_attempts:
                        print(f"Nog {max_login_attempts - attempt} poging(en).")
                        continue
                    else:
                        print("❌ Maximum aantal pogingen bereikt.")
                        log_event("Max login attempts - empty username", "", "Meerdere lege gebruikersnaam pogingen", suspicious=True)
                        pause()
                        break

                # FIX: Use getpass for password masking
                password = getpass.getpass("Wachtwoord: ")
                if not password:
                    print("❌ Wachtwoord is verplicht")
                    if attempt < max_login_attempts:
                        print(f"Nog {max_login_attempts - attempt} poging(en).")
                        continue
                    else:
                        print("❌ Maximum aantal pogingen bereikt.")
                        log_event("Max login attempts - empty password", "", "Meerdere lege wachtwoord pogingen", suspicious=True)
                        pause()
                        break

                result = login(username, password)
                if result:
                    role, actual_username = result
                    print(f"\n✅ Welkom {actual_username}!")
                    print(f"🎭 Rol: {role}")
                    pause()
                    login_success = True
                    break  # Exit login loop
                else:
                    print("\n❌ Login mislukt. Controleer gebruikersnaam en wachtwoord.")
                    if attempt < max_login_attempts:
                        print(f"🔄 Probeer het opnieuw. Nog {max_login_attempts - attempt} poging(en).")
                    else:
                        print("❌ Maximum aantal login pogingen bereikt.")
                        log_event("Max login attempts exceeded", "", f"Laatste poging gebruikersnaam: {username}", suspicious=True)
                        pause()

            # If login successful, enter main menu
            if login_success:
                # Main menu loop
                while True:
                    action = show_main_menu(actual_username, role)
                    
                    if action == "logout":
                        log_event(f"Uitgelogd", actual_username)
                        print("👋 Tot ziens!")
                        break
                    elif action == "exit":
                        print("👋 Tot ziens!")
                        sys.exit(0)
                    elif action == "user_management":
                        result = user_management_menu(actual_username, role)
                        if result == "force_logout":
                            break  # Exit to login screen
                    elif action == "traveller_management":
                        traveller_management_menu(actual_username, role)
                    elif action == "scooter_management":
                        scooter_management_menu(actual_username, role)
                    elif action == "search_scooters":
                        search_scooters_menu()
                    elif action == "update_scooter_info":
                        update_scooter_menu(actual_username, role)
                    elif action == "view_logs":
                        view_logs_menu(actual_username, role)
                    elif action == "backup_management":
                        backup_management_menu(actual_username, role)
                    elif action == "restore_code_management":
                        restore_code_management_menu(actual_username, role)
                    elif action == "change_password":
                        change_password_menu(actual_username, role)
                    elif action == "show_statistics":
                        show_statistics_menu()
                    else:
                        print(f"❌ Functie '{action}' nog niet geïmplementeerd.")
                        pause()
            else:
                print("\n❌ Login mislukt. Controleer gebruikersnaam en wachtwoord.")
                print("🔄 Probeer het opnieuw...")
                pause()
        
        elif choice == "2":
            print("👋 Tot ziens!")
            sys.exit(0)
        else:
            print("❌ Ongeldige keuze. Kies 1 of 2.")
            pause()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n🛑 Programma beëindigd door gebruiker.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Onverwachte fout: {e}")
        print("🔧 Controleer of alle bestanden correct zijn en dependencies geïnstalleerd zijn.")
        print("📦 Run: pip install bcrypt cryptography")
        sys.exit(1)