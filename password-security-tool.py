#! python3
"""
Password Security Analysis Tool
A comprehensive tool for password strength analysis, encryption, and security auditing
Author: [mayuresh madane]
Date: 2026
"""

import hashlib
import re
import os
import json
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import requests
import getpass


class PasswordSecurityTool:
    def __init__(self):
        self.key_file = "secret.key"
        self.password_db = "passwords.enc"
        self.setup_encryption()

    def setup_encryption(self):
        """Initialize or load encryption key"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(self.key)
        self.cipher = Fernet(self.key)

    def check_password_strength(self, password):
        """
        Comprehensive password strength analyzer
        Returns score (0-100) and detailed feedback
        """
        score = 0
        feedback = []

        # Length check
        if len(password) >= 12:
            score += 30
            feedback.append("✓ Excellent length (12+ characters)")
        elif len(password) >= 8:
            score += 20
            feedback.append("✓ Good length (8-11 characters)")
        else:
            feedback.append("✗ Password too short (minimum 8 characters recommended)")

        # Uppercase letters
        if re.search(r'[A-Z]', password):
            score += 15
            feedback.append("✓ Contains uppercase letters")
        else:
            feedback.append("✗ Add uppercase letters")

        # Lowercase letters
        if re.search(r'[a-z]', password):
            score += 15
            feedback.append("✓ Contains lowercase letters")
        else:
            feedback.append("✗ Add lowercase letters")

        # Numbers
        if re.search(r'\d', password):
            score += 15
            feedback.append("✓ Contains numbers")
        else:
            feedback.append("✗ Add numbers")

        # Special characters
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 25
            feedback.append("✓ Contains special characters")
        else:
            feedback.append("✗ Add special characters (!@#$%^&*)")

        # Common password check
        common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
        if password.lower() in common_passwords:
            score = max(0, score - 50)
            feedback.append("⚠ WARNING: This is a commonly used password!")

        # Calculate hash for additional checks
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        return {
            'score': min(100, score),
            'feedback': feedback,
            'hash': password_hash,
            'timestamp': datetime.now().isoformat()
        }

    def check_against_breaches(self, password):
        """
        Check if password has been exposed in data breaches
        Uses HaveIBeenPwned API (k-anonymity model)
        """
        try:
            # Hash the password
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]

            # Query HIBP API
            response = requests.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                timeout=5
            )

            if response.status_code == 200:
                hashes = [line.split(':')[0] for line in response.text.splitlines()]
                if suffix in hashes:
                    return {
                        'breached': True,
                        'message': "⚠ Password found in known data breaches! Do NOT use this password."
                    }
                else:
                    return {
                        'breached': False,
                        'message': "✓ Password not found in known breaches (good!)"
                    }
        except Exception:
            return {
                'breached': None,
                'message': "Could not check breach database (offline mode)"
            }

    def generate_strong_password(self, length=16):
        """
        Generate cryptographically strong random password
        """
        import secrets
        import string

        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))

        # Ensure at least one of each type
        while not (re.search(r'[A-Z]', password) and 
                   re.search(r'[a-z]', password) and 
                   re.search(r'\d', password) and 
                   re.search(r'[!@#$%^&*]', password)):
            password = ''.join(secrets.choice(alphabet) for _ in range(length))

        return password

    def encrypt_password(self, service, username, password):
        """
        Securely encrypt and store credentials
        """
        try:
            # Load or create password database
            if os.path.exists(self.password_db):
                with open(self.password_db, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = self.cipher.decrypt(encrypted_data)
                credentials = json.loads(decrypted_data.decode())
            else:
                credentials = {}

            # Add new credential
            entry = {
                'username': username,
                'password': password,
                'created': datetime.now().isoformat()
            }

            if service not in credentials:
                credentials[service] = []
            credentials[service].append(entry)

            # Encrypt and save
            encrypted_data = self.cipher.encrypt(
                json.dumps(credentials, indent=2).encode()
            )
            with open(self.password_db, 'wb') as f:
                f.write(encrypted_data)

            return True
        except Exception as e:
            print(f"Encryption error: {e}")
            return False

    def decrypt_passwords(self):
        """
        Retrieve and decrypt all stored credentials
        """
        try:
            if not os.path.exists(self.password_db):
                return {}

            with open(self.password_db, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = self.cipher.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception:
            return {}

    def run_interactive(self):
        """Interactive command-line interface"""
        while True:
            print("\n" + "="*50)
            print("🔐 PASSWORD SECURITY TOOL")
            print("="*50)
            print("1. Check password strength")
            print("2. Generate strong password")
            print("3. Store encrypted password")
            print("4. View stored passwords")
            print("5. Exit")
            print("-"*50)

            choice = input("Select option (1-5): ").strip()

            if choice == '1':
                password = getpass.getpass("Enter password to analyze: ")

                # Strength analysis
                result = self.check_password_strength(password)
                print(f"\n📊 Password Score: {result['score']}/100")
                print("\nDetailed Feedback:")
                for item in result['feedback']:
                    print(f"  {item}")

                # Breach check
                breach_result = self.check_against_breaches(password)
                print(f"\n🔍 Breach Check: {breach_result['message']}")

                # Save report
                report_file = f"password_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(report_file, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"\n📁 Report saved to {report_file}")

            elif choice == '2':
                length = input("Password length (default 16): ").strip()
                length = int(length) if length.isdigit() else 16
                password = self.generate_strong_password(length)
                print(f"\n🔑 Generated Password: {password}")

                # Auto-analyze the generated password
                result = self.check_password_strength(password)
                print(f"📊 Strength Score: {result['score']}/100")

            elif choice == '3':
                service = input("Service name (e.g., Gmail): ").strip()
                username = input("Username/Email: ").strip()
                password = getpass.getpass("Password: ")

                if self.encrypt_password(service, username, password):
                    print("✅ Password encrypted and stored securely!")
                else:
                    print("❌ Failed to store password")

            elif choice == '4':
                credentials = self.decrypt_passwords()
                if credentials:
                    print("\n📋 Stored Credentials:")
                    for service, entries in credentials.items():
                        print(f"\n  {service}:")
                        for entry in entries:
                            print(f"    - {entry['username']} (added: {entry['created']})")
                            print(f"      Password: {'*' * len(entry['password'])}")
                else:
                    print("No stored credentials found")

            elif choice == '5':
                print("Goodbye! Stay secure! 👋")
                break


if __name__ == "__main__":
    tool = PasswordSecurityTool()
    tool.run_interactive()
#/usr/bin/env python3
"""
Password Security Analysis Tool
A comprehensive tool for password strength analysis, encryption, and security auditing
Author: [Your Name]
Date: 2026
"""

import hashlib
import re
import os
import json
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import requests
import getpass

class PasswordSecurityTool:
    def __init__(self):
        self.key_file = "secret.key"
        self.password_db = "passwords.enc"
        self.setup_encryption()
    
    def setup_encryption(self):
        """Initialize or load encryption key"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(self.key)
        self.cipher = Fernet(self.key)
    
    def check_password_strength(self, password):
        """
        Comprehensive password strength analyzer
        Returns score (0-100) and detailed feedback
        """
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 30
            feedback.append("✓ Excellent length (12+ characters)")
        elif len(password) >= 8:
            score += 20
            feedback.append("✓ Good length (8-11 characters)")
        else:
            feedback.append("✗ Password too short (minimum 8 characters recommended)")
        
        # Uppercase letters
        if re.search(r'[A-Z]', password):
            score += 15
            feedback.append("✓ Contains uppercase letters")
        else:
            feedback.append("✗ Add uppercase letters")
        
        # Lowercase letters
        if re.search(r'[a-z]', password):
            score += 15
            feedback.append("✓ Contains lowercase letters")
        else:
            feedback.append("✗ Add lowercase letters")
        
        # Numbers
        if re.search(r'\d', password):
            score += 15
            feedback.append("✓ Contains numbers")
        else:
            feedback.append("✗ Add numbers")
        
        # Special characters
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 25
            feedback.append("✓ Contains special characters")
        else:
            feedback.append("✗ Add special characters (!@#$%^&*)")
        
        # Common password check
        common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
        if password.lower() in common_passwords:
            score = max(0, score - 50)
            feedback.append("⚠ WARNING: This is a commonly used password!")
        
        # Calculate hash for additional checks
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        return {
            'score': min(100, score),
            'feedback': feedback,
            'hash': password_hash,
            'timestamp': datetime.now().isoformat()
        }
    
    def check_against_breaches(self, password):
        """
        Check if password has been exposed in data breaches
        Uses HaveIBeenPwned API (k-anonymity model)
        """
        try:
            # Hash the password
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Query HIBP API
            response = requests.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                timeout=5
            )
            
            if response.status_code == 200:
                hashes = [line.split(':')[0] for line in response.text.splitlines()]
                if suffix in hashes:
                    return {
                        'breached': True,
                        'message': "⚠ Password found in known data breaches! Do NOT use this password."
                    }
                else:
                    return {
                        'breached': False,
                        'message': "✓ Password not found in known breaches (good!)"
                    }
        except:
            return {
                'breached': None,
                'message': "Could not check breach database (offline mode)"
            }
    
    def generate_strong_password(self, length=16):
        """
        Generate cryptographically strong random password
        """
        import secrets
        import string
        
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        
        # Ensure at least one of each type
        while not (re.search(r'[A-Z]', password) and 
                   re.search(r'[a-z]', password) and 
                   re.search(r'\d', password) and 
                   re.search(r'[!@#$%^&*]', password)):
            password = ''.join(secrets.choice(alphabet) for _ in range(length))
        
        return password
    
    def encrypt_password(self, service, username, password):
        """
        Securely encrypt and store credentials
        """
        try:
            # Load or create password database
            if os.path.exists(self.password_db):
                with open(self.password_db, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = self.cipher.decrypt(encrypted_data)
                credentials = json.loads(decrypted_data.decode())
            else:
                credentials = {}
            
            # Add new credential
            entry = {
                'username': username,
                'password': password,
                'created': datetime.now().isoformat()
            }
            
            if service not in credentials:
                credentials[service] = []
            credentials[service].append(entry)
            
            # Encrypt and save
            encrypted_data = self.cipher.encrypt(
                json.dumps(credentials, indent=2).encode()
            )
            with open(self.password_db, 'wb') as f:
                f.write(encrypted_data)
            
            return True
        except Exception as e:
            print(f"Encryption error: {e}")
            return False
    
    def decrypt_passwords(self):
        """
        Retrieve and decrypt all stored credentials
        """
        try:
            if not os.path.exists(self.password_db):
                return {}
            
            with open(self.password_db, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.cipher.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except:
            return {}
    
    def run_interactive(self):
        """Interactive command-line interface"""
        while True:
            print("\n" + "="*50)
            print("🔐 PASSWORD SECURITY TOOL")
            print("="*50)
            print("1. Check password strength")
            print("2. Generate strong password")
            print("3. Store encrypted password")
            print("4. View stored passwords")
            print("5. Exit")
            print("-"*50)
            
            choice = input("Select option (1-5): ").strip()
            
            if choice == '1':
                password = getpass.getpass("Enter password to analyze: ")
                
                # Strength analysis
                result = self.check_password_strength(password)
                print(f"\n📊 Password Score: {result['score']}/100")
                print("\nDetailed Feedback:")
                for item in result['feedback']:
                    print(f"  {item}")
                
                # Breach check
                breach_result = self.check_against_breaches(password)
                print(f"\n🔍 Breach Check: {breach_result['message']}")
                
                # Save report
                report_file = f"password_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(report_file, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"\n📁 Report saved to {report_file}")
            
            elif choice == '2':
                length = input("Password length (default 16): ").strip()
                length = int(length) if length.isdigit() else 16
                password = self.generate_strong_password(length)
                print(f"\n🔑 Generated Password: {password}")
                
                # Auto-analyze the generated password
                result = self.check_password_strength(password)
                print(f"📊 Strength Score: {result['score']}/100")
            
            elif choice == '3':
                service = input("Service name (e.g., Gmail): ").strip()
                username = input("Username/Email: ").strip()
                password = getpass.getpass("Password: ")
                
                if self.encrypt_password(service, username, password):
                    print("✅ Password encrypted and stored securely!")
                else:
                    print("❌ Failed to store password")
            
            elif choice == '4':
                credentials = self.decrypt_passwords()
                if credentials:
                    print("\n📋 Stored Credentials:")
                    for service, entries in credentials.items():
                        print(f"\n  {service}:")
                        for entry in entries:
                            print(f"    - {entry['username']} (added: {entry['created']})")
                            print(f"      Password: {'*' * len(entry['password'])}")
                else:
                    print("No stored credentials found")
            
            elif choice == '5':
                print("Goodbye! Stay secure! 👋")
                break

if __name__ == "__main__":
    tool = PasswordSecurityTool()
    tool.run_interactive()