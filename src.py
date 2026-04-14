#!/usr/bin/env python3
"""
File Encryption Tool using AES-256-GCM
======================================
A secure file encryption/decryption tool using the cryptography library.
Uses AES-256-GCM for authenticated encryption.


Usage:
    python file_encryptor.py --help
"""

import os
import sys
import argparse
import secrets
import stat
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag


class FileEncryptor:
    """
    Secure file encryption/decryption using AES-256-GCM.
    """

    SALT_SIZE = 32
    NONCE_SIZE = 12
    KEY_SIZE = 32
    ITERATIONS = 480000

    def __init__(self):
        pass

    def generate_key(self):
        """Generate a cryptographically secure random key."""
        return secrets.token_bytes(self.KEY_SIZE)

    def generate_key_file(self, filepath):
        """Generate and save a secure key to a file."""
        key = self.generate_key()
        key_path = Path(filepath)
        key_path.write_bytes(key)
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
        return str(key_path.absolute())

    def derive_key_from_password(self, password, salt):
        """Derive an AES key from a password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.ITERATIONS,
        )
        return kdf.derive(password.encode('utf-8'))

    def encrypt_file(self, input_path, output_path=None, key=None, password=None, delete_original=False):
        """Encrypt a file using AES-256-GCM."""
        input_path = Path(input_path)

        if not input_path.exists():
            raise FileNotFoundError(f"File not found: {input_path}")

        if output_path is None:
            output_path = input_path.with_suffix(input_path.suffix + '.encrypted')
        else:
            output_path = Path(output_path)

        salt = secrets.token_bytes(self.SALT_SIZE)

        if key is not None:
            if len(key) != self.KEY_SIZE:
                raise ValueError(f"Key must be {self.KEY_SIZE} bytes")
        elif password is not None:
            key = self.derive_key_from_password(password, salt)
        else:
            raise ValueError("Either key or password must be provided")

        nonce = secrets.token_bytes(self.NONCE_SIZE)
        plaintext = input_path.read_bytes()
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        with open(output_path, 'wb') as f:
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext)

        if delete_original:
            self.secure_delete(input_path)

        return str(output_path.absolute())

    def decrypt_file(self, input_path, output_path=None, key=None, password=None, delete_encrypted=False):
        """Decrypt a file encrypted with AES-256-GCM."""
        input_path = Path(input_path)

        if not input_path.exists():
            raise FileNotFoundError(f"File not found: {input_path}")

        if output_path is None:
            if input_path.suffix == '.encrypted':
                output_path = input_path.with_suffix('')
            else:
                output_path = input_path.with_suffix(input_path.suffix + '.decrypted')
        else:
            output_path = Path(output_path)

        data = input_path.read_bytes()

        if len(data) < self.SALT_SIZE + self.NONCE_SIZE:
            raise ValueError("Invalid encrypted file format")

        salt = data[:self.SALT_SIZE]
        nonce = data[self.SALT_SIZE:self.SALT_SIZE + self.NONCE_SIZE]
        ciphertext = data[self.SALT_SIZE + self.NONCE_SIZE:]

        if password is not None:
            key = self.derive_key_from_password(password, salt)
        elif key is None:
            raise ValueError("Either key or password must be provided")

        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes")

        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag:
            raise ValueError("Decryption failed: invalid key or corrupted file")

        output_path.write_bytes(plaintext)

        if delete_encrypted:
            self.secure_delete(input_path)

        return str(output_path.absolute())

    def secure_delete(self, filepath, passes=3):
        """Securely delete a file by overwriting with random data before unlinking."""
        filepath = Path(filepath)

        if not filepath.exists():
            return

        file_size = filepath.stat().st_size

        if file_size == 0:
            filepath.unlink()
            return

        with open(filepath, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(secrets.token_bytes(min(file_size, 1024 * 1024)))
                f.flush()
                os.fsync(f.fileno())

        temp_name = filepath.parent / secrets.token_hex(8)
        filepath.rename(temp_name)
        temp_name.unlink()

    def get_file_info(self, filepath):
        """Get information about an encrypted file."""
        filepath = Path(filepath)

        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        stat_info = filepath.stat()

        return {
            'path': str(filepath.absolute()),
            'size': stat_info.st_size,
            'size_human': self._human_readable_size(stat_info.st_size),
            'encrypted': filepath.suffix == '.encrypted',
        }

    def _human_readable_size(self, size_bytes):
        """Convert bytes to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"


def interactive_mode():
    """Interactive CLI for file encryption."""
    encryptor = FileEncryptor()

    print("=" * 60)
    print("FILE ENCRYPTION TOOL")
    print("=" * 60)
    print()
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    print("3. Generate encryption key")
    print("4. Secure delete a file")
    print("5. Exit")
    print()

    choice = input("Select option (1-5): ").strip()

    if choice == '1':
        filepath = input("Enter file path to encrypt: ").strip()
        key_choice = input("Use (k)ey file or (p)assword? [k/p]: ").strip().lower()

        key = None
        password = None

        if key_choice == 'k':
            key_path = input("Enter key file path (leave empty to generate): ").strip()
            if key_path:
                key = Path(key_path).read_bytes()
            else:
                key_path = "encryption.key"
                encryptor.generate_key_file(key_path)
                key = Path(key_path).read_bytes()
                print(f"Generated key saved to: {key_path}")
        else:
            password = input("Enter encryption password: ").strip()

        output_path = input("Output path (leave empty for default): ").strip() or None
        delete = input("Delete original file after encryption? [y/N]: ").strip().lower() == 'y'

        try:
            result = encryptor.encrypt_file(
                filepath,
                output_path=output_path,
                key=key,
                password=password,
                delete_original=delete
            )
            print(f"Encrypted file saved to: {result}")
        except Exception as e:
            print(f"Error: {e}")

    elif choice == '2':
        filepath = input("Enter encrypted file path: ").strip()
        key_choice = input("Use (k)ey file or (p)assword? [k/p]: ").strip().lower()

        key = None
        password = None

        if key_choice == 'k':
            key_path = input("Enter key file path: ").strip()
            key = Path(key_path).read_bytes()
        else:
            password = input("Enter decryption password: ").strip()

        output_path = input("Output path (leave empty for default): ").strip() or None
        delete = input("Delete encrypted file after decryption? [y/N]: ").strip().lower() == 'y'

        try:
            result = encryptor.decrypt_file(
                filepath,
                output_path=output_path,
                key=key,
                password=password,
                delete_encrypted=delete
            )
            print(f"Decrypted file saved to: {result}")
        except Exception as e:
            print(f"Error: {e}")

    elif choice == '3':
        filepath = input("Enter key file name (default: encryption.key): ").strip() or "encryption.key"
        result = encryptor.generate_key_file(filepath)
        print(f"Key saved to: {result}")
        print(f"Keep this file secure! Anyone with this key can decrypt your files.")

    elif choice == '4':
        filepath = input("Enter file path to securely delete: ").strip()
        passes = input("Number of overwrite passes (default: 3): ").strip()
        passes = int(passes) if passes.isdigit() else 3

        confirm = input(f"Are you sure you want to permanently delete {filepath}? [yes/N]: ").strip()
        if confirm.lower() == 'yes':
            try:
                encryptor.secure_delete(filepath, passes=passes)
                print("File securely deleted.")
            except Exception as e:
                print(f"Error: {e}")
        else:
            print("Cancelled.")

    elif choice == '5':
        sys.exit(0)


def main():
    """Command-line interface."""
    parser = argparse.ArgumentParser(
        description='File Encryption Tool - Secure AES-256-GCM encryption',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Generate a new key
    python file_encryptor.py --generate-key mykey.key

    # Encrypt with key file
    python file_encryptor.py -e document.pdf -k mykey.key

    # Encrypt with password
    python file_encryptor.py -e document.pdf -p mypassword

    # Decrypt with key file
    python file_encryptor.py -d document.pdf.encrypted -k mykey.key

    # Encrypt and delete original
    python file_encryptor.py -e document.pdf -k mykey.key --delete-original

    # Secure delete a file
    python file_encryptor.py --secure-delete document.pdf --passes 5
"""
    )

    parser.add_argument('-e', '--encrypt', metavar='FILE',
                        help='File to encrypt')
    parser.add_argument('-d', '--decrypt', metavar='FILE',
                        help='File to decrypt')
    parser.add_argument('-k', '--key-file', metavar='FILE',
                        help='Path to encryption key file')
    parser.add_argument('-p', '--password',
                        help='Encryption/decryption password')
    parser.add_argument('-o', '--output',
                        help='Output file path')
    parser.add_argument('--generate-key', metavar='FILE',
                        help='Generate new encryption key and save to file')
    parser.add_argument('--delete-original', action='store_true',
                        help='Securely delete original file after encryption')
    parser.add_argument('--delete-encrypted', action='store_true',
                        help='Securely delete encrypted file after decryption')
    parser.add_argument('--secure-delete', metavar='FILE',
                        help='Securely delete a file (overwrite then unlink)')
    parser.add_argument('--passes', type=int, default=3,
                        help='Number of overwrite passes for secure delete (default: 3)')
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Run in interactive mode')

    args = parser.parse_args()

    if args.interactive or len(sys.argv) == 1:
        interactive_mode()
        return

    encryptor = FileEncryptor()

    if args.generate_key:
        path = encryptor.generate_key_file(args.generate_key)
        print(f"Generated key saved to: {path}")
        return

    if args.secure_delete:
        try:
            encryptor.secure_delete(args.secure_delete, passes=args.passes)
            print(f"Securely deleted: {args.secure_delete}")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return

    key = None
    if args.key_file:
        key = Path(args.key_file).read_bytes()

    if args.encrypt:
        if not key and not args.password:
            print("Error: Must provide either key file or password", file=sys.stderr)
            sys.exit(1)

        try:
            result = encryptor.encrypt_file(
                args.encrypt,
                output_path=args.output,
                key=key,
                password=args.password,
                delete_original=args.delete_original
            )
            print(f"Encrypted: {result}")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.decrypt:
        if not key and not args.password:
            print("Error: Must provide either key file or password", file=sys.stderr)
            sys.exit(1)

        try:
            result = encryptor.decrypt_file(
                args.decrypt,
                output_path=args.output,
                key=key,
                password=args.password,
                delete_encrypted=args.delete_encrypted
            )
            print(f"Decrypted: {result}")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
