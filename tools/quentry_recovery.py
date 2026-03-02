#!/usr/bin/env python3
"""
Quentry Backup Recovery Script (Open Source)
Version 2.1

This script allows you to decrypt and recover your Quentry notes
from backup files (.qb) after uninstalling the app.

Security Implementation:
    - AES-256-CTR encryption
    - HMAC-SHA256 authentication (Encrypt-then-MAC)
    - PBKDF2-HMAC-SHA256 key derivation (310,000 iterations)

Requirements:
    - Python 3.7+
    - pycryptodome (pip install pycryptodome)

Usage:
    python quentry_recovery.py backup.qb

    You will be prompted for your backup PIN.
    Recovered notes will be saved to JSON and individual TXT files.

License: MIT
"""

import json
import os
import sys
import hmac
import hashlib
import base64
from datetime import datetime
from getpass import getpass
from typing import Optional, Tuple

# Check for cryptography module
try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256, HMAC
except ImportError:
    print("Error: pycryptodome is required")
    print("Install with: pip install pycryptodome")
    sys.exit(1)


# Constants - must match the app's implementation
PBKDF2_ITERATIONS = 310000
KEY_LENGTH = 32  # 256 bits
NONCE_LENGTH = 12  # 96 bits


def pbkdf2_derive(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Derive key using PBKDF2-HMAC-SHA256.
    Returns 64 bytes: 32 for encryption, 32 for MAC.
    """
    return PBKDF2(
        password.encode('utf-8'),
        salt,
        dkLen=64,
        count=iterations,
        prf=lambda p, s: HMAC.new(p, s, SHA256).digest()
    )


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256."""
    return hmac.new(key, data, hashlib.sha256).digest()


def aes_ctr_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    AES-256-CTR decryption.
    """
    # CTR mode with 12-byte nonce + 4-byte counter
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def decrypt_backup(encrypted_json: str, pin: str) -> Optional[str]:
    """
    Decrypt Quentry backup file.
    
    The backup format is JSON with fields:
    - v: version
    - s: salt (base64)
    - n: nonce (base64)
    - c: ciphertext (base64)
    - t: auth tag (base64)
    - i: iterations
    
    Returns decrypted JSON string or None if decryption fails.
    """
    try:
        data = json.loads(encrypted_json)
        
        version = data.get('v', '2.0')
        salt = base64.b64decode(data['s'])
        nonce = base64.b64decode(data['n'])
        ciphertext = base64.b64decode(data['c'])
        stored_tag = base64.b64decode(data['t'])
        iterations = data.get('i', PBKDF2_ITERATIONS)
        
        print(f"Backup version: {version}")
        print(f"PBKDF2 iterations: {iterations:,}")
        print("Deriving key (this may take a moment)...")
        
        # Derive key
        derived_key = pbkdf2_derive(pin, salt, iterations)
        enc_key = derived_key[:32]
        mac_key = derived_key[32:64]
        
        # Verify HMAC first (Encrypt-then-MAC)
        computed_tag = hmac_sha256(mac_key, nonce + ciphertext)
        
        if not constant_time_compare(stored_tag, computed_tag):
            print("\n❌ Authentication failed: Wrong PIN or corrupted file")
            return None
        
        print("✓ Authentication successful")
        
        # Decrypt
        plaintext = aes_ctr_decrypt(ciphertext, enc_key, nonce)
        
        return plaintext.decode('utf-8')
        
    except json.JSONDecodeError:
        print("Error: Invalid backup file format")
        return None
    except KeyError as e:
        print(f"Error: Missing field in backup: {e}")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None


def save_entries(backup_data: dict, output_dir: str) -> int:
    """
    Save decrypted entries to individual files.
    Returns number of entries saved.
    """
    entries = backup_data.get('entries', [])
    
    if not entries:
        print("No entries found in backup")
        return 0
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Save combined JSON
    json_path = os.path.join(output_dir, 'all_entries.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)
    print(f"✓ Saved combined JSON: {json_path}")
    
    # Save individual TXT files
    for i, entry in enumerate(entries, 1):
        # Support both 'content' (new) and 'text' (old) field names
        content = entry.get('content') or entry.get('text', '')
        created_at = entry.get('createdAt', 'unknown')
        category = entry.get('category', 'prive')
        
        # Create filename from date
        try:
            dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            date_str = dt.strftime('%Y-%m-%d_%H-%M')
        except:
            date_str = f'entry_{i}'
        
        filename = f"{date_str}_{category}.txt"
        filepath = os.path.join(output_dir, filename)
        
        # Write entry
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"Date: {created_at}\n")
            f.write(f"Category: {category}\n")
            f.write("-" * 40 + "\n\n")
            f.write(content)
        
        print(f"  ✓ {filename}")
    
    return len(entries)


def main():
    """Main entry point."""
    print("=" * 60)
    print("  Quentry Backup Recovery Tool v2.1")
    print("  Security: AES-256-CTR + HMAC-SHA256 + PBKDF2")
    print("=" * 60)
    print()
    
    # Check arguments
    if len(sys.argv) < 2:
        print("Usage: python quentry_recovery.py <backup.qb>")
        print()
        print("Example: python quentry_recovery.py quentry-20240115.qb")
        sys.exit(1)
    
    backup_path = sys.argv[1]
    
    # Verify file exists
    if not os.path.exists(backup_path):
        print(f"Error: File not found: {backup_path}")
        sys.exit(1)
    
    print(f"Backup file: {backup_path}")
    print()
    
    # Read backup file
    with open(backup_path, 'r', encoding='utf-8') as f:
        encrypted_data = f.read()
    
    # Get PIN
    pin = getpass("Enter backup PIN: ")
    if not pin:
        print("Error: PIN is required")
        sys.exit(1)
    
    print()
    
    # Decrypt
    decrypted = decrypt_backup(encrypted_data, pin)
    
    if decrypted is None:
        sys.exit(1)
    
    try:
        backup_data = json.loads(decrypted)
    except json.JSONDecodeError:
        print("Error: Decrypted data is not valid JSON")
        sys.exit(1)
    
    # Show metadata
    metadata = backup_data.get('metadata', {})
    print()
    print("Backup Metadata:")
    print(f"  Version: {metadata.get('version', 'unknown')}")
    print(f"  Created: {metadata.get('createdAt', 'unknown')}")
    print(f"  Entries: {metadata.get('entriesCount', 0)}")
    if metadata.get('dateRange'):
        dr = metadata['dateRange']
        print(f"  Date range: {dr.get('from', '?')} → {dr.get('to', '?')}")
    print()
    
    # Create output directory
    backup_name = os.path.splitext(os.path.basename(backup_path))[0]
    output_dir = f"recovered_{backup_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Save entries
    count = save_entries(backup_data, output_dir)
    
    print()
    print("=" * 60)
    print(f"✅ Recovery complete! {count} entries saved to: {output_dir}")
    print("=" * 60)


if __name__ == '__main__':
    main()
