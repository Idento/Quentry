#!/usr/bin/env python3
"""
Quentry Backup Recovery Script (Open Source)
Version 2.2

This script allows you to decrypt and recover your Quentry notes
from backup files (.qb) after uninstalling the app.

Security Implementation:
    - AES-256-CTR encryption
    - HMAC-SHA256 authentication (Encrypt-then-MAC)
    - PBKDF2-HMAC-SHA256 key derivation (600,000 iterations for v2.1+)

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
import re
import sys
import hmac
import hashlib
import base64
import unicodedata
from datetime import datetime
from getpass import getpass
from typing import Optional, Tuple

# A Windows console or a redirected output may not know « ✓ » or accents: replace them
# instead of stopping the recovery halfway.
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(errors='replace')

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
PBKDF2_ITERATIONS = 600000  # Default for v2.1+, older backups store their own value
KEY_LENGTH = 32  # 256 bits
NONCE_LENGTH = 12  # 96 bits


def pbkdf2_derive(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Derive key using standard PBKDF2-HMAC-SHA256.
    Returns 64 bytes: 32 for encryption, 32 for MAC.
    Used for backups produced by quick-crypto (OpenSSL): versions 3.x.
    """
    return PBKDF2(
        password.encode('utf-8'),
        salt,
        dkLen=64,
        count=iterations,
        prf=lambda p, s: HMAC.new(p, s, SHA256).digest()
    )


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Standard HMAC-SHA256 over raw bytes."""
    return hmac.new(key, data, hashlib.sha256).digest()


# ============================================================================
# LEGACY MODE: reproduces the pure-JS implementation exactly
#
# Older versions of the app (backups with v: "2.x") used a pure-JS HMAC that
# went through expo-crypto's digestStringAsync. That function takes a STRING
# and hashes its UTF-8 byte representation, so the JS code passed
# bytesToHex(data) and ended up hashing the hex-string of the bytes rather
# than the bytes themselves. The result is a non-standard HMAC, and PBKDF2
# built on top of it inherits the same property.
#
# Backups produced before the migration to quick-crypto need this code path.
# Backups produced after use the standard pycryptodome implementation above.
# ============================================================================

def hmac_sha256_legacy(key: bytes, data: bytes) -> bytes:
    """Reproduces pure-JS HMAC-SHA256 that hashed the hex-string of bytes."""
    block_size = 64

    key_prime = key
    if len(key) > block_size:
        # SHA256 of the hex-string of the key (UTF-8 encoded)
        key_prime = hashlib.sha256(key.hex().encode('utf-8')).digest()

    padded = bytearray(block_size)
    padded[:len(key_prime)] = key_prime

    ipad = bytes(b ^ 0x36 for b in padded)
    opad = bytes(b ^ 0x5c for b in padded)

    inner_data = ipad + data
    inner_hash = hashlib.sha256(inner_data.hex().encode('utf-8')).digest()

    outer_data = opad + inner_hash
    outer_hash = hashlib.sha256(outer_data.hex().encode('utf-8')).digest()

    return outer_hash


def pbkdf2_derive_legacy(password: str, salt: bytes, iterations: int) -> bytes:
    """Reproduces pure-JS PBKDF2 built on top of the legacy HMAC."""
    password_bytes = password.encode('utf-8')
    hash_length = 32
    key_length = 64
    num_blocks = (key_length + hash_length - 1) // hash_length

    derived = bytearray(key_length)

    for block_index in range(1, num_blocks + 1):
        block_bytes = block_index.to_bytes(4, 'big')
        u = hmac_sha256_legacy(password_bytes, salt + block_bytes)
        result = bytearray(u)

        for _ in range(2, iterations + 1):
            u = hmac_sha256_legacy(password_bytes, u)
            for j in range(len(result)):
                result[j] ^= u[j]

        offset = (block_index - 1) * hash_length
        length = min(hash_length, key_length - offset)
        derived[offset:offset + length] = result[:length]

    return bytes(derived)


def aes_ctr_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    AES-256-CTR decryption.
    Must match JavaScript implementation exactly:
    - 12-byte nonce in bytes [0-11]
    - 4-byte big-endian counter in bytes [12-15], starting at 0
    """
    # Create initial counter block: nonce (12 bytes) + counter starting at 0 (4 bytes)
    initial_counter = nonce + b'\x00\x00\x00\x00'
    
    # Use initial_value parameter with big-endian counter
    cipher = AES.new(
        key, 
        AES.MODE_CTR, 
        initial_value=initial_counter,
        nonce=b''  # Empty nonce since we include it in initial_value
    )
    return cipher.decrypt(ciphertext)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def _try_decrypt(
    pin: str,
    salt: bytes,
    nonce: bytes,
    ciphertext: bytes,
    stored_tag: bytes,
    iterations: int,
    legacy: bool,
) -> Optional[bytes]:
    """Attempt to decrypt with either standard or legacy HMAC/PBKDF2.
    Returns plaintext bytes on success, None on auth failure."""
    if legacy:
        derived_key = pbkdf2_derive_legacy(pin, salt, iterations)
        mac_fn = hmac_sha256_legacy
    else:
        derived_key = pbkdf2_derive(pin, salt, iterations)
        mac_fn = hmac_sha256

    enc_key = derived_key[:32]
    mac_key = derived_key[32:64]

    computed_tag = mac_fn(mac_key, nonce + ciphertext)
    if not constant_time_compare(stored_tag, computed_tag):
        return None

    return aes_ctr_decrypt(ciphertext, enc_key, nonce)


def decrypt_backup(encrypted_json: str, pin: str) -> Optional[str]:
    """
    Decrypt a Quentry backup file.

    The backup format is JSON with fields:
    - v: version (3.x = quick-crypto, 2.x = legacy pure-JS)
    - s: salt (base64)
    - n: nonce (base64)
    - c: ciphertext (base64)
    - t: auth tag (base64)
    - i: iterations

    Tries both standard (pycryptodome / OpenSSL-compatible) and legacy
    (pure-JS reproduction) modes, regardless of the version header: older
    builds did not always set v correctly, so probing both is the only
    reliable way to recover.
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

        # Heuristic: v >= 3.0 is most likely standard, but we always have a
        # second attempt available so the order only affects error messages
        # and timing on the wrong-PIN case.
        try_standard_first = not str(version).startswith('2.')

        attempts = (
            [(False, "standard (OpenSSL-compatible)"), (True, "legacy pure-JS")]
            if try_standard_first
            else [(True, "legacy pure-JS"), (False, "standard (OpenSSL-compatible)")]
        )

        for legacy, label in attempts:
            print(f"Trying {label} mode (deriving key, this may take a moment)...")
            plaintext = _try_decrypt(pin, salt, nonce, ciphertext, stored_tag, iterations, legacy)
            if plaintext is not None:
                print(f"✓ Authentication successful ({label})")
                return plaintext.decode('utf-8')

        print("\n❌ Authentication failed in both modes: wrong PIN or corrupted file")
        return None

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


def _slugify_name(name: str, fallback: str) -> str:
    """Slugify a template name: strip diacritics, lowercase, non-alphanum → '-'."""
    if not isinstance(name, str) or not name.strip():
        return fallback
    nfkd = unicodedata.normalize('NFKD', name)
    ascii_str = ''.join(c for c in nfkd if not unicodedata.combining(c))
    slug = re.sub(r'[^A-Za-z0-9]+', '-', ascii_str).strip('-').lower()
    return slug or fallback


def _escape_html_text(value) -> str:
    """Escape text for safe inclusion in an HTML comment / body."""
    if value is None:
        return ''
    s = str(value)
    return (
        s.replace('&', '&amp;')
         .replace('<', '&lt;')
         .replace('>', '&gt;')
    )


def save_templates(backup_data: dict, output_dir: str) -> int:
    """
    Save decrypted templates (v2.2+ backups) to individual HTML files plus a
    combined templates.json. Returns number of templates saved.

    Backups produced by app versions ≤ 2.1 don't include the `templates` field,
    in which case nothing is written.
    """
    templates = backup_data.get('templates')
    if not isinstance(templates, list) or not templates:
        return 0

    # Sort by sortOrder to mirror the in-app display order
    sorted_templates = sorted(
        templates,
        key=lambda t: t.get('sortOrder', 0) if isinstance(t, dict) else 0
    )

    templates_dir = os.path.join(output_dir, 'templates')
    os.makedirs(templates_dir, exist_ok=True)

    # Combined JSON next to all_entries.json at the root of output_dir
    json_path = os.path.join(output_dir, 'templates.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(sorted_templates, f, ensure_ascii=False, indent=2)
    print(f"✓ Saved combined JSON: {json_path}")

    used_slugs = set()
    for i, tpl in enumerate(sorted_templates, 1):
        name = tpl.get('name', '') if isinstance(tpl, dict) else ''
        description = tpl.get('description', '') if isinstance(tpl, dict) else ''
        content = tpl.get('content', '') if isinstance(tpl, dict) else ''
        builtin = bool(tpl.get('builtin', False)) if isinstance(tpl, dict) else False
        created_at = tpl.get('createdAt', '') if isinstance(tpl, dict) else ''
        updated_at = tpl.get('updatedAt', '') if isinstance(tpl, dict) else ''

        base_slug = _slugify_name(name, f'template-{i}')
        slug = base_slug
        suffix = 2
        while slug in used_slugs:
            slug = f'{base_slug}-{suffix}'
            suffix += 1
        used_slugs.add(slug)

        filename = f'{slug}.html'
        filepath = os.path.join(templates_dir, filename)

        header_comment = (
            '<!--\n'
            f'  Name: {_escape_html_text(name)}\n'
            f'  Description: {_escape_html_text(description)}\n'
            f'  Built-in: {"yes" if builtin else "no"}\n'
            f'  Created: {_escape_html_text(created_at)}\n'
            f'  Updated: {_escape_html_text(updated_at)}\n'
            '-->\n'
        )

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(header_comment)
            f.write(content if isinstance(content, str) else '')

        print(f"  ✓ templates/{filename}")

    return len(sorted_templates)


def save_trash(backup_data: dict, output_dir: str) -> int:
    """
    Save the 30-day trash (backups v2.3+, 15/11/2026) to output_dir/corbeille/:
    one TXT per deleted note plus trash.json. Older backups have no 'trash'
    field: nothing is created. Returns the number of deleted notes saved.
    """
    trash = backup_data.get('trash')
    if not isinstance(trash, list):
        return 0
    valid = [n for n in trash if isinstance(n, dict) and isinstance(n.get('content'), str)
             and isinstance(n.get('deletedAt'), str)]
    if not valid:
        return 0

    trash_dir = os.path.join(output_dir, 'corbeille')
    os.makedirs(trash_dir, exist_ok=True)
    with open(os.path.join(trash_dir, 'trash.json'), 'w', encoding='utf-8') as f:
        json.dump(valid, f, ensure_ascii=False, indent=2)

    for i, note in enumerate(valid, 1):
        created_at = note.get('createdAt', 'unknown')
        category = note.get('category', 'prive')
        try:
            dt = datetime.fromisoformat(str(created_at).replace('Z', '+00:00'))
            date_str = dt.strftime('%Y-%m-%d_%H-%M')
        except ValueError:
            date_str = f'deleted_{i}'
        filename = f"{date_str}_{category}_{i}.txt"
        with open(os.path.join(trash_dir, filename), 'w', encoding='utf-8') as f:
            f.write(f"Date: {created_at}\n")
            f.write(f"Deleted: {note['deletedAt']}\n")
            f.write(f"Category: {category}\n")
            f.write("-" * 40 + "\n\n")
            f.write(note['content'])
        print(f"  ✓ corbeille/{filename}")

    return len(valid)


def main():
    """Main entry point."""
    print("=" * 60)
    print("  Quentry Backup Recovery Tool v2.3")
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

    # Save templates (v2.2+ backups only ; absent or empty list = silent no-op)
    templates_count = save_templates(backup_data, output_dir)

    # Save trash (v2.3+ backups only ; absent = silent no-op)
    trash_count = save_trash(backup_data, output_dir)

    print()
    print("=" * 60)
    extras = []
    if templates_count:
        extras.append(f"{templates_count} templates")
    if trash_count:
        extras.append(f"{trash_count} deleted notes (corbeille/)")
    suffix = (" + " + " + ".join(extras)) if extras else ""
    print(f"✅ Recovery complete! {count} entries{suffix} saved to: {output_dir}")
    print("=" * 60)


if __name__ == '__main__':
    main()
