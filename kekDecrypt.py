#!/usr/bin/env python3
"""
NetScaler ns.conf decryption tool:
- Processes entire ns.conf files
- Searches for -kek flags and extracts encrypted strings
- Decrypts using F1 and F2 keys with the correct NetScaler method
- Extract F1[34-65] and F2[36-67] (32 bytes each)
- Use HMAC-SHA256(key=F2, message=F1) to create KEK
- Decrypt using AES-256-CBC with embedded IV
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import hmac
import re
import sys
import argparse

def read_file(filename):
    """Read file content as string"""
    with open(filename, 'r') as f:
        return f.read().strip()

def hex_to_bytes(hex_string):
    """Convert hex string to bytes"""
    return bytes.fromhex(hex_string)

def netscaler_kek_derivation(f1_hex, f2_hex, verbose=False):
    """NetScaler KEK derivation using the correct byte ranges and HMAC-SHA256"""
    f1_bytes = hex_to_bytes(f1_hex)
    f2_bytes = hex_to_bytes(f2_hex)
    
    # Use the correct NetScaler method: F1[34-65], F2[36-67] (32 bytes each)
    # HMAC-SHA256(key=F2[36-67], message=F1[34-65])
    
    if len(f1_bytes) < 65:
        raise ValueError(f"F1 key too short: {len(f1_bytes)} bytes, need at least 65")
    if len(f2_bytes) < 67:
        raise ValueError(f"F2 key too short: {len(f2_bytes)} bytes, need at least 67")
    
    f1_segment = f1_bytes[33:65]  # F1[34-65] in 1-based indexing = [33:65] in 0-based
    f2_segment = f2_bytes[35:67]  # F2[36-67] in 1-based indexing = [35:67] in 0-based
    
    if verbose:
        print(f"F1 segment [34-65]: {f1_segment.hex()} ({len(f1_segment)} bytes)")
        print(f"F2 segment [36-67]: {f2_segment.hex()} ({len(f2_segment)} bytes)")
    
    # Create KEK using HMAC-SHA256(key=F2, message=F1)
    kek = hmac.new(f2_segment, f1_segment, hashlib.sha256).digest()
    
    if verbose:
        print(f"KEK: {kek.hex()}")
    
    return kek

def netscaler_decrypt_aes_cbc(encrypted_data, kek, verbose=False):
    """NetScaler AES-256-CBC decryption with embedded IV"""
    if len(encrypted_data) != 32:
        if verbose:
            print(f"   Warning: Expected 32 bytes, got {len(encrypted_data)}")
        return None
    
    if len(kek) != 32:
        if verbose:
            print(f"   Warning: KEK should be 32 bytes, got {len(kek)}")
        return None
    
    try:
        # NetScaler uses embedded IV (first 16 bytes)
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        if verbose:
            print(f"   IV: {iv.hex()}")
            print(f"   Ciphertext: {ciphertext.hex()}")
        
        # AES-256-CBC decryption
        cipher = AES.new(kek, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        
        if verbose:
            print(f"   Raw decrypted: {decrypted}")
            print(f"   Raw hex: {decrypted.hex()}")
        
        # NetScaler uses PKCS#7 padding, but try other methods as fallback
        padding_methods = [
            ("PKCS7", lambda x: unpad(x, AES.block_size)),
            ("raw", lambda x: x),
            ("null_strip", lambda x: x.rstrip(b'\x00')),
        ]
        
        for pad_name, pad_func in padding_methods:
            try:
                plaintext = pad_func(decrypted)
                
                # Try UTF-8 first, then ASCII
                for encoding in ['utf-8', 'ascii']:
                    try:
                        text = plaintext.decode(encoding, errors='strict')
                        
                        if verbose:
                            print(f"   {pad_name} + {encoding}: '{text}'")
                        
                        # Return the first successful decryption
                        if text and len(text.strip()) > 0:
                            return text.strip()
                    except:
                        continue
            except Exception as e:
                if verbose:
                    print(f"   {pad_name} padding failed: {e}")
                continue
                
    except Exception as e:
        if verbose:
            print(f"   Decryption failed: {e}")
    
    return None

def find_kek_strings(ns_conf_content):
    """Find all -kek encrypted strings in ns.conf content"""
    # NetScaler can use different formats:
    # 1. -kek followed by hex: -kek hexstring
    # 2. hex followed by -kek: hexstring -kek (more common in real configs)
    # 3. -ldapBindDnPassword hex -encrypted -encryptmethod ENCMTHD_3 -kek
    
    matches = []
    lines = ns_conf_content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        # Pattern 1: -kek followed by hex string
        kek_pattern1 = r'-kek\s+["\']?([a-fA-F0-9]{64})["\']?'
        for match in re.finditer(kek_pattern1, line):
            encrypted_hex = match.group(1)
            matches.append({
                'line_number': line_num,
                'line_content': line.strip(),
                'encrypted_hex': encrypted_hex,
                'start_pos': match.start(),
                'end_pos': match.end(),
                'pattern_type': 'kek_then_hex'
            })
        
        # Pattern 2: hex string followed by -kek (more common in real configs)
        # Look for 64-char hex strings that are followed by -kek somewhere in the line
        hex_pattern = r'\b([a-fA-F0-9]{64})\b'
        for hex_match in re.finditer(hex_pattern, line):
            encrypted_hex = hex_match.group(1)
            # Check if -kek appears after this hex string in the same line
            remaining_line = line[hex_match.end():]
            if '-kek' in remaining_line:
                matches.append({
                    'line_number': line_num,
                    'line_content': line.strip(),
                    'encrypted_hex': encrypted_hex,
                    'start_pos': hex_match.start(),
                    'end_pos': hex_match.end(),
                    'pattern_type': 'hex_then_kek'
                })
    
    # Remove duplicates (same hex string from same line)
    unique_matches = []
    seen = set()
    for match in matches:
        key = (match['line_number'], match['encrypted_hex'])
        if key not in seen:
            seen.add(key)
            unique_matches.append(match)
    
    return unique_matches

def decrypt_kek_string(encrypted_hex, kek, verbose=False):
    """Decrypt a single KEK encrypted string"""
    try:
        encrypted_data = hex_to_bytes(encrypted_hex)
        return netscaler_decrypt_aes_cbc(encrypted_data, kek, verbose)
    except Exception as e:
        if verbose:
            print(f"   Error decrypting {encrypted_hex}: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(
        description='NetScaler ns.conf KEK decryption tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python kekDecrypt.py ns.conf F1.key F2.key
  python kekDecrypt.py ns.conf F1.key F2.key --verbose
  python kekDecrypt.py ns.conf F1.key F2.key --output decrypted.conf
        """
    )
    
    parser.add_argument('ns_conf', help='Path to ns.conf file')
    parser.add_argument('f1_key', help='Path to F1.key file')
    parser.add_argument('f2_key', help='Path to F2.key file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--output', '-o', help='Output file for decrypted ns.conf (optional)')
    
    args = parser.parse_args()
    
    try:
        # Read input files
        print(f"🔍 NetScaler ns.conf KEK Decryption Tool")
        print(f"📁 Reading ns.conf: {args.ns_conf}")
        
        with open(args.ns_conf, 'r', encoding='utf-8', errors='ignore') as f:
            ns_conf_content = f.read()
        
        print(f"🔑 Reading F1 key: {args.f1_key}")
        f1_key = read_file(args.f1_key)
        
        print(f"🔑 Reading F2 key: {args.f2_key}")
        f2_key = read_file(args.f2_key)
        
        print(f"📏 F1 key length: {len(hex_to_bytes(f1_key))} bytes")
        print(f"📏 F2 key length: {len(hex_to_bytes(f2_key))} bytes")
        print()
        
        # Generate KEK using NetScaler's method
        print("🔐 Generating KEK using NetScaler method...")
        kek = netscaler_kek_derivation(f1_key, f2_key, verbose=args.verbose)
        print("✅ KEK generated successfully")
        print()
        
        # Find all -kek encrypted strings
        print("🔍 Searching for -kek encrypted strings...")
        kek_matches = find_kek_strings(ns_conf_content)
        
        if not kek_matches:
            print("❌ No -kek encrypted strings found in ns.conf")
            return
        
        print(f"📋 Found {len(kek_matches)} encrypted string(s)")
        print()
        
        # Decrypt each found string
        decrypted_content = ns_conf_content
        successful_decryptions = 0
        
        for i, match in enumerate(kek_matches, 1):
            print(f"--- String {i} (Line {match['line_number']}) ---")
            if args.verbose:
                print(f"Line: {match['line_content']}")
                print(f"Encrypted: {match['encrypted_hex']}")
            
            # Decrypt the string
            decrypted = decrypt_kek_string(match['encrypted_hex'], kek, verbose=args.verbose)
            
            if decrypted:
                print(f"✅ SUCCESS: '{decrypted}'")
                successful_decryptions += 1
                
                # Replace in content for output file
                if args.output:
                    if match['pattern_type'] == 'kek_then_hex':
                        # Pattern: -kek hexstring
                        old_pattern = f"-kek {match['encrypted_hex']}"
                        new_pattern = f'# DECRYPTED: "{decrypted}" (was -kek {match['encrypted_hex']})'
                        decrypted_content = decrypted_content.replace(old_pattern, new_pattern)
                        
                        # Also try with quotes
                        old_pattern_quoted = f'-kek "{match['encrypted_hex']}"'
                        new_pattern_quoted = f'# DECRYPTED: "{decrypted}" (was -kek "{match['encrypted_hex']}")'
                        decrypted_content = decrypted_content.replace(old_pattern_quoted, new_pattern_quoted)
                    
                    elif match['pattern_type'] == 'hex_then_kek':
                        # Pattern: hexstring ... -kek
                        # Replace just the hex string with a comment
                        old_hex = match['encrypted_hex']
                        new_hex = f'# DECRYPTED_PASSWORD: "{decrypted}" # was: {old_hex}'
                        decrypted_content = decrypted_content.replace(old_hex, new_hex)
            else:
                print(f"❌ FAILED: Could not decrypt")
            
            print()
        
        # Summary
        print("="*60)
        print(f"📊 SUMMARY:")
        print(f"   Total encrypted strings found: {len(kek_matches)}")
        print(f"   Successfully decrypted: {successful_decryptions}")
        print(f"   Failed to decrypt: {len(kek_matches) - successful_decryptions}")
        
        if successful_decryptions == len(kek_matches):
            print(f"🎉 All encrypted strings successfully decrypted!")
        elif successful_decryptions > 0:
            print(f"⚠️  Partial success: {successful_decryptions}/{len(kek_matches)} decrypted")
        else:
            print(f"❌ No strings could be decrypted")
        
        # Write output file if requested
        if args.output:
            print(f"\n💾 Writing decrypted ns.conf to: {args.output}")
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(decrypted_content)
            print(f"✅ Decrypted configuration saved")
            
    except FileNotFoundError as e:
        print(f"❌ File not found: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()