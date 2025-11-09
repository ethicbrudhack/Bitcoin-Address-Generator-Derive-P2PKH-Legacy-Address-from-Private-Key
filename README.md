# 💎 Bitcoin Address Generator — Derive P2PKH (Legacy) Address from Private Key

This Python script demonstrates how to generate a **Bitcoin P2PKH (legacy)** address directly from a **private key `d`** using the **secp256k1** elliptic curve.  
It walks through each cryptographic step manually — from generating the public key to computing the final **Base58Check-encoded address**.

---

## ⚙️ Script Overview

```python
import hashlib
import ecdsa

# Step 1: Compute HASH160 = RIPEMD160(SHA256(data))
def hash160(data):
    sha = hashlib.sha256(data).digest()
    rip = hashlib.new('ripemd160', sha).digest()
    return rip

# Step 2: Encode bytes into Base58 (Bitcoin alphabet)
def base58_encode(b):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(b, byteorder='big')
    result = ''
    while num > 0:
        num, rem = divmod(num, 58)
        result = alphabet[rem] + result
    # Preserve leading zeros as '1's
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return '1' * pad + result

# Step 3: Generate P2PKH Bitcoin address from private key
def generate_address_from_private_key(d):
    # Convert private key (integer) to 32-byte big-endian
    private_key_bytes = d.to_bytes(32, byteorder='big')
    
    # Generate ECDSA key pair using secp256k1
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    
    # Uncompressed public key format: 0x04 || X || Y
    pubkey_bytes = b'\x04' + vk.to_string()
    
    # Compute HASH160 of the public key
    h160 = hash160(pubkey_bytes)
    
    # Add version byte (0x00 for Bitcoin mainnet)
    vh160 = b'\x00' + h160
    
    # Compute checksum (first 4 bytes of double SHA256)
    checksum = hashlib.sha256(hashlib.sha256(vh160).digest()).digest()[:4]
    
    # Concatenate and encode using Base58Check
    address_bytes = vh160 + checksum
    return base58_encode(address_bytes)

if __name__ == '__main__':
    # Example private key (hex format)
    d_hex = "9fccfa3e683a26ed6c370992c9517679a7428bc78520e68343c0cc7e2873058e"
    d = int(d_hex, 16)
    print("🔑 Private Key (d):", hex(d))
    
    # Generate Bitcoin address
    address = generate_address_from_private_key(d)
    print("🏦 Generated Bitcoin Address:", address)
🧠 Step-by-Step Explanation
1️⃣ Convert Private Key → Public Key

Uses the secp256k1 elliptic curve:

vk = sk.get_verifying_key()
pubkey = b'\x04' + vk.to_string()


The prefix 0x04 denotes an uncompressed public key.

2️⃣ Compute HASH160

Bitcoin uses a two-step hash:

HASH160 = RIPEMD160(SHA256(pubkey))


This produces a 20-byte hash used for address derivation.

3️⃣ Add Version Byte & Checksum

Prefix version byte 0x00 → denotes Bitcoin mainnet.

Checksum = first 4 bytes of SHA256(SHA256(version + hash160))

4️⃣ Base58Check Encoding

The final step encodes the 25-byte result in Base58, removing ambiguous characters (0, O, I, l).

Example alphabet:

123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz

🧾 Example Output
🔑 Private Key (d): 0x9fccfa3e683a26ed6c370992c9517679a7428bc78520e68343c0cc7e2873058e
🏦 Generated Bitcoin Address: 1Eo3eqTYPt1tE2hzDjYzgfSADcE87hzVDq

🧩 What This Script Demonstrates
Step	Description	Example
1️⃣	Private key → Public key (elliptic curve math)	secp256k1
2️⃣	Public key → HASH160	20-byte hash
3️⃣	HASH160 → Versioned + checksum	0x00 + HASH160 + checksum
4️⃣	Base58Check encoding	Bitcoin address (starts with 1)
⚠️ Security Notes

🚫 Never expose your real private key — anyone with it can spend your Bitcoin.
💻 Use this script only for educational or offline research purposes.
🧱 For real wallets, always rely on hardened key derivation (BIP32/BIP44).

🧰 Requirements

Install required library:

pip install ecdsa


Run the script:

python3 generate_p2pkh_address.py

📜 License

MIT License
© 2025 — Author: [ethicbrudhack]

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr

🧠 TL;DR Summary

This script takes a private key (d) and walks through the Bitcoin address generation process step-by-step:
elliptic curve → public key → HASH160 → Base58Check → final P2PKH address.
