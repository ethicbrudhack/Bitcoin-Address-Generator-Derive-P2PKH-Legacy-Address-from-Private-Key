import hashlib
import ecdsa

# Funkcja obliczająca hash160 (SHA256, a potem RIPEMD160)
def hash160(data):
    sha = hashlib.sha256(data).digest()
    rip = hashlib.new('ripemd160', sha).digest()
    return rip

# Funkcja kodująca Base58
def base58_encode(b):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(b, byteorder='big')
    result = ''
    while num > 0:
        num, rem = divmod(num, 58)
        result = alphabet[rem] + result
    # Dodajemy '1' dla każdego zerowego bajtu na początku
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return '1' * pad + result

# Funkcja generująca adres Bitcoin na podstawie klucza prywatnego d
def generate_address_from_private_key(d):
    # Konwertujemy klucz prywatny (d) na 32-bajtowy ciąg
    private_key_bytes = d.to_bytes(32, byteorder='big')
    # Tworzymy klucz podpisujący przy użyciu SECP256k1
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    # Uzyskujemy klucz weryfikujący (publiczny)
    vk = sk.get_verifying_key()
    # Format niekompresowany: 0x04 || x || y (gdzie x i y mają po 32 bajty)
    pubkey_bytes = b'\x04' + vk.to_string()
    # Obliczamy hash160 klucza publicznego
    h160 = hash160(pubkey_bytes)
    # Dodajemy wersję 0x00 dla Bitcoin mainnet
    vh160 = b'\x00' + h160
    # Obliczamy checksum: pierwsze 4 bajty podwójnego SHA256
    checksum = hashlib.sha256(hashlib.sha256(vh160).digest()).digest()[:4]
    # Łączymy wszystko i kodujemy Base58
    address_bytes = vh160 + checksum
    return base58_encode(address_bytes)

if __name__ == '__main__':
    # Ustawiamy klucz prywatny d (przykładowa wartość)
    d_hex = "9fccfa3e683a26ed6c370992c9517679a7428bc78520e68343c0cc7e2873058e"
    d = int(d_hex, 16)
    print("Klucz prywatny d:", hex(d))
    
    address = generate_address_from_private_key(d)
    print("Wygenerowany Bitcoin Address:", address)
