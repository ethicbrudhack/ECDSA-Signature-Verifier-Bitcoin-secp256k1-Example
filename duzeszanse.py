import hashlib
from ecdsa import SECP256k1, util
from ecdsa.ecdsa import verify
from ecdsa.keys import BadSignatureError

# Funkcja do obliczania wartości z (message hash)
def calculate_z(txid):
    # W tym przypadku 'z' jest wyliczane na podstawie TXID w formie hash'a
    return hashlib.sha256(bytes.fromhex(txid)).hexdigest()

# Funkcja do weryfikacji podpisów ECDSA
def verify_signature(txid, r, s, z, n):
    try:
        # Używamy krzywej SECP256k1 do weryfikacji
        curve = SECP256k1.curve
        order = curve.order()
        
        # Sprawdzenie, czy r i s są w odpowiednim zakresie
        if not (0 < r < order and 0 < s < order):
            return False
        
        # Sprawdzenie, czy podpis jest poprawny
        pubkey = util.string_to_number(bytes.fromhex(txid))  # Publiczny klucz z TXID (symulacja)
        return verify((r, s), z, pubkey)  # Weryfikacja podpisu

    except BadSignatureError:
        return False
    except Exception as e:
        print(f"Błąd weryfikacji podpisu: {e}")
        return False

# Dane podpisów
signatures = [
    {
        "TXID": "44b4cca7a2306c6af2a931a50f9138bf87bf13ba41cd5ce5b6239e930b34793e",
        "r": "0xfbc2b9a148f7c136fd5ab60d9a1317624d90630ccdf1b65562977f370d999841",
        "s": "0x3f598a19e8e4eefec27af6fb8765132b205f45445d4b3755235d232d6f2ee41c",
        "z": "0xbeb21d89f2ebdc645094135d999aa79d386711a6a5f0289eba893c5515a4856f",
        "Low-S?": True,
        "n": "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
    },
    {
        "TXID": "44b4cca7a2306c6af2a931a50f9138bf87bf13ba41cd5ce5b6239e930b34793e",
        "r": "0x8ca2698b53fffcf9d064b1ca1313ff08e08e47d3bbb97a4f9d54dd0e3164af9a",
        "s": "0x65913d2b007ebedf451e0068b368a33ff0fdb9725370a8cecc34e2e8449f143c",
        "z": "0xbeb21d89f2ebdc645094135d999aa79d386711a6a5f0289eba893c5515a4856f",
        "Low-S?": True,
        "n": "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
    },
    {
        "TXID": "44b4cca7a2306c6af2a931a50f9138bf87bf13ba41cd5ce5b6239e930b34793e",
        "r": "0xefe66ff0cc452d2dc373db4cf2fa848944e32dbfac6c46542d2ed03a22cbb081",
        "s": "0x1726f4b1dc28ca118aea9d6a4fc7f9345c6cb071b7cbd95b22456c45539cb5fa",
        "z": "0xbeb21d89f2ebdc645094135d999aa79d386711a6a5f0289eba893c5515a4856f",
        "Low-S?": True,
        "n": "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
    },
    {
        "TXID": "44b4cca7a2306c6af2a931a50f9138bf87bf13ba41cd5ce5b6239e930b34793e",
        "r": "0x1e68b7d13178cd65061c2bb57623efb2f99be1577465a2ec0532f697113e4e34",
        "s": "0x16779876223604f100c9e444feea939aa828928dd2a67ca4a2ac1afe1edfa310",
        "z": "0xbeb21d89f2ebdc645094135d999aa79d386711a6a5f0289eba893c5515a4856f",
        "Low-S?": True,
        "n": "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
    }
]

# Sprawdzanie podpisów
for signature in signatures:
    txid = signature['TXID']
    r = int(signature['r'], 16)  # Konwersja z heksadecymalnej na int
    s = int(signature['s'], 16)  # Konwersja z heksadecymalnej na int
    z = int(signature['z'], 16)  # Konwersja z heksadecymalnej na int
    n = int(signature['n'], 16)  # Konwersja z heksadecymalnej na int
    
    print(f"🔹 Podpis dla TXID {txid}:")
    print(f"  r = {hex(r)}")
    print(f"  s = {hex(s)}")
    print(f"  z (computed) = {hex(z)}")
    print(f"  Low-S? = {signature['Low-S?']}")
    print(f"  n = {hex(n)}")
    
    # Weryfikacja podpisu
    valid_signature = verify_signature(txid, r, s, z, n)
    if valid_signature:
        print(f"  🔑 Podpis jest poprawny!")
    else:
        print(f"  ❌ Podpis jest niepoprawny!")
    
    print("------------------------------------------------")
