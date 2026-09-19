from crypto_utils import (
    sha256_hash,
    caesar_encrypt,
    caesar_decrypt,
    generate_aes_key,
    generate_iv,
    aes_encrypt,
    aes_decrypt,
    generate_rsa_keypair,
    sign_message,
    verify_signature,
    serialize_public_key,
)

USERS = {
    "Carter": {"password": "password123", "role": "admin"},
    "bob": {"password": "letmein", "role": "user"},
}


def login():
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    user = USERS.get(username)
    if user and user["password"] == password:
        print(f"Login successful. Role: {user['role']}")
        return username, user["role"]
    print("Invalid credentials.")
    return None, None


def show_menu(role: str):
    print("\n=== Main Menu ===")
    print("1. Hash + Encrypt + Decrypt + Verify")
    print("2. Caesar cipher")
    print("3. Digital signature")
    if role == "admin":
        print("4. View all users")
    print("0. Exit")


def handle_hash_encrypt_flow():
    message = input("Enter a message: ").encode("utf-8")
    original_hash = sha256_hash(message)
    print(f"Original SHA-256 hash: {original_hash}")
    key = generate_aes_key()
    iv = generate_iv()
    ciphertext = aes_encrypt(message, key, iv)
    print(f"Ciphertext: {ciphertext}")
    decrypted = aes_decrypt(ciphertext, key, iv)
    print(f"Decrypted: {decrypted.decode('utf-8')}")
    decrypted_hash = sha256_hash(decrypted)
    print(f"Decrypted SHA-256 hash: {decrypted_hash}")
    print("Integrity verified." if original_hash == decrypted_hash else "Integrity FAILED.")


def handle_caesar():
    text = input("Enter text: ")
    shift = int(input("Shift: "))
    encrypted = caesar_encrypt(text, shift)
    decrypted = caesar_decrypt(encrypted, shift)
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")


def handle_digital_signature():
    message = input("Enter message: ").encode("utf-8")
    private_key, public_key = generate_rsa_keypair()
    signature = sign_message(private_key, message)
    print("Signature:", signature)
    print("Public key:")
    print(serialize_public_key(public_key))
    valid = verify_signature(public_key, message, signature)
    print("Signature valid:", valid)


def handle_admin_view_users():
    for username, info in USERS.items():
        print(f"{username} - {info['role']}")


def main():
    username, role = login()
    if not username:
        return
    while True:
        show_menu(role)
        choice = input("Choose: ").strip()
        if choice == "1":
            handle_hash_encrypt_flow()
        elif choice == "2":
            handle_caesar()
        elif choice == "3":
            handle_digital_signature()
        elif choice == "4" and role == "admin":
            handle_admin_view_users()
        elif choice == "0":
            break
        else:
            print("Invalid or unauthorized.")


if __name__ == "__main__":
    main()
