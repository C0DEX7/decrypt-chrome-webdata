import os
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Customize file paths here
local_state_path = r"C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Local State"
web_data_path = r"C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default\Web Data"
credit_card_file_path = "decrypted_credit_cards.txt"
other_data_file_path = "decrypted_other_data.txt"

# Function to retrieve the AES key from the Local State file
def get_encryption_key():
    with open(local_state_path, "r", encoding="utf-8") as file:
        local_state_data = json.load(file)
    
    # Base64 decode and DPAPI decrypt the encrypted key
    encrypted_key = base64.b64decode(local_state_data["os_crypt"]["encrypted_key"])[5:]  # Remove DPAPI header
    key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return key

# Function to decrypt encrypted values with and without an authentication tag
def decrypt_value(encrypted_value, key):
    iv = encrypted_value[3:15]  # Extract initialization vector (IV)
    payload = encrypted_value[15:]
    
    try:
        # Assume the last 16 bytes of payload is the tag (common in AES-GCM)
        tag = payload[-16:]
        ciphertext = payload[:-16]
        
        # Set up AES-GCM for decryption with the tag
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_value = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_value.decode()
    
    except ValueError:
        # If tag is missing or decryption fails, try decrypting without a tag
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_value = decryptor.update(payload) + decryptor.finalize()
        return decrypted_value.decode()

# Extract and decrypt all data, separating credit card data from other data
def extract_credit_card_data():
    key = get_encryption_key()
    # Adding timeout and read-only mode to avoid database lock issues
    conn = sqlite3.connect(f"file:{web_data_path}?mode=ro", uri=True, timeout=10)
    cursor = conn.cursor()
    
    # Query the credit card data
    cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
    credit_cards = []

    for row in cursor.fetchall():
        name_on_card = row[0]
        expiration_month = row[1]
        expiration_year = row[2]
        encrypted_card_number = row[3]
        
        # Decrypt the card number
        card_number = decrypt_value(encrypted_card_number, key)
        
        # Store the decrypted credit card information
        credit_cards.append({
            "name_on_card": name_on_card,
            "expiration_month": expiration_month,
            "expiration_year": expiration_year,
            "card_number": card_number
        })
    
    conn.close()
    return credit_cards


def extract_all_data():
    key = get_encryption_key()
    conn = sqlite3.connect(f"file:{web_data_path}?mode=ro", uri=True, timeout=10)
    conn.text_factory = bytes  # Retrieve columns as raw binary data
    cursor = conn.cursor()
    
    # Fetch all table names and decode them to strings
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()

    credit_card_data = extract_credit_card_data()  # Extract the credit card data
    other_data = {}

    for table_name in tables:
        # Decode table name to string if it's in bytes
        table_name = table_name[0].decode('utf-8')

        # Safely quote the table name to handle special characters
        table_name_quoted = f'"{table_name}"'
        
        try:
            cursor.execute(f"PRAGMA table_info({table_name_quoted})")
            columns = cursor.fetchall()

            cursor.execute(f"SELECT * FROM {table_name_quoted}")
            rows = cursor.fetchall()

            # Process each row, decrypting if necessary
            table_data = []
            for row in rows:
                row_data = {}
                for idx, column in enumerate(columns):
                    column_name = column[1]
                    value = row[idx]
                    
                    # Check if the value is binary (bytes) data, which may need decryption
                    if isinstance(value, bytes):
                        try:
                            value = decrypt_value(value, key)
                        except Exception as e:
                            pass  # Skip decryption if not encrypted or error occurs

                    # If value is still bytes after decryption attempt, decode if possible
                    if isinstance(value, bytes):
                        try:
                            value = value.decode("utf-8")
                        except UnicodeDecodeError:
                            value = "<Binary Data>"  # Placeholder for unrecognized binary data

                    row_data[column_name] = value
                table_data.append(row_data)

            # Add the other data to the collection
            other_data[table_name] = table_data
        except sqlite3.OperationalError as e:
            print(f"Skipping table {table_name} due to error: {e}")

    conn.close()

    # Return both credit card data and other data
    return credit_card_data, other_data




# Save credit card and other data to separate files
def save_to_files(credit_card_data, other_data, credit_card_file_path, other_data_file_path):
    # Save credit card data
    with open(credit_card_file_path, "w", encoding="utf-8") as file:
        file.write("Credit Card Information:\n")
        for card in credit_card_data:
            for column_name, value in card.items():
                file.write(f"{column_name}: {value}\n")
            file.write("-" * 30 + "\n")
    print(f"Decrypted credit card data saved to {credit_card_file_path}")

    # Save other data
    with open(other_data_file_path, "w", encoding="utf-8") as file:
        for table_name, rows in other_data.items():
            file.write(f"Table: {table_name}\n")
            for row in rows:
                for column_name, value in row.items():
                    file.write(f"{column_name}: {value}\n")
                file.write("-" * 30 + "\n")
            file.write("=" * 50 + "\n\n")
    print(f"Decrypted non-credit card data saved to {other_data_file_path}")

# Run and save results to separate text files
if __name__ == "__main__":
    credit_card_data, other_data = extract_all_data()
    save_to_files(credit_card_data, other_data, credit_card_file_path, other_data_file_path)
