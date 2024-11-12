import argparse
from cryptography.fernet import Fernet

def generate_key(file_path):
    """Generate and save an encryption key."""
    key = Fernet.generate_key()
    with open(file_path, 'wb') as key_file:
        key_file.write(key)
    print(f"Key saved to {file_path}")

def load_key(file_path):
    """Load the key from the specified file."""
    with open(file_path, 'rb') as key_file:
        return key_file.read()

def encrypt_file(input_file, key_file, output_file):
    """Encrypt a file using the given key."""
    key = load_key(key_file)
    fernet = Fernet(key)
    
    with open(input_file, 'rb') as file:
        file_data = file.read()
    
    encrypted_data = fernet.encrypt(file_data)
    
    with open(output_file, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)
    
    print(f"File {input_file} encrypted and saved to {output_file}")

def decrypt_file(encrypted_file, key_file, output_file):
    """Decrypt a file using the given key."""
    key = load_key(key_file)
    fernet = Fernet(key)
    
    with open(encrypted_file, 'rb') as file:
        encrypted_data = file.read()
    
    decrypted_data = fernet.decrypt(encrypted_data)
    
    with open(output_file, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)
    
    print(f"File {encrypted_file} decrypted and saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt and decrypt files using symmetric encryption.")
    parser.add_argument("operation", choices=["generate_key", "encrypt", "decrypt"], help="The operation to perform")
    parser.add_argument("--key_file", help="Path to the key file")
    parser.add_argument("--input_file", help="Path to the input file")
    parser.add_argument("--output_file", help="Path to the output file")

    args = parser.parse_args()

    if args.operation == "generate_key":
        if not args.key_file:
            print("Please specify --key_file to save the generated key.")
        else:
            generate_key(args.key_file)

    elif args.operation == "encrypt":
        if not args.key_file or not args.input_file or not args.output_file:
            print("Please specify --key_file, --input_file, and --output_file for encryption.")
        else:
            encrypt_file(args.input_file, args.key_file, args.output_file)

    elif args.operation == "decrypt":
        if not args.key_file or not args.input_file or not args.output_file:
            print("Please specify --key_file, --input_file, and --output_file for decryption.")
        else:
            decrypt_file(args.input_file, args.key_file, args.output_file)