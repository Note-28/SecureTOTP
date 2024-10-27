import hmac
import hashlib
import time
import struct

def generate_totp(secret, time_step=30, sha_algorithm='sha1', num_digits=6):
    # Get the current time in seconds
    current_time = int(time.time() // time_step)
    
    # Convert the current time to bytes
    time_bytes = struct.pack('>Q', current_time)
    
    # Select the hashing algorithm
    if sha_algorithm == 'sha1':
        hash_func = hashlib.sha1
    elif sha_algorithm == 'sha256':
        hash_func = hashlib.sha256
    elif sha_algorithm == 'sha512':
        hash_func = hashlib.sha512
    else:
        raise ValueError("Unsupported SHA algorithm. Use 'sha1', 'sha256', or 'sha512'.")

    # Create the HMAC hash
    hmac_hash = hmac.new(secret.encode(), time_bytes, hash_func).digest()
    
    # Extract the dynamic binary code (last nibble)
    offset = hmac_hash[-1] & 0x0F
    code = (struct.unpack('>I', hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** num_digits)  # Dynamic length
    
    return str(code).zfill(num_digits)  # Zero-pad to ensure the specified number of digits

if __name__ == "__main__":
    # Prompt user for input
    shared_secret = input("Enter the shared secret: ")
    sha_algorithm = input("Enter the SHA algorithm (sha1, sha256, sha512): ").strip().lower()
    time_step = int(input("Enter the time step in seconds (default is 30): ") or 30)
    num_digits = int(input("Enter the number of digits for the TOTP (default is 6): ") or 6)

    totp_password = generate_totp(shared_secret, time_step, sha_algorithm, num_digits)
    print("Generated TOTP:", totp_password)
