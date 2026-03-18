import os
import base64
import logging
import uuid
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Setup logging
logger = logging.getLogger(__name__)

from django.conf import settings

ENCRYPTION_KEY = settings.ENCRYPTION_KEY
if isinstance(ENCRYPTION_KEY, str):
    # Ensure the key is exactly 32 bytes by hashing it
    from hashlib import sha256
    ENCRYPTION_KEY = sha256(ENCRYPTION_KEY.encode()).digest()

def encrypt_file(source_path, destination_folder):
    """
    Encrypts a file using AES-256 in CBC mode.
    
    Args:
        source_path: Path to the file to encrypt
        destination_folder: Folder to store the encrypted file
        
    Returns:
        (encrypted_file_path, iv): Path to the encrypted file and the initialization vector
    """
    try:
        # Generate a random IV (initialization vector)
        iv = get_random_bytes(16)
        
        # Generate a unique filename for the encrypted file
        encrypted_filename = f"{uuid.uuid4().hex}.enc"
        encrypted_path = os.path.join(destination_folder, encrypted_filename)
        
        # Create cipher object
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
        
        # Read the source file
        with open(source_path, 'rb') as f:
            plaintext = f.read()
        
        # Pad the data to be a multiple of 16 bytes (AES block size)
        padded_data = pad(plaintext, AES.block_size)
        
        # Encrypt the data
        ciphertext = cipher.encrypt(padded_data)
        
        # Write the encrypted data to the destination
        with open(encrypted_path, 'wb') as f:
            f.write(ciphertext)
        
        # Return the path to the encrypted file and the IV (convert IV to string for storage)
        return encrypted_path, base64.b64encode(iv).decode('utf-8')
    
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        raise

def decrypt_file(encrypted_path, output_path, iv_b64):
    """
    Decrypts a file that was encrypted using AES-256 in CBC mode.
    
    Args:
        encrypted_path: Path to the encrypted file
        output_path: Path to save the decrypted file
        iv_b64: Base64 encoded initialization vector used for encryption
        
    Returns:
        output_path: Path to the decrypted file
    """
    try:
        # Decode the IV from base64
        iv = base64.b64decode(iv_b64)
        
        # Create cipher object
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
        
        # Read the encrypted file
        with open(encrypted_path, 'rb') as f:
            ciphertext = f.read()
        
        # Decrypt the data
        padded_plaintext = cipher.decrypt(ciphertext)
        
        # Remove padding
        plaintext = unpad(padded_plaintext, AES.block_size)
        
        # Write the decrypted data to the output file
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        return output_path
    
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        raise

def sanitize_input(value):
    """
    Sanitizes input to prevent injection attacks.
    
    Args:
        value: The input value to sanitize
        
    Returns:
        Sanitized value
    """
    if isinstance(value, str):
        # Remove potentially dangerous characters
        sanitized = value.replace('<', '&lt;').replace('>', '&gt;')
        return sanitized
    return value

def validate_file_extension(filename, allowed_extensions):
    """
    Validates that a file has an allowed extension.
    
    Args:
        filename: Name of the file to validate
        allowed_extensions: Set of allowed extensions
        
    Returns:
        Boolean indicating if the extension is allowed
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
