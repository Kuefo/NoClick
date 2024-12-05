#   Requirements:                             pip install cryptography PyInquirer

import os
import hashlib
import random
import string
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from PyInquirer import prompt

SUPPORTED_TYPES = ['exe', 'image', 'video', 'mp3', 'html', 'pdf', 'docx', 'xlsx', 'pptx', 'txt']

def generate_random_string(length=5):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def obfuscate_extension(file_path):
    base_path, ext = os.path.splitext(file_path)
    obfuscated_ext = generate_random_string()
    obfuscated_file_path = f"{base_path}.{obfuscated_ext}"
    return obfuscated_file_path

def generate_encryption_key(password, salt, algorithm='Fernet'):
    if algorithm == 'Fernet':
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, 32)
    elif algorithm == 'PBKDF2':
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,
            salt=salt,
            length=32
        )
        key = kdf.derive(password.encode('utf-8'))
    else:
        raise ValueError("Unsupported encryption algorithm")
    return key

def encrypt_data(key, data, algorithm='Fernet'):
    if algorithm == 'Fernet':
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)
    else:
        raise ValueError("Unsupported encryption algorithm")
    return encrypted_data

def validate_file_type(file_path):
    _, file_extension = os.path.splitext(file_path)
    actual_type = file_extension.lower()[1:]
    if actual_type not in SUPPORTED_TYPES:
        raise ValueError(f"Invalid file type. Expected one of {SUPPORTED_TYPES}, Actual: {actual_type}")

def file_binder():
    questions = [
        {
            'type': 'input',
            'name': 'exe_path',
            'message': 'Enter the path of the EXE file:',
        },
        {
            'type': 'input',
            'name': 'media_path',
            'message': 'Enter the path of the media file (image, video, or mp3):',
        },
        {
            'type': 'input',
            'name': 'output_path',
            'message': 'Enter the path of the output EXE file:',
        },
        {
            'type': 'password',
            'name': 'password',
            'message': 'Enter a password for encryption:',
        },
        {
            'type': 'list',
            'name': 'encryption_algorithm',
            'message': 'Choose an encryption algorithm:',
            'choices': ['Fernet', 'PBKDF2'],
        },
    ]

    answers = prompt(questions)

    try:
        validate_file_type(answers['exe_path'])
        validate_file_type(answers['media_path'])
        validate_file_type(answers['output_path'])

        answers['output_path'] = obfuscate_extension(answers['output_path'])

        with open(answers['exe_path'], 'rb') as exe_file, open(answers['media_path'], 'rb') as media_file:
            exe_data = exe_file.read()
            media_data = media_file.read()

        combined_data = exe_data + media_data

        salt = os.urandom(16)
        encryption_key = generate_encryption_key(answers['password'], salt, answers['encryption_algorithm'])

        encrypted_data = encrypt_data(encryption_key, combined_data, answers['encryption_algorithm'])

        with open(answers['output_path'], 'wb') as output_file:
            output_file.write(encrypted_data)

        print("Exe file bound securely to the media file with encryption and obfuscated extension.")
        print("Output file path:", answers['output_path'])

    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {str(e)}")
    except Exception as e:
        print(f"Error: An unexpected error occurred.")

if __name__ == '__main__':
    file_binder()