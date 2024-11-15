from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pandas as pd
import pandas as pd
import base64
import os

def generate_key_from_masterpw(masterpw, salt):
	kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
	return kdf.derive(masterpw.encode())


def generate_salt(length = 16):
	return os.urandom(length)


def verify_password(username, entered_password):
	csv = pd.read_csv('src/data/masterpw.csv')
	user_data = csv[csv['username'] == username]

	salt_str = user_data['salt'].values[0].strip("b'")
	print(salt_str)
	salt = base64.b64decode(salt_str)
	print(salt)
	encrypted_master_key = base64.decode(user_data['encrypted_master_key'].values[0])
	print(encrypted_master_key)
	stored_hashedpw = base64.decode(encrypted_master_key)
	print(stored_hashedpw)

	kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
	
	entered_hashedpw = kdf.derive(entered_password.encode('utf-8'))
	return entered_hashedpw == stored_hashedpw


def remove_user(user):
	print('To Do')


def see_passwords(user):
	print('To Do')


def add_password(user):
	print('To Do')
	