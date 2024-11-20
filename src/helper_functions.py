from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass
import pandas as pd
import bcrypt
import base64
import os

def hash_password(masterpw, salt):
	kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
	return kdf.derive(masterpw.encode())


def generate_salt(length = 16):
	return os.urandom(length)


def verify_password(username: str, entered_password: str):
	csv = pd.read_csv('src/data/masterpw.csv')
	user_data = csv[csv['username'] == username]

	salt = bytes(user_data['salt'].values[0].strip('b"'), 'utf-8')
	
	kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
	
	try:
		kdf.verify(entered_password.encode(), user_data['encrypted_master_key'].values[0])
		return True
	except Exception:
		return False
	

def log_in():
	csv = pd.read_csv('src/data/masterpw.csv')
	username = input('Enter Username: ')

	if username not in csv['username'].values:
		print('User Not Found')
		return
	
	masterpw = getpass('Enter your master password: ')
	if verify_password(username, masterpw):
		return username


def remove_user(user):
	print('To Do')


def see_passwords(user):
	print('To Do')


def add_password(user):
	print('To Do')
	