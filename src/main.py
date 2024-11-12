from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os


def main_menu():
	# Show the main menu options
	try:
		print('========== Password Manager ==========')
		print('0. Exit')
		print('1. Existing User')
		print('2. New User')
		print('3. Remove User')

		# Take input and parse the result
		option = int(input('Option: '))
		
		if option == 0:
			exit(0)
		elif option == 1:
			user = log_in()
			existing_user_menu(user)
		elif option == 2:
			new_user_menu()
		elif option == 3:
			remove_user()
		else:
			print('Invalid Option')

	except Exception as e:
		print(e)
		exit(1)


def log_in():
	user = input('Enter Username: ')
	masterpass = input('Enter your master password: ')

	encrypted = open('pwmanager.csv', 'rb')
	with open('private_key.pem', 'rb') as key:
		decrypted = Fernet.decrypt(encrypted, key)
		verify_masterpass(masterpass, decrypted)


def verify_masterpass(masterpass, decrypted):
	print('To Do')


def existing_user_menu(user):
	# Menu for existing users to log in
	try:
		print('========== {user} ==========')
		print('0. Exit')
		print('1. See your passwords')
		print('2. Add a new password')
		option = int(input())
		if option == 0:
			exit(0)
		elif option == 1:
			see_passwords(user)
		elif option == 2:
			add_password(user)
		else:
			print('Invalid Option')

	except Exception as e:
		print(e)
		exit(1)


def new_user_menu():
	username = input('Give a username: ')
	# Add the user to the csv


def remove_user():
	print('To Do')


def see_passwords(user):
	print('To Do')


def add_password(user):
	print('To Do')


def main():
	if not os.path.exists('pwmanager.csv'):
		file = open('pwmanager.csv', 'x')
		file.close()
	
	while True:
		main_menu()


if __name__ == '__main__':
	main()