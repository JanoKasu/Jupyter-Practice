from helper_functions import *
from getpass import getpass


def main_menu():
	# Show the main menu options
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
		if not user:
			print('Login Failed.')
			return
		existing_user_menu(user)
	elif option == 2:
		new_user_menu()
	elif option == 3:
		user = log_in()
		remove_user(user)
	else:
		print('Invalid Option')


def existing_user_menu(user):
	# Menu for existing users to log in
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


def new_user_menu():
	# Check for unique username
	username = input('Give a username: ')
	csv = pd.read_csv('src/data/masterpw.csv')
	if username in csv['username'].values:
		print('User already exists')
		return
	
	# Add a master password
	masterpw = getpass('Enter a master password: ')
	salt = generate_salt()
	encrypted_master_key = hash_password(masterpw, salt)
	new_row = {'username':username, 'salt':salt, 'encrypted_master_key':encrypted_master_key}
	csv.loc[len(csv)] = new_row
	csv.to_csv('src/data/masterpw.csv', index=False)

	print('Successful Entry')


def main():
	if not os.path.exists('src/data/user_passwords.csv'):
		file = open('src/data/user_passwords.csv', 'x')
		file.write('username,site_name,encrypted_password,initialization_vector')
		file.close()
	
	if not os.path.exists('src/data/masterpw.csv'):
		file = open('src/data/masterpw.csv', 'x')
		file.write('username,salt,encrypted_master_key')
		file.close()

	while True:
		main_menu()


if __name__ == '__main__':
	main()