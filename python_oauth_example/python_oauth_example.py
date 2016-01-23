'''
OAuth Authentication with Toodledo via Python without needing to proprly handle
the callback. This example uses requests_oauthlib which can be installed via
pip.

Combines Reddit's Python Oauth Instructions:
(https://github.com/reddit/reddit/wiki/OAuth2-Python-Example)

With requests_oauthlib's Google:
(http://requests-oauthlib.readthedocs.org/en/stable/examples/google.html)
And GitHub's examples
(http://requests-oauthlib.readthedocs.org/en/stable/examples/github.html)

'''

from requests_oauthlib import OAuth2Session
import requests
import requests.auth

import argparse
import pickle

# Get your program's details from Toodledo's page

client_id = 'CHANGEME'
client_secret = 'CHANGEME'
authorization_base_url = 'https://api.toodledo.com/3/account/authorize.php'
redirect_uri = 'CHANGEME'
token_url = 'https://api.toodledo.com/3/account/token.php'
scope = ['basic','tasks', 'write']

# Set up the Auth Connection for Later
client_auth = requests.auth.HTTPBasicAuth(client_id, client_secret)



def _get_auth_code():
	'''
	Creates a url for the user to copy & paste into their browser. Approving
	the app will send the user to a broken URL with the authorization code
	in the address bar.
	'''
	toodle = OAuth2Session(client_id, scope=scope)
	authorization_url, state = toodle.authorization_url(authorization_base_url)
	print 'Please go here and authorize,', authorization_url
	code = raw_input('Enter Code from Broken URL: ')
	return code, state

def get_token():
	'''
	Sends Toodledo the necessary POST to generate an auth token after getting 
	the state and code from _get_auth_code().

	get_token() stores the full token as a pickle file so it can be loaded later
	or used to refresh the token.
	'''
	code, state = _get_auth_code()
	post_data = {
		'grant_type':'authorization_code',
		'code':code,
		'redirect_uri':redirect_uri,
		'state':state,
		'device':'terminal'
	}
	response = requests.post(token_url, auth=client_auth, data = post_data)
	full_token = response.json()
	pickle.dump(full_token, open('auth_token.pkl', 'wb'))
	print 'Created token {}'.format(full_token['access_token'])



def refresh():
	'''
	Loads the pickled auth token and makes the necessary POST request to 
	Toodledo in order to refresh the token. It then pickles the new token.
	''' 
	full_token = pickle.load( open('auth_token.pkl', 'rb'))
	post_data = {
		'grant_type':'refresh_token',
		'refresh_token':full_token['refresh_token'],
		'device':'terminal'
	}
	response = requests.post(token_url, auth=client_auth, data = post_data)
	full_token = response.json()
	pickle.dump(full_token, open('auth_token.pkl', 'wb'))
	print 'Refreshed Token {}'.format(full_token['refresh_token'])

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--new-token', action='store_true',
		help='Authorize a new app and generate a new oauth_token')
	parser.add_argument('--refresh-token', action='store_true',
		help='Refresh the current auth_token.pkl file')
	args = parser.parse_args()
	if args.new_token:
		get_token()
	if args.refresh_token:
		refresh

if __name__ == '__main__':
	main()

