import socket
import requests
import yaml
import logging

from hashlib import sha1
from random import random
from urllib import parse
from datetime import datetime, timedelta
from dateutil import parser as dateparser

from packj import __version__
from packj.auth.creds import Creds

def setup_session(cfg, creds):
	try:
		base_url = cfg['base_url']
		start_session_endpoint = cfg['endpoints']['session']

		grant_type = creds.get('type')
		logging.debug(f'Initiating a new user auth session with grant_type {grant_type}')

		hostname = socket.gethostname()
 
		params = {
			'hostname': hostname,
			'auth_type': grant_type,
		}
		params = parse.urlencode(params)

		headers = {
			'User-Agent': f'pypi-packj-{__version__}',
			'From': f'{hostname}',
		}

		url = base_url + start_session_endpoint
		resp = requests.post(url=url, params=params, headers=headers)
		resp.raise_for_status()
	except Exception as e:
		raise Exception("Failed to setup_session (post, %s%s, %s): %s" % \
				(base_url, start_session_endpoint, params, str(e)))

	try:
		# json format
		response_data = resp.json()
		logging.debug("session data: %s" % (response_data))

		# validate
		if 'auth_url' not in response_data or not response_data['auth_url']:
			raise Exception('invalid session data')
		if 'id' not in response_data or not response_data['id']:
			raise Exception('invalid session data')
	except Exception as e:
		logging.error("Failed to setup session: %s" % (str(e))) 
		return None

	# update user credentials
	try:
		creds.update('id', response_data['id'])
		creds.update('auth_url', response_data['auth_url'])
	except Exception as e:
		logging.warning("Failed to update user credentials: %s" % (str(e))) 

	# manual user auth
	try:
		msg = "Visit the site below in your browser, follow the steps to authenticate, " + \
					"and then come back here to continue [ENTER]\n\t%s" % (response_data['auth_url']) 
		input(msg)
	except Exception as e:
		logging.error("Failed to setup session: %s" % (str(e))) 
		return None

def get_auth_code(cfg, creds):
	try:
		logging.debug('Getting user auth code')

		base_url = cfg['base_url']
		auth_endpoint = cfg['endpoints']['auth']

		headers = {
			'User-Agent': f'pypi-packj-{__version__}',
			'From': socket.gethostname(),
		}

		url = base_url + auth_endpoint

		state = sha1(str(random()).encode('utf-8')).hexdigest()
		params = {
			'client_id': creds.get('id'),
			'response_type': 'code',
			'scope': 'audit',
			'state': state,
		}
		params = parse.urlencode(params)

		logging.debug("POST url %s params: %s" % (url, params))

		resp = requests.post(url=url, params=params, headers=headers)
		resp.raise_for_status()
	except requests.exceptions.HTTPError:
		print("Authentication failed! Did you visit the link in the browser (login required)?")
		return
	except Exception as e:
		logging.debug(f'Failed to get auth code {url}: {str(e)}')
		return None

	try:
		# json format
		response_data = resp.json()
		logging.debug(f'auth code response: {response_data}')

		# validate response
		if 'state' not in response_data or response_data['state'] != state:
			raise Exception('Invalid state!')
		if 'code' not in response_data or not response_data['code']:
			raise Exception('Invalid code!')
	except Exception as e:
		logging.debug(f'Failed to get auth code {url}: {str(e)}')
		return None

	try:
		# remove stale auth code/token
		creds.update('token', None)
		creds.update('code', response_data['code'])
	except Exception as e:
		logging.warning("Failed to update user credentials: %s" % (str(e)))
	finally:
		return True

def get_auth_token(cfg, creds):
	try:
		logging.debug('Getting user auth token from code')

		base_url = cfg['base_url']
		code_redirect_endpoint = cfg['endpoints']['redirect']
		token_endpoint = cfg['endpoints']['token']

		url = base_url + token_endpoint

		headers = {
			'User-Agent': f'pypi-packj-{__version__}',
			'From': socket.gethostname(),
		}

		client_id = creds.get('id')
		if not client_id:
			raise Exception('no client_id')

		auth_code = creds.get('code')
		if not auth_code:
			raise Exception('no auth_code')

		params = {
			'client_id': client_id,
			'code': auth_code,
			'grant_type': 'authorization_code',
			'redirect_uri': code_redirect_endpoint,
		}
		params = parse.urlencode(params)

		logging.debug(f'POST url {url} params {params}')
		resp = requests.post(url=url, params=params, headers=headers)
		resp.raise_for_status()
	except Exception as e:
		raise Exception(f'Failed to get auth token: {str(e)}')

	try:
		# json format
		response_data = resp.json()
		logging.debug(f'auth token: {response_data}')

		# validate response
		if 'access_token' not in response_data or not response_data['access_token']:
			raise Exception('Invalid token!')
		if 'refresh_token' not in response_data or not response_data['refresh_token']:
			raise Exception('Invalid token!')
		if 'token_type' not in response_data or not response_data['token_type']:
			raise Exception('Invalid token!')

		# token expiry
		if 'expires' not in response_data:
			if 'expires_in' in response_data:
				expires_in = int(response_data['expires'])
			else:
				expires_in = 3600
			expires = datetime.now() + timedelta(seconds=expires_in)
			expires = expires.strftime('%Y-%m-%d %H:%M:%S %Z')
			response_data['expires'] = expires
	except Exception as e:
		raise Exception(f'Failed to get auth token {url}: {str(e)}')

	try:
		# remove stale auth code/token
		creds.update('token', response_data)
	except Exception as e:
		logging.warning("Failed to update user credentials: %s" % (str(e)))
	finally:
		return True

def get_auth_implicit_token(creds):
	logging.debug('get_auth_implicit_token')

	try:
		base_url = cfg['base_url']
		auth_endpoint = cfg['endpoints']['auth']

		url = base_url + auth_endpoint

		headers = {
			'User-Agent': f'pypi-packj-{__version__}',
			'From': socket.gethostname(),
		}

		client_id = creds.get('id')
		if not client_id:
			raise Exception('no client_id!')

		state = sha1(str(random()).encode('utf-8')).hexdigest()
		params = {
			'client_id': client_id,
			'response_type': 'token',
			'scope': 'audit',
			'state': state,
			'redirect_uri': base_url + token_redirect_endpoint + '/' + client_id,
		}

		params = parse.urlencode(params)
		logging.debug("(implicit) POST url: %s params: %s" % (url, params))

		resp = requests.post(url=url, params=params, headers=headers)
		resp.raise_for_status()
	except Exception as e:
		raise Exception("get_auth_implicit_token(%s:%s): %s" % \
				(base_url, auth_endpoint, str(e)))

	try:
		# validate response
		response_data = resp.json()
		logging.debug("server response: %s" % (response_data))

		assert 'error' not in response_data, response_data['error']
		if 'state' in response_data:
			response_data['state'] == state, 'Invalid state!'
	except Exception as e:
		raise Exception("get_auth_implicit_token(%s:%s): %s" % \
				(base_url, auth_endpoint, str(e)))

	try:	
		# token expiry
		if 'expires' not in response_data:
			if 'expires_in' in response_data:
				expires_in = int(response_data['expires'])
			else:
				expires_in = 3600
			expires = datetime.now() + timedelta(seconds=expires_in)
			expires = expires.strftime('%Y-%m-%d %H:%M:%S %Z')
			response_data['expires'] = expires
	except Exception as e:
		logger,warning("get_auth_implicit_token(%s:%s): failed to add token expiry (%s)" % \
				(base_url, auth_endpoint, str(e)))

	try:
		# remove stale auth code/token
		creds.update('code', None)
		creds.update('token', response_data)
	except Exception as e:
		logging.warning("get_auth_implicit_token(%s:%s): failed to save token (%s)" % \
				(base_url, auth_endpoint, str(e)))

def refresh_credentials(cfg, creds):
	try:
		logging.debug("Refreshing user auth tokens")

		base_url = cfg['base_url']
		token_endpoint = cfg['endpoints']['token']

		headers = {
			'User-Agent': f'pypi-packj-{__version__}',
			'From': socket.gethostname(),
		}

		client_id = creds.get('id')
		if not client_id:
			raise Exception("refresh_credentials(): failed to get client_id!")

		state = sha1(str(random()).encode('utf-8')).hexdigest()

		token = creds.get('token')
		if not token:
			raise Exception("refresh_credentials(): failed to get tokens!")

		refresh_token = token['refresh_token']

		params = {
			'client_id': client_id,
			'grant_type': 'refresh_token',
			'scope': 'audit',
			'refresh_token': refresh_token,
			'state': state,
		}
		params = parse.urlencode(params)

		url = base_url + token_endpoint
	except Exception as e:
		raise Exception("Error constructing refresh request: %s" % (str(e)))

	logging.debug("POST url: %s params: %s" % (url, params))

	try:
		headers = {
			'User-Agent': f'pypi-packj-{__version__}',
			'From': socket.gethostname(),
		}

		# talk to the server
		resp = requests.post(url=url, params=params, headers=headers)
		resp.raise_for_status()
	except Exception as e:
		logging.debug("Failed to refresh tokens: %s" % (str(e)))
		raise Exception("Server error: %s" % (str(e)))

	try:
		# validate response
		response_data = resp.json()
	except Exception as e:
		raise Exception("Invalid data: %s" % (str(e)))

	logging.debug("refresh response: %s" % (response_data))
	if 'state' in response_data and response_data['state'] != state:
		raise Exception('Invalid state!')

	try:
		# token expiry
		if 'expires' not in response_data:
			if 'expires_in' in response_data.keys():
				expires_in = int(response_data['expires'])
			else:
				expires_in = 3600
			expires = datetime.now() + timedelta(seconds=expires_in)
			expires = expires.strftime('%Y-%m-%d %H:%M:%S %Z')
			response_data['expires'] = expires
	except Exception as e:
		logging.debug("Failed to parse token expiry: %s" % (str(e)))

	try:
		creds.update('token', response_data)
	except Exception as e:
		logging.debug("Failed to save tokens: %s" % (str(e)))

def token_expired(creds, token):
	expired = False
	if not token:
		token = creds.get('token')
	if token:
		expiry = dateparser.parse(token['expires'])
		current_time = datetime.now(expiry.tzinfo)
		if expiry < current_time:
			expired = True
		logging.debug("Token expiry %s current_time %s (expired: %s)" % \
				  (expiry, current_time, expired))
	return expired

def create_or_refresh_session(cfg, creds, expired, env='cli', grant_type='token'):
	logging.debug("create_or_refresh_session(expired: %s) grant_type: %s" % \
			(expired, grant_type))

	if expired:
		try:
			refresh_credentials(cfg, creds)
			return True
		except Exception as e:
			if '401 Client Error: UNAUTHORIZED for url' in str(e):
				if env == "Staging":
					print("Failed to refresh user credentials:: request not supported!")
					exit(1)
				expired = True
			else:
				print("Failed to refresh user credentials: %s! Exiting." % (str(e)))
				exit(1)

	if expired:
		logging.debug('FATAL: Access token has expired. Please re-authenticate the user.')

	# create a new auth session
	try:
		setup_session(cfg, creds)
	except Exception as e:
		print("Failed to initiate authentication session: %s. Exiting!" % (str(e)))
		exit(1)

	# continue with user authentication
	try:
		if get_auth_code(cfg, creds):
			get_auth_token(cfg, creds)
			return True
	except Exception as e:
		print(f'Failed to authenticate: {str(e)}! Exiting.')
		exit(1)

def load_account_config(config_file:str) -> dict:
	try:
		with open(config_file, 'r') as f:
			cfg = yaml.safe_load(f)
	except Exception as e:
		raise Exception(f'Failed to parse config file {config_file}: {str(e)}')
	try:
		return cfg['account']
	except KeyError:
		raise Exception(f'Invalid config file {config_file}: no "account" section found')

def main(args, config_file):
	try:
		if args.debug:
			logging.getLogger().setLevel(logging.DEBUG)
		else:
			logging.getLogger().setLevel(logging.ERROR)

		cfg = load_account_config(config_file)
		creds = Creds(cfg['creds_file'])

		token = creds.get('token')
		if not token or args.force:
			save = create_or_refresh_session(cfg, creds, expired=False)
		else:
			expired = token_expired(creds, token)
			if not expired:
				save = False
				print("Already authenticated. Nothing to do")
			else:
				save = create_or_refresh_session(cfg, creds, expired=expired)
		if save:
			creds.save()
			print("Successfully authenticated (pro account activated).")
	except Exception as e:
		print(f'Failed to authenticate: {str(e)}')
		exit(1)
