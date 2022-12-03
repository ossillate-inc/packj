import os
import json
import logging

class Creds:
	__id = None
	__code = None
	__token = None
	__auth_url = None
	__file = None

	def __init__(self, creds_file):
		try:
			self.__file = os.path.expanduser(creds_file)
			if not os.path.exists(self.__file):
				logging.debug(f'{creds_file} does not exist!')
				return
			with open(self.__file, 'r') as f:
				data = json.loads(f.read())
				self.__auth_url = data.get('auth_url', None)
				self.__code = data.get('code', None)
				self.__id = data.get('id', None)
				self.__token = data.get('token', None)
				logging.debug(f'Loaded user {self.__id} creds')
		except Exception as e:
			raise Exception(f'Failed to get user creds: {str(e)}')

	def save(self):
		try:
			data = {
				'auth_url': self.__auth_url,
				'code': self.__code,
				'id': self.__id,
				'token' : self.__token,
			}
			with open(self.__file, 'w+') as f:
				f.write(json.dumps(data))
		except Exception as e:
			logging.error(f'Failed to save user creds: {str(e)}')

	def get(self, typ):
		try:
			if typ == 'id':
				return self.__id
			elif typ == 'token':
				return self.__token
			elif typ == 'code':
				return self.__code
			elif typ == 'type':
				return 'code'
			raise Exception(f'Invalid cred type {typ}')
		except Exception as e:
			logging.error(f'Failed to get cred: {str(e)}')
			return None

	def update(self, typ, val):
		try:
			if typ == 'id':
				self.__id = val
			elif typ == 'code':
				self.__code = val
			elif typ == 'token':
				self.__token = val
			elif typ == 'auth_url':
				self.__auth_url = val
			else:
				raise Exception(f'Invalid cred type {typ}')
			logging.debug(f'Updated {typ} to {val}')
		except Exception as e:
			logging.error(f'Failed to upate cred: {str(e)}')
