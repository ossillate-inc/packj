import os
import inspect

from util.files import read_from_csv, read_json_from_file
 
def parse_api_usage(pm_name, filepath):
	cwd = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
	config_dir= os.path.join(cwd, 'config')
	if pm_name == 'pypi':
		api_dir = os.path.join(config_dir, 'python_api')
	elif pm_name == 'npm':
		api_dir = os.path.join(config_dir, 'javascript_api')
	elif pm_name == 'rubygems':
		api_dir = os.path.join(config_dir, 'rubygems_api')
	else:
		raise Exception('API parser for %s not supported!' % (pm_name))

	apis2perms_filepath = os.path.join(api_dir, 'apis2perms.csv')
	assert os.path.exists(apis2perms_filepath), f'{apis2perms_filepath} does not exist'

	apis2perms = {}
	for line in read_from_csv(apis2perms_filepath):
		api = line[0]
		perm = line[1]
		if api not in apis2perms:
			apis2perms[api] = perm

	perms = {}

	usage_data = read_json_from_file(filepath)
	if not usage_data or 'pkgs' not in usage_data or \
		not isinstance(usage_data['pkgs'], list) or \
		len(usage_data['pkgs']) != 1 or \
		'apiResults' not in usage_data['pkgs'][0]:
		return None

	for api_usage in usage_data['pkgs'][0]['apiResults']:
		api = api_usage['fullName']
		try:
			usage = {
				"filepath": api_usage['range']['start']['fileInfo']['file'],
				"api_name" : api_usage['name'],
				"lineno": str(api_usage['range']['start']['row']),
			}
		except:
			usage = None

		try:
			p = apis2perms[api]
		except KeyError:
			p = None

		if p and usage:
			if p not in perms:
				perms[p] = []
			perms[p].append(usage)
	return perms
