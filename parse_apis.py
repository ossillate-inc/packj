from util.files import read_from_csv, read_json_from_file
 
def parse_api_usage(pm_name, filepath):
	if pm_name == 'pypi':
		apis2perms_filepath = 'config/python_api/apis2perms.csv'
	else:
		raise Exception('%s not supported!' % (pm_name))

	apis2perms = {}
	for line in read_from_csv(apis2perms_filepath):
		api = line[0]
		perm = line[1]
		if api not in apis2perms:
			apis2perms[api] = perm

	#print(apis2perms)
	perms = []

	usage_data = read_json_from_file(filepath)
	if not usage_data or 'pkgs' not in usage_data or \
		not isinstance(usage_data['pkgs'], list) or \
		len(usage_data['pkgs']) != 1 or \
		'apiResults' not in usage_data['pkgs'][0]:
		return None

	for api_usage in usage_data['pkgs'][0]['apiResults']:
		api = api_usage['fullName']
		if api == 'os.environ.get':
			perms.append('SOURCE_ENVVAR')
		elif api in apis2perms:
			perms.append(apis2perms[api])
	return set(perms)
