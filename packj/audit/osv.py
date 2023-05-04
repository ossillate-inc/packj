import requests
import urllib
from re import match

def __fetch_vuln_data(pm_name, pkg_name, ver_str):
	if pm_name.lower() == 'pypi':
		pm_name = 'PyPI'
	elif pm_name.lower() == 'npm':
		pm_name = 'npm'
	elif pm_name.lower() == 'rubygems':
		pm_name = 'RubyGems'
	elif pm_name.lower() == 'cargo':
		pm_name = 'cargo'
	assert pm_name in ['PyPI', 'npm', 'RubyGems','cargo'], "CVE checking for package manager %s not supported" % (pm_name)
	data = {
		"version": ver_str,
		"package": {
			"name": pkg_name.lower(),
			"ecosystem": pm_name,
		}
	}
	url = 'https://api.osv.dev/v1/query'
	resp = requests.post(url=url, json=data)
	resp.raise_for_status()
	return resp.json()

def get_pkgver_vulns(pm_name, pkg_name, ver_str):
	vuln_data = None
	try:
		vuln_data_dict = __fetch_vuln_data(pm_name, pkg_name, ver_str)
		if not len(vuln_data_dict):
			return []
		assert 'vulns' in vuln_data_dict, "invalid CVE data format: 'vulns' missing!"

		vuln_data_list = vuln_data_dict['vulns']
		assert isinstance(vuln_data_list, list), "invalid CVE data format: not a list!"

		vuln_list = []
		for vuln_data in vuln_data_list:

			# get a vulnerability ID
			try:
				vuln_ids = vuln_data['aliases']
			except KeyError:
				vuln_ids = None
				continue

			# pick one, preference for CVEs
			cves = list(filter(lambda v: match('^CVE-.+$', v), vuln_ids))
			if cves:
				vuln_id = cves[0]
			else:
				vuln_id = vuln_ids[0]

			# source
			try:
				vuln_ref_url = vuln_data['references'][0]['url']
			except KeyError:
				vuln_ref_url = None

			vuln_list.append({
				'id'		: vuln_id,
				'ref_url'	: vuln_ref_url,
			})
		return vuln_list
	except Exception as e:
		raise Exception("Failed to get CVEs: %s" % (str(e)))

if __name__ == "__main__":
	import sys
	if len(sys.argv) != 4:
		print("%s <package manager name> <package name> <version string>" % (sys.argv[0]))
		exit(1)
	vuln_list = get_pkgver_vulns(sys.argv[1], sys.argv[2], sys.argv[3])
	print(vuln_list)
