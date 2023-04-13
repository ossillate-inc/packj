import logging
import json

def parse_repo_data(service, repo_data):
	assert repo_data, "no data!"
	assert service in ['gitlab','github'], 'service %s not supported!' % (service)

	try:
		created_at = repo_data['created_at']
	except KeyError:
		created_at = None

	try:
		if service == 'gitlab':
			last_activity_at = repo_data['last_activity_at']
		elif service == 'github':
			last_activity_at = repo_data['updated_at']
	except KeyError:
		last_activity_at = None

	try:
		num_forks = repo_data['forks_count']
	except KeyError:
		num_forks = None

	num_stars = None
	try:
		if service == 'gitlab':
			num_stars = repo_data['star_count']
		elif service == 'github':
			num_stars = repo_data['stargazers_count']
	except KeyError:
		pass

	author = None
	try:
		if service == 'gitlab':
			if 'namespace' in repo_data:
				if repo_data['namespace']['kind'] == 'user':
					author = repo_data['namespace']['name']
				elif repo_data['namespace']['kind'] == 'group':
					author = repo_data['namespace']['name']
		elif service == 'github':
			if 'owner' in repo_data and 'login' in repo_data['owner']:
				author = repo_data['owner']['login']
	except KeyError:
		pass

	try:
		if service == 'github':
			repo_url = repo_data['html_url']
		elif service == 'gitlab':
			repo_url = repo_data['web_url']
	except KeyError:
		pass

	try:
		descr = repo_data['description']
	except KeyError:
		descr = None

	forked_from = None
	try:
		if service == 'github':
			if repo_data['fork'] and repo_data['parent'] and repo_data['parent']['html_url']:
				forked_from = repo_data['parent']['html_url']
			else:
				forked_from = None
		elif service == 'gitlab':
			if repo_data['parent'] and repo_data['parent']['web_url']:
				forked_from = repo_data['parent']['web_url']
			else:
				forked_from = None
	except KeyError:
		pass

	parsed_data = {
		'created' : created_at,
		'author' : author,
		'description' : descr,
		'last_activity' : last_activity_at,
		'num_stars' : num_stars,
		'num_forks' : num_forks,
		'forked_from' : forked_from,
	}
	if repo_url:
		parsed_data['url'] = repo_url
	return parsed_data

def fetch_gitlab_repo_data(token, repo_id):
	import gitlab
	logging.debug("fetching %s from gitlab" % (repo_id))

	try:
		gl = gitlab.Gitlab('https://gitlab.com', api_version=4, private_token=token)
	except:
		gl = gitlab.Gitlab('https://gitlab.com', api_version=4)
	assert gl, "NULL gl!"

	repository = gl.projects.get(repo_id)
	assert repository, "repo not found!"

	return parse_repo_data('gitlab', repository._attrs)

def fetch_github_repo_data(token, repo_id):
	from github3 import GitHub
	logging.debug("fetching %s from github" % (repo_id))

	try:
		gh = GitHub(token=token)
	except:
		gh = GitHub()
	assert gh, "NULL gh!"

	items = repo_id.split('/')
	if len(items) >= 2:
		owner = items[0]
		repo_name = items[1]
	else:
		raise Exception("repo not found!")

	repository = gh.repository(owner = owner, repository = repo_name)
	assert repository, "repo not found!"

	return parse_repo_data('github', repository.as_dict())

def fetch_repo_data(config, repo_url):
	tokens = config.get('tokens', dict())
	try:
		logging.debug("Request to dump repo %s data" % (repo_url))
		if repo_url.startswith('https://github.com/'):
			token = tokens.get('github', None)
			repo_id = repo_url.replace('https://github.com/','')
			ret = fetch_github_repo_data(token, repo_id)

		elif repo_url.startswith('http://github.com/'):
			token = tokens.get('github', None)
			repo_id = repo_url.replace('http://github.com/','')
			ret = fetch_github_repo_data(token, repo_id)

		elif repo_url.startswith('https://gitlab.com/'):
			token = tokens.get('gitlab', None)
			repo_id = repo_url.replace('https://gitlab.com/','')
			ret = fetch_gitlab_repo_data(token, repo_id)

		elif repo_url.startswith('http://gitlab.com/'):
			token = tokens.get('gitlab', None)
			repo_id = repo_url.replace('http://gitlab.com/','')
			ret = fetch_gitlab_repo_data(token, repo_id)

		else:
			raise Exception("%s not supported!" % (repo_url))
		return None, ret
	except Exception as e:
		logging.debug("Failed to analyze repo %s: %s" % (repo_url, str(e)))
		return str(e), None

if __name__ == "__main__":
	import json
	import sys
	import os
	dictionary = fetch_repo_data(sys.argv[1])
	json_object = json.dumps(dictionary, indent = 4)
	with open("sample.json", "w") as outfile:
		outfile.write(json_object)
