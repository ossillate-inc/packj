import logging
import git
import tempfile
import os
import shutil

from util.dates import ts_to_date_str, datetime_to_date_str

def replace_last(source_string, replace_what, replace_with):
	head, _sep, tail = source_string.rpartition(replace_what)
	return head + replace_with + tail
 
def git_clone(repo_url):
	try:
		clone_dir = tempfile.mkdtemp(prefix='clone-')
		os.environ['GIT_ASKPASS'] = 'false'
		os.environ['GIT_TERMINAL_PROMPT'] = '0'
		git.Git(clone_dir).clone(repo_url)
	except Exception as e:
		logging.debug("Failed to clone %s: %s" % (repo_url, str(e)))
		return "repo does not exit", None

	try:
		clone_dir = os.path.join(clone_dir, os.path.basename(repo_url))
		repo = git.Repo(clone_dir)
	except Exception as e:
		logging.debug("Failed to get parse repo at %s: %s" % (clone_dir, str(e)))
		return "invalid repo", None

	# tags
	try:
		tags = [(t.name, datetime_to_date_str(t.commit.committed_datetime)) for t in repo.tags]
	except Exception as e:
		logging.debug("Failed to get tags %s: %s" % (clone_dir, str(e)))
		tags = None

	# branches
	try:
		branches = [b.name for b in repo.remote().refs]
	except Exception as e:
		logging.debug("Failed to get branches %s: %s" % (clone_dir, str(e)))
		branches = None

	try:
		commits = []
		for commit in repo.iter_commits():
			commits.append(commit)
	except Exception as e:
		logging.debug("Failed to get commits %s: %s" % (clone_dir, str(e)))
		commits = None

	try:
		if commits:
			authors = set([commit.author.email for commit in commits])
	except Exception as e:
		logging.debug("Failed to get authors %s: %s" % (clone_dir, str(e)))
		authors = None

	shutil.rmtree(os.path.dirname(clone_dir))
	return None, {
		'commits'	: len(commits) if commits else None,
		'branches'	: len(branches),
		'tags'		: len(tags),
		'contributors' : len(authors),
	}
