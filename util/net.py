from util.dates import curr_timestamp
import os

def __parse_url(url):
	try:
		import six
		if six.PY2:
			from urlparse import urlparse												
		elif six.PY3:																	
			from urllib.parse import urlparse											
		return urlparse(url)
	except Exception as e:
		raise Exception(str(e))

def __open_url(url):
	try:
		import six
		if six.PY2:
			from urllib2 import urlopen
		elif six.PY3:																	
			from urllib.request import urlopen
		return urlopen(url)
	except Exception as e:
		raise Exception(str(e))

def check_domain_popular(url):													
	try:
		url_parts = __parse_url(url)												
		from tldextract import extract
		subdomain, domain, suffix = extract(url)
	except Exception as e:
		print(str(e))
		return False

	try:
		from io import BytesIO
		from zipfile import ZipFile
		domain_list_url = 'http://s3.amazonaws.com/alexa-static/top-1m.csv.zip'		
		resp = __open_url(domain_list_url)
		zipfile = ZipFile(BytesIO(resp.read()))
		domain_list = []
		for line in zipfile.open(zipfile.namelist()[0]).readlines():				
			rank, dom = line.strip().decode('utf-8').split(',')					
			domain_list.append(dom)												
		return domain in domain_list and url_parts.path==''
	except Exception as e:															
		print("check_domain_popular (%s): %s" % (url, str(e)))						
		return False

def check_site_exist(url, check_validity=False):
	try:
		if check_validity:
			url_parts = __parse_url(url)
	except:
		return False

	try:
		import requests
		resp = requests.head(url, allow_redirects=True)
		resp.raise_for_status()
		return resp.status_code == 200
	except Exception as e:
		print("check_site_exist (%s): %s" % (url, str(e)))
		return False
def download_file(url, filepath=None, mode='wb+'):
	assert url, "NULL url"
	if not filepath:
		import tempfile
		import datetime
		download_dir = tempfile.mkdtemp(prefix='download-%s' % (curr_timestamp()))
		try:
			filename=url.rsplit('/', 1)[-1]
		except:
			filename="%s" % (curr_timestamp())
		filepath = os.path.join(download_dir, filename)
	try:
		# fetch and write to file
		size = 0
		with open(filepath, mode) as f:
			for content in make_request_stream(url, stream_size=8192):
				f.write(content)
				size += len(content)
		return filepath, size
	except Exception as e:
		raise Exception("Failed to download %s: %s" % (url, str(e)))

def make_request(url, headers=None, params=None):
	try:
		import requests
		resp = requests.get(url=url, headers=headers, params=params)
		resp.raise_for_status()
		return resp
	except ImportError as e:
		print("'requests' module not available. Please install.")
		exit(1)
	except Exception as e:
		raise Exception("Failed to make request: %s" % (str(e)))

def make_request_stream(url, stream_size, headers=None, params=None):
	try:
		import requests
		with requests.get(url=url, headers=headers, params=params, stream=True) as resp:
			resp.raise_for_status()
			for chunk in resp.iter_content(stream_size):
				yield chunk
	except ImportError as e:
		print("'requests' module not available. Please install.")
		exit(1)
	except Exception as e:
		raise Exception("Failed to make request: %s" % (str(e)))

