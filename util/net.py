from util.dates import curr_timestamp
import os

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

