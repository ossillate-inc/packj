from util.json_wrapper import json_loads

# loads @data from @filename
def read_dict_from_file(filename):
	try:
		data = {}
		with open(filename, 'r') as f:
			data = eval(f.read())
			f.close()
		return data
	except Exception as e:
		raise Exception("Failed to read dict from file %s: %s" % (filename, str(e)))

def read_json_from_file(filepath):
	try:
		import json
	except ImportError as e:
		raise Exception("'json' module not available. Please install.")
	try:
		with open(filepath, "r") as f:
			return json_loads(f.read())
	except Exception as e:
		raise Exception("Failed to load json data from file %s: %s" % (filepath, str(e)))

def read_from_csv(filename, skip_header=False):
	import csv
	with open(filename, 'r') as csvfile:
		reader = csv.reader(csvfile, delimiter=',')
		if skip_header:
			next(reader)
		for row in reader:
			if len(row) and not row[0].startswith('#'):
				yield row
