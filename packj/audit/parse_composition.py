from packj.util.files import read_json_from_file
import logging
import os

def parse_package_composition(pkg_name, ver_str, filepath):
	try:
		assert os.path.exists(filepath), f'{filepath} does not exist!'
		assert os.path.isfile(filepath), f'{filepath} is not a file!'

		data = read_json_from_file(filepath)
		assert data and len(data), 'invalid data!'

		num_files = 0
		total_loc = 0
		num_funcs = 0
		lang_files = 0
		bin_files = 0

		if 'Files' in data and data['Files']:
			for f in data['Files']:
				num_files += 1
				try:
					if f['Native'] == True:
						lang_files += 1
				except:
					pass
				try:
					if f['Binary'] == True:
						bin_files += 1
				except:
					pass
				try:
					total_loc += f['LoC']
				except:
					pass

		if 'Functions' in data and data['Functions']:
			num_funcs = len(data['Functions'])

		return num_files, lang_files, bin_files, num_funcs, total_loc
	except Exception as e:
		logging.debug("Failed to parse package %s (ver %s) composition: %s" % \
			(pkg_name, ver_str if ver_str else 'latest', str(e)))
		return None, None, None, None
