def date_timestamp(date):
	import sys
	if sys.version_info[0] < 3 or sys.version_info[1] < 4:
		# python version < 3.3
		import time
		def timestamp(date):
			return time.mktime(date.timetuple())
	else:
		def timestamp(date):
			return date.timestamp()

def curr_timestamp():
	import datetime
	return date_timestamp(datetime.datetime.now())

def date_str_to_datetime(date_str, fmt=None):
	try:
		if not date_str:
			return None
		if fmt:
			from datetime import datetime
			ret = datetime.strptime(date_str, fmt)
		else:
			from dateutil import parser
			ret = parser.parse(date_str)
		return ret
	except Exception as e:
		raise Exception("Failed to get datetime from date string %s: %s" % (date_str, str(e)))

def datetime_delta(date_str1, date_str2=None, days=None):
	try:
		import datetime

		date1 = date_str_to_datetime(date_str1)
		if not date_str2:
			date2 = datetime.datetime.now()
		else:
			date2 = date_str_to_datetime(date_str2)

		delta = date2 - date1
		if days:
			return delta.days
		return delta
	except Exception as e:
		raise Exception("Failed to get datetime delta between %s and %s: %s" % \
				(date_str1, date_str2 if date_str2 else 'now()', str(e)))
