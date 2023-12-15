def nearest(tuple_list, pivot):
	return min(tuple_list, key=lambda x: abs(x[1] - pivot))

def ts_to_date_str(tstamp:float, fmt:str='%m-%d-%Y'):
	try:
		import datetime
		if not tstamp:
			return None
		return datetime.datetime.fromtimestamp(tstamp).strftime(fmt)
	except Exception as e:
		raise Exception("Failed to get date string from timestamp %s: %s" % (tstamp, str(e)))

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

def datetime_to_date_str(date, fmt='%m-%d-%Y'):
	try:
		import datetime
		if not date:
			return None
		return date.strftime(fmt)
	except Exception as e:
		raise Exception("Failed to get date string from datetime %s: %s" % (date, str(e)))

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

def datetime_delta(date1, date2=None, days=False):
	try:
		import datetime
		import pytz
		
		utc=pytz.UTC

		if isinstance(date1, str):
			date1 = date_str_to_datetime(date1)
		if not date2:
			date2 = datetime.datetime.now()
		elif isinstance(date2, str):
			date2 = date_str_to_datetime(date2)

		delta = date2.replace(tzinfo=utc) - date1.replace(tzinfo=utc)
		if days:
			return abs(delta.days)
		return delta
	except Exception as e:
		raise Exception("Failed to get datetime delta between %s and %s: %s" % \
				(date1, date2 if date2 else 'now()', str(e)))
