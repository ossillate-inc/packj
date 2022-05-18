def human_format(number):
	from math import log, floor
	units = ['', 'K', 'M', 'G', 'T', 'P']
	k = 1000.0
	magnitude = int(floor(log(number, k)))
	val = '%.1f' % (number/k**magnitude)
	unit = '%s' % (units[magnitude])
	return '%s%s' % (val.rstrip('0').rstrip('.'), unit)
