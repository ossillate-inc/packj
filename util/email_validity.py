from pyisemail.diagnosis import ValidDiagnosis, InvalidDiagnosis, DNSDiagnosis 
from pyisemail import is_email
import sys
import dns

popular_domains = [
	"posteo.de",
	"umich.edu",
	"mozilla.com",
	"web.de",
	"users.sourceforge.net",
	"uw.edu",
	"sina.com",
	"cern.ch",
	"stanford.edu",
	"thapar.edu",
	"mit.edu",
	"berkeley.edu",
	"naver.com",
	"gmx.de",
	"microsoft.com",
	"google.com",
	"pm.me",
	"googlemail.com",
	"me.com",
	"example.com",
	"mail.ru",
	"redhat.com",
	"live.com",
	"foxmail.com",
	"icloud.com",
	"yandex.ru",
	"126.com",
	"googlegroups.com",
	"users.noreply.github.com",
	"yahoo.com",
	"protonmail.com",
	"hotmail.com",
	"outlook.com",
	"163.com",
	"qq.com",
	"gmail.com",
]

def check_email_address(address):
	if not address:
		return False, False
	try:
		bool_result = is_email(address)
	except Exception as e:
		return False, False
	
	try:
		domain = address.split('@')[1]
	except Exception as e:
		return False, False
	
	if domain not in popular_domains:
		try:
			ret = is_email(address, check_dns=True, diagnose=True)
			if isinstance(ret, ValidDiagnosis) and ret.code == 0:
				# "Address is valid."
				return True, True
			elif isinstance(ret, InvalidDiagnosis):
				return False, False
			elif isinstance(ret,  DNSDiagnosis):
				return bool_result, False

		except Exception as e:
			print("EXCEPTION: %s" % (str(e)))
			bool_result_with_dns = False
	else:
		bool_result_with_dns = bool_result
	return (bool_result, bool_result_with_dns)

if __name__ == "__main__":
	addr = sys.argv[1]
	ret = check_email_address(addr)
	print(addr, ret)
