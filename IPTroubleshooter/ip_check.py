

import sys
import requests
import json
from optparse import OptionParser
import ipaddress
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def open_vrni_session(url, user_id, password):
	try:
		session = requests.Session()

		session.auth = (user_id, password)

		data = '{"username":"' + user_id + '","password":"' + password + '","tenantName":"' + sys.argv[2] +\
			   '","vIDMURL":"","redirectURL":"","authenticationDomains":{'

		nDomains = 0
		domain_string = "localdomain"

		if not "@local" in user_id:
			#Looks like ad/ldap login
			nDomains = 1
			data += '"0":{"domainType":"LDAP","domain":"' + user_id.split("@")[1] + '","redirectUrl":""},'
			domain_string = user_id.split("@")[1]

		data += '"' + str(nDomains) + '":{"domainType":"LOCAL_DOMAIN","domain":"localdomain","redirectUrl":""}},'

		if nDomains == 1:
			nDomains = 2

		data +=	'"currentDomain":0,"domain":"' + domain_string + '","nDomains":' + str(nDomains) + ',"serverTimestamp":false,"loginFieldPlaceHolder":"Username"}'

		# Instead of requests.get(), you'll use session.get()
		response = session.post(url+"/api/auth/login", data=data, verify=False, headers={'content-type':'application/json', 'accept':'application/json'})
		#print response
		loaded_json = json.loads(response.content)
		session.headers["x-vrni-csrf-token"] = loaded_json["csrfToken"]
		return session
	except requests.exceptions.ConnectionError as connection_exception:
		print "Failed to connect to " + url
		print connection_exception.message
	return None



def ip_checking_wizard(session, ip_argument):
	try:
		# Step 1 - Check if IP is assigned to some entity
		start_idx = 0
		ask_length = 50
		ip_search_query = "/api/search/query?searchString=IP%20Endpoint%20where%20IP%20Address%20%3D%20" + str(ip_argument) + \
						  "&includeObjects=false&includeFacets=true&includeMetrics=false&includeEvents=false&startIndex=" + str(start_idx) +\
						  "&maxItemCount=" + str(ask_length) + "&dateTimeZone=%2B05%3A30&sourceString=USER&includeModelKeyOnly=false"
		response = session.get(url + ip_search_query, verify=False)
		found_ips = json.loads(response.content)
		if len(found_ips['resultList']) == 0:
			print "IP is not assigned to any entity known to vRNI"
			return
		else:
			print "IP " + ip_argument + " is assigned to " + response.content + " checking if it is online"

		# Step 2 - Check if the VM/Switch
	except requests.exceptions.ConnectionError as connection_exception:
		print "Failed to connect to " + url
		print connection_exception.message
		return None

def check_options(options):
	return True

if __name__ == '__main__':

	parser = OptionParser()
	parser.add_option("-d", "--destination", dest="server",
					  help="vRNI Server IP/fqdn")

	parser.add_option("-u", "--user",
					  dest="uid",
					  help="vRNI User")

	parser.add_option("-p", "--password",
					  dest="password",
					  help="vRNI User's password")

	parser.add_option("-i", "--ip",
					  dest="ipaddress",
					  help="IPv4 address to check for reachability issues")


	parser.add_option("-f", "--from",
					  dest="fromipaddress",
					  help="[Optional] IPv4 address from which the ip given in -i argument is not reachable")

	(options, args) = parser.parse_args()

	if options.server is None or options.uid is None or options.password is None or options.ipaddress is None:
		parser.print_help()
		print "Insufficient arguments"
		sys.exit(1)

	if not check_options(options):
		sys.exit(1)

	url = "https://" + options.server
	ip_argument = options.ipaddress
	user_id = options.uid
	password = options.password

	session = open_vrni_session(url, user_id, password)
	if not session:
		print "Unable to connect to vRNI"
		sys.exit(1)

	ip_checking_wizard(session, ip_argument)
