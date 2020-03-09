

import sys
import requests
import json
from optparse import OptionParser
import ipaddress
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_existing_ips(url, user_id, password, subnet):
	existing_ip_set = set()
	with requests.Session() as session:
		session.auth = (user_id, password)

		data = '{"username":"' + user_id + '","password":"' + password + '","tenantName":"' + sys.argv[1] +\
			   '","vIDMURL":"","redirectURL":"","authenticationDomains":{"0":{"domainType":"LOCAL_DOMAIN","domain":"localdomain","redirectUrl":""}},'+\
			   '"currentDomain":0,"domain":"localdomain","nDomains":1,"serverTimestamp":false,"loginFieldPlaceHolder":"Username"}'

		try:
			response = session.post(url+"/api/auth/login", data=data, verify=False, headers={'content-type':'application/json', 'accept':'application/json'})
			#print response
			loaded_json = json.loads(response.content)
			if loaded_json["responseMessage"] == "AuthenticationException":
				print "Failed to connect to " + url + " owing to authentication failure, please check userid and password"
				return None

			session.headers["x-vrni-csrf-token"] = loaded_json["csrfToken"]

			start_idx = 0
			ask_length = 50
			ip_search_query = "/api/search/query?searchString=IP%20Endpoint%20where%20IP%20Address%20%3D%20" + str(subnet) + \
							  "&includeObjects=false&includeFacets=true&includeMetrics=false&includeEvents=false&startIndex=" + str(start_idx) +\
							  "&maxItemCount=" + str(ask_length) + "&dateTimeZone=%2B05%3A30&sourceString=USER&includeModelKeyOnly=false"
			response = session.get(url+ip_search_query, verify=False)
			#print response
			found_ips = json.loads(response.content)
			while len(found_ips['resultList']) > 0:
				for result in found_ips['resultList']:
					existing_ip_set.add(result['searchContext']['name'])
				current_len = len(found_ips['resultList'])
				start_idx += current_len
				ip_search_query = "/api/search/query?searchString=IP%20Endpoint%20where%20IP%20Address%20%3D%20" + str(subnet) + \
								  "&includeObjects=false&includeFacets=true&includeMetrics=false&includeEvents=false&startIndex=" + str(start_idx) + \
								  "&maxItemCount=" + str(ask_length) + "&dateTimeZone=%2B05%3A30&sourceString=USER&includeModelKeyOnly=false"
				response = session.get(url + ip_search_query, verify=False)
				found_ips = json.loads(response.content)
		except requests.exceptions.ConnectionError as connection_exception:
			print "Failed to connect to " + url
			print connection_exception.message
			return None

	return existing_ip_set

def check_options(options):
	if "/" not in options.subnet:
		print "Incorrect format for subnet parameter. Be sure to include the length. Sample format: 192.168.21.0/24"
		return False
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

	parser.add_option("-s", "--subnet",
					  dest="subnet",
					  help="subnet to search in. e.g.: 192.168.21.0/24")

	(options, args) = parser.parse_args()

	if options.server is None or options.uid is None or options.password is None or options.subnet is None:
		parser.print_help()
		print "Insufficient arguments"
		sys.exit(1)

	if not check_options(options):
		sys.exit(1)

	url = "https://" + options.server
	ip_argument = options.subnet
	user_id = options.uid
	password = options.password
	subnet = options.subnet

	existing_ip_set = get_existing_ips(url, user_id, password, subnet)

	if existing_ip_set is None:
		sys.exit(1)

	theoretical_ip_set = ipaddress.IPv4Network(unicode(subnet, "utf-8"))

	# print existing_ip_set
	# print theoretical_ip_set

	print "Free IP addresses in given subnet:"
	free_ips = 0
	total_ips = 0
	for tip in theoretical_ip_set:
		total_ips += 1
		if not tip.compressed in existing_ip_set:
			print tip
			free_ips += 1

	print "Found", free_ips, "free IPs, out of", total_ips, "IPs in", subnet


