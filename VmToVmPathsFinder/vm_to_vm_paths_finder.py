
import sys
import requests
import json
from optparse import OptionParser
import ipaddress
import urllib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_options(options):
	return True

def get_all_suitable_vms(url, user_id, password):
	l2_to_vms_map = dict()
	with requests.Session() as session:
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

		start_idx = 0
		ask_length = 50

		url_encoded_query = urllib.quote_plus("L2 Network, name of VM where Power State = 'POWEREDON' and L2 Network is set and Default Gateway is set and VMTools Status = 'guestToolsRunning' and  ( VMTools Config Status  =  'GuestToolsCurrent' or VMTools Config Status = 'GuestToolsSupportedOld' ) and Default Gateway Router Interface is set")

		#"vlan%2C%20name%20of%20VM%20where%20Power%20State%20%3D%20'POWEREDON'%20and%20L2%20Network%20is%20set%20and%20Default%20Gateway%20is%20set%20and%20VMTools%20Status%20%3D%20'guestToolsRunning'%20and%20%20(%20VMTools%20Config%20Status%20%20%3D%20%20'GuestToolsCurrent'%20or%20VMTools%20Config%20Status%20%3D%20'GuestToolsSupportedOld'%20)%20and%20Default%20Gateway%20Router%20Interface%20is%20set"
		vm_search_query = "/api/search/query?searchString=" + url_encoded_query + \
						  "&includeObjects=false&includeFacets=true&includeMetrics=false&includeEvents=false&startIndex=" + str(start_idx) +\
						  "&maxItemCount=" + str(ask_length) + "&dateTimeZone=%2B05%3A30&sourceString=USER&includeModelKeyOnly=true"

		response = session.get(url+vm_search_query, verify=False)
		print response
		found_vms = json.loads(response.content)
		while len(found_vms['resultList']) > 0:
			for result in found_vms['resultList']:
				vm_l2 = result['searchContext']['extraPropMap']['layer2Networks.name'][0]
				vm_name = result['searchContext']['extraPropMap']['name'][0]
				if vm_l2 in l2_to_vms_map:
					l2_to_vms_map.get(vm_l2).append(vm_name)
				else:
					l2_to_vms_map[vm_l2] = [vm_name]

			current_len = len(found_vms['resultList'])
			start_idx += current_len
			vm_search_query = "/api/search/query?searchString=" + url_encoded_query + \
			                  "&includeObjects=false&includeFacets=true&includeMetrics=false&includeEvents=false&startIndex=" + str(start_idx) + \
			                  "&maxItemCount=" + str(ask_length) + "&dateTimeZone=%2B05%3A30&sourceString=USER&includeModelKeyOnly=true"
			response = session.get(url + vm_search_query, verify=False)
			found_vms = json.loads(response.content)
	return l2_to_vms_map

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

	(options, args) = parser.parse_args()

	if options.server is None or options.uid is None or options.password is None:
		parser.print_help()
		print "Insufficient arguments"
		sys.exit(1)

	if not check_options(options):
		sys.exit(1)

	url = "https://" + options.server
	user_id = options.uid
	password = options.password

	l2_to_vms_map = get_all_suitable_vms(url, user_id, password)

	print l2_to_vms_map