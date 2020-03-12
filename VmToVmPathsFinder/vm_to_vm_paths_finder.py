
import sys
import requests
import json
from optparse import OptionParser
import ipaddress
import urllib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time


def check_options(options):
	return True

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


def get_all_suitable_vms(session):
	l2_to_vms_map = dict()
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
			vm_modek_key = result['searchContext']['modelKey']
			vm_name_plus_mk = vm_name + "+" + vm_modek_key
			if vm_l2 in l2_to_vms_map:
				l2_to_vms_map.get(vm_l2).append(vm_name_plus_mk)
			else:
				l2_to_vms_map[vm_l2] = [vm_name_plus_mk]

		current_len = len(found_vms['resultList'])
		start_idx += current_len
		vm_search_query = "/api/search/query?searchString=" + url_encoded_query + \
		                  "&includeObjects=false&includeFacets=true&includeMetrics=false&includeEvents=false&startIndex=" + str(start_idx) + \
		                  "&maxItemCount=" + str(ask_length) + "&dateTimeZone=%2B05%3A30&sourceString=USER&includeModelKeyOnly=true"
		response = session.get(url + vm_search_query, verify=False)
		found_vms = json.loads(response.content)
	return l2_to_vms_map

vm_pairs_list = []

def check_vm_to_vm_path(vm_pair, valid_vm_to_vm_paths, session):

	source_vm_name_mk = vm_pair[0]
	dest_vm_name_mk = vm_pair[1]
	source_vm_name, source_vm_mk = source_vm_name_mk.split('+')
	dest_vm_name, dest_vm_mk = dest_vm_name_mk.split('+')
	source_vm_mk_encoded = urllib.quote_plus(source_vm_mk)
	dest_vm_mk_encoded = urllib.quote_plus(dest_vm_mk)
	vm_to_vm_request = "/api/config/graph?graphLevel=L2_UNDERLAY_OVERLAY&graphType=VM_TO_VM_TOPOLOGY2&listOfObjects=" + source_vm_mk_encoded + "&listOfObjects=" + dest_vm_mk_encoded + "&includeUnderlay=true&time=" + str(long(time.time() * 1000))
	response = session.get(url + vm_to_vm_request, verify=False)
	found_vm_paths = json.loads(response.content)
	if response.status_code == 200:
		try:
			paths = found_vm_paths['paths']
			path_nodes = found_vm_paths['graph']['nodes']
			found_physical = False
			for path_node in path_nodes:
				if path_node['id'].split(":")[1] == "96":
					if len(path_node['data']['config']['subType']) > 0 and path_node['data']['config']['subType'][0] not in (1102, 1103):
						if paths[0]['partial'] == True:
							print "Path from " + source_vm_name + " to " + dest_vm_name + " could have physical routers, but only a **PARTIAL** path"
						else:
							print "Path from " + source_vm_name + " to " + dest_vm_name + " could have physical routers"
						found_physical = True
						break
			if not found_physical:
				print "Path from " + source_vm_name + " to " + dest_vm_name + " could work, but only in virtual network"
			valid_vm_to_vm_paths.add((source_vm_name, dest_vm_name))
		except Exception:
			pass

	#print found_vm_paths

def get_valid_vm_to_vm_paths(l2_to_vms_map, session):
	valid_vm_to_vm_paths = set()
	num_vlans = len(l2_to_vms_map)
	all_keys = l2_to_vms_map.keys()
	for i in range(0, num_vlans):
		for j in range(i+1, num_vlans):
			first_set_of_vms = l2_to_vms_map.get(all_keys[i])
			second_set_of_vms = l2_to_vms_map.get(all_keys[j])

			for first_vm in first_set_of_vms:
				for second_vm in second_set_of_vms:
					vm_pairs_list.append((first_vm, second_vm))

	for vm_pair in vm_pairs_list:
		check_vm_to_vm_path(vm_pair, valid_vm_to_vm_paths, session)

	print "Finding vm to vm path between " + first_set_of_vms[0] + "and " + second_set_of_vms[0]
	return valid_vm_to_vm_paths

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

	session = open_vrni_session(url, user_id, password)
	if not session:
		print "Unable to connect to vRNI"
		sys.exit(1)

	l2_to_vms_map = get_all_suitable_vms(session)

	valid_vm_to_vm_paths = get_valid_vm_to_vm_paths(l2_to_vms_map, session)

	print l2_to_vms_map