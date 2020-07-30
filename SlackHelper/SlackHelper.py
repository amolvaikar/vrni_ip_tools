
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

def getEvents(session):
	fromTime = 1596102869816
	toTime = 1596106740000
	event_search_query = "/api/search/query?searchString=open+problems&timestamp=1596106948788&timeRangeString=+between+timestamp+1596102869816+and+timestamp+1596106740000&includeObjects=false&includeFacets=false&includeMetrics=false&includeEvents=false&startIndex=0&maxItemCount=100&dateTimeZone=%2B05%3A30&sourceString=USER&includeModelKeyOnly=false&fetchQueryTelemetry=true&appDistributionEnabled=false&appletDistributionEnabled=false"
	response = session.get(url + event_search_query, verify=False)
	#print response
	found_events = json.loads(response.content)
	#print found_events
	requests = list()
	for event in found_events['resultList']:
		mk = event['searchContext']['modelKey']
		atTime = event['searchContext']['version']['lastModifiedTs']
		requests.append({"modelKey":mk, "time":atTime})
	#print requests
	object_fetch_query = "/api/config/objects"
	response = session.post(url+object_fetch_query, verify=False, data=json.dumps({"requests":requests}), headers={'content-type':'application/json', 'accept':'application/json'})
	objectsResponse = json.loads(response.content)
	for data in objectsResponse['data']:
		eventData = data['value']
		eventName = eventData['name']
		eventMessage = eventData['message']
		involvedEntities = ""
		for aentity in eventData['anchorEntities']:
			if aentity['name'] is not None:
				involvedEntities += aentity['name'] + " "
		print "Event Info:", eventName, eventMessage, involvedEntities, "\n"


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
	getEvents(session)