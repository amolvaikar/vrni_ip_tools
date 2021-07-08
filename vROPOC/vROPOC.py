
import sys
import requests
import json
from optparse import OptionParser
import ipaddress
import urllib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time
import re

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

def open_vro_session(url, user_id, password):
	try:
		session = requests.Session()

		session.auth = (user_id, password)

		data = '{"username":"' + user_id + '","password":"' + password + '"}'

		# Get refresh token as first step
		response = session.post(url+"/csp/gateway/am/api/login?access_token", data=data, verify=False, headers={'content-type':'application/json', 'accept':'application/json'})
		#print response
		loaded_json = json.loads(response.content)
		refreshToken = loaded_json["refresh_token"]

		data = '{ "refreshToken":"' + refreshToken + '"}'
		# Get bearer token as second step
		response = session.post(url+"/iaas/api/login", data=data, verify=False, headers={'content-type':'application/json', 'accept':'application/json'})
		#print response
		loaded_json = json.loads(response.content)
		token = loaded_json["token"]
		session.headers["csp-auth-token"] = loaded_json["token"]
		return session
	except requests.exceptions.ConnectionError as connection_exception:
		print "Failed to connect to " + url
		print connection_exception.message
	return None

def sendEvents(vrnisession, vrosession, fromTime=None, toTime=None):
	if fromTime is None:
		#if user has not given time, we will ask for events from last 5 minutes
		toTime = int(round(time.time() * 1000))
		fromTime = toTime - (69680 * 60 * 1000)

	# Get events modelKey list of last 5 minutes
	event_search_query = "/api/search/query?searchString=" + urllib.quote_plus("open problems where Alert Name = 'link mtu mismatch alert' and timestampinms >= " + str(fromTime) + " and timestampinms <= " + str(toTime)) +\
						 "&timestamp=1596106948788&timeRangeString=+between+timestamp+" + str(fromTime) + "+and+timestamp+" + str(toTime) + \
						 "&includeObjects=false&includeFacets=false&includeMetrics=false&includeEvents=false&startIndex=0&maxItemCount=100&dateTimeZone=%2B05%3A30&sourceString=USER&includeModelKeyOnly=false&fetchQueryTelemetry=true&appDistributionEnabled=false&appletDistributionEnabled=false"

	response = vrnisession.get(url + event_search_query, verify=False)
	if response.status_code != 200:
		print "Failure in fetching event model keys from vrni: " + response.reason
		return

	found_events = json.loads(response.content)
	#print found_events
	objRequests = list()
	for event in found_events['resultList']:
		mk = event['searchContext']['modelKey']
		atTime = event['searchContext']['version']['lastModifiedTs']
		objRequests.append({"modelKey":mk, "time":atTime})

	#Get event objects for mks received above
	object_fetch_query = "/api/config/objects"
	response = vrnisession.post(url + object_fetch_query, verify=False, data=json.dumps({"requests":objRequests}), headers={'content-type': 'application/json', 'accept': 'application/json'})
	objectsResponse = json.loads(response.content)

	#For all received objects, convert them to slack format and send it to slack
	for data in objectsResponse['data']:
		finalobject = '''{
  "parameters": [
       {
            "value": {
                "string": {
                    "value": "10.40.13.36"
                }
            },
            "type": "string",
            "name": "hostNameOrIP",
            "scope": "local"
        },
        {
            "value": {
                "number": {
                    "value": 22.0
                }
            },
            "type": "number",
            "name": "port",
            "scope": "local"
        },
        {
            "value": {
                "string": {
                    "value": "admin"
                }
            },
            "type": "string",
            "name": "username",
            "scope": "local"
        },
        {
            "value": {
                "secure-string": {
                    "value": "Vnera655",
                    "isPlainText":true
                }
            },
            "type": "SecureString",
            "name": "password",
            "scope": "local"
        },
        {
            "value": {
                "string": {
                    "value": "show version"
                }
            },
            "type": "string",
            "name": "cmd",
            "scope": "local"
        },
        {
            "value": {
                "boolean": {
                    "value": true
                }
            },
            "type": "boolean",
            "name": "passwordAuthentication",
            "scope": "local"
        }
  ]
}'''
		responseSlack = vrosession.post(vrourl + "/vco/api/workflows/90808080808080808080808080808080D28080800120523434428525559a3425f/executions", data=finalobject, verify=False,
					 headers={'content-type': 'application/json', 'accept': 'application/json'})
		print responseSlack
		break


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

	parser.add_option("-o", "--vrourl",
					  dest="vrourl",
					  help="URL For vRO API")

	parser.add_option("-q", "--vrouid",
					  dest="vrouid",
					  help="User Id For vRO API")

	parser.add_option("-r", "--vropasswd",
					  dest="vropasswd",
					  help="Password For vRO API")

	(options, args) = parser.parse_args()

	if options.server is None or \
			options.uid is None or \
			options.password is None or \
			options.vrourl is None or \
			options.vrouid is None or \
			options.vropasswd is None:
		parser.print_help()
		print "Insufficient arguments"
		sys.exit(1)

	if not check_options(options):
		sys.exit(1)

	url = "https://" + options.server
	user_id = options.uid
	password = options.password
	vrourl = options.vrourl
	vrouid = options.vrouid
	vropasswd = options.vropasswd

	session = open_vrni_session(url, user_id, password)
	if not session:
		print "Unable to connect to vRNI"
		sys.exit(1)

	vroSession = open_vro_session(vrourl, vrouid, vropasswd)

	sendEvents(session, vroSession)