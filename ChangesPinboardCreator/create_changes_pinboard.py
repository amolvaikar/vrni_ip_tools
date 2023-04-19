from datetime import datetime
import sys
import requests
import json
from optparse import OptionParser
import ipaddress
import urllib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time
import smtplib, ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

sender = 'noreply@vmware.com'

def open_vrni_session(url, user_id, password):
	try:
		session = requests.Session()

		session.auth = (user_id, password)

		data = '{"username":"' + user_id + '","password":"' + password + '", "domain": {'

		domain_type = "LOCAL"
		domain_value = ""

		if not "@local" in user_id:
			#Looks like ad/ldap login
			domain_type = "LDAP"
			domain_value = user_id.split("@")[1]

		data += '"domain_type" : "' + domain_type + '","value":"' + domain_value + '"}}'

		# Instead of requests.get(), you'll use session.get()
		response = session.post(url+"/api/ni/auth/token", data=data, verify=False, headers={'content-type':'application/json', 'accept':'application/json'})
		#print response
		loaded_json = json.loads(response.content)
		session.headers["Authorization"] = "NetworkInsight " + loaded_json["token"]
		return session
	except requests.exceptions.ConnectionError as connection_exception:
		print ("Failed to connect to " + url)
		print (connection_exception.message)
	return None

def create_changes_pinboard(session, pinboard_name = "Important Changes"):
	# Steps:
	# 1. Create pinboard with the name provided as parameter
	# 2. Add pins for all the important entities and their CRUD
	# 3. Add pins for all the important metrics
	# 4. Add pins for all the important flow
	pinboard_id = create_pinboard(session, pinboard_name, "")
	if pinboard_id:
		for entity_type in ["NSX-T Transport Node", "Host"]:
			generate_crud_pinboards_for_entity_type(session, pinboard_id, entity_type)
	return

def generate_crud_pinboards_for_entity_type(session, pinboard_id, entity_type, create = True, update = True, delete = True):
	if create:
		# Add discovery pinboard:
		discovery_pinboard_name = "New {1} Discovered".format(entity_type)
		discovery_alert_name = "Entity type {1} discovered".format(entity_type)
		discovery_query = 'entity.name of change alert where message = "{1}"'.format(discovery_alert_name)
		add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

	if update:
		# Add property update pinboard:
		update_pinboard_name = "Changed {1}".format(entity_type)
		update_alert_name = "Entity type {1} properties updated".format(entity_type)
		update_query = 'change alert where message = "{1}" group by entity, changedProperties.propertyPath'.format(update_alert_name)
		add_pin_to_pinboard(session, pinboard_id, update_pinboard_name, update_query)

	if delete:
		# Add entity deleted pinboard:
		deletion_pinboard_name = "Deleted {1}".format(entity_type)
		deletion_alert_name = "Entity type {1} deleted".format(entity_type)
		deletion_query = 'entity.name of change alert where message = "{1}"'.format(deletion_alert_name)
		add_pin_to_pinboard(session, pinboard_id, deletion_pinboard_name, deletion_query)
def add_pin_to_pinboard(session, pinboard_id, pin_name, pin_query):
	body = '''{"name": "{1}", "query": "{2}"}'''.format(pin_name, pin_query)
	response = session.post(url+"/api/ni/pinboards/{id}/pins".format(pinboard_id), data=body, verify=False)
	loaded_json = json.loads(response.content)
	return

# returns the pinboard id if succcessful, None in case of failures.
def create_pinboard(session, pinboard_name, pinboard_description):
	body = '''{"name": "{1}", "description": "{2}"}'''.format(pinboard_name, pinboard_description)
	response = session.post(url+"/api/ni/pinboards", data=body, verify=False)
	if response.status == 201:
		loaded_json = json.loads(response.content)
		return loaded_json["id"]
	return None
def check_options(options):
	if options.target_email == "":
		print ("email id is mandatory")
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

	parser.add_option("-n", "--name",
					  dest="pinboard_name",
					  help="Name to be used for the important changes pinboard")


	(options, args) = parser.parse_args()

	if options.server is None or options.uid is None or options.password is None or options.pinboard_name is None:
		parser.print_help()
		print ("Insufficient arguments")
		sys.exit(1)

	if not check_options(options):
		sys.exit(1)

	url = "https://" + options.server
	user_id = options.uid
	password = options.password
	pinboard_name = options.pinboard_name
	session = open_vrni_session(url, user_id, password)
	if not session:
		print ("Unable to connect to vRNI")
		sys.exit(1)

	create_changes_pinboard(session, pinboard_name)
