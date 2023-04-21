import sys
import requests
import json
from optparse import OptionParser
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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

		if response.status_code != 200:
			print("Failed to authenticate")
			return

		loaded_json = json.loads(response.content)
		session.headers["Authorization"] = "NetworkInsight " + loaded_json["token"]
		session.headers["Content-Type"] = "application/json"
		session.headers["Accept"] = "application/json"
		session.auth = None
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
		for entity_type in ["NSX-T Transport Node", "Host", "NSX-T Edge Cluster", "NSX-T Layer2 Network", "VRF"]:
			generate_crud_pinboards_for_entity_type(session, pinboard_id, entity_type)
		generate_problem_alert_pinboard(session, pinboard_id)
		generate_flows_pinboard(session, pinboard_id)
		generate_topology_change_pinboard(session, pinboard_id)
		generate_metrics_pinboard(session, pinboard_id)
	return

def generate_crud_pinboards_for_entity_type(session, pinboard_id, entity_type, create = True, update = True, delete = True):
	if create:
		# Add discovery pinboard:
		discovery_pinboard_name = "New {} Discovered".format(entity_type)
		discovery_alert_name = "Entity type {} discovered".format(entity_type)
		discovery_query = 'entity.name of change alert where message = \\"{}\\"'.format(discovery_alert_name)
		add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

	if update:
		# Add property update pinboard:
		update_pinboard_name = "Changed {}".format(entity_type)
		update_alert_name = "Entity type {} properties updated".format(entity_type)
		update_query = 'change alert where message = \\"{}\\" group by entity, changedProperties.propertyPath'.format(update_alert_name)
		add_pin_to_pinboard(session, pinboard_id, update_pinboard_name, update_query)

	if delete:
		# Add entity deleted pinboard:
		deletion_pinboard_name = "Deleted {}".format(entity_type)
		deletion_alert_name = "Entity type {} deleted".format(entity_type)
		deletion_query = 'entity.name of change alert where message = \\"{}\\"'.format(deletion_alert_name)
		add_pin_to_pinboard(session, pinboard_id, deletion_pinboard_name, deletion_query)

def generate_problem_alert_pinboard(session, pinboard_id):
	add_pin_to_pinboard(session, pinboard_id, "NSX-T related alerts", "open problem where Alert Tags =  'NSX-T' group by name, severity")

def generate_flows_pinboard(session, pinboard_id):
	# Daily flow count comparison, doesnt work for 6.6, but works 6.7 onwards.
	# daily_flow_count_pin_query = "count of flows {} days ago"
	# day_count = 5
	# for x in range(day_count, 1, -1):
	# 	add_pin_to_pinboard(session, pinboard_id, daily_flow_count_pin_query.format(x), daily_flow_count_pin_query.format(x))
	# add_pin_to_pinboard(session, pinboard_id, "Todays Flows", "count of flows today")

	services_accessed_query = """Flows where Flow Type = 'East-West' and Service Endpoint is set and Service Endpoint not in (list(Service Endpoint) of Flows where Flow Type = 'East-West' until 24 hours ago) group by Service Endpoint """
	services_accessed_name = "New Internal Services accessed"
	add_pin_to_pinboard(session, pinboard_id, services_accessed_name, services_accessed_query)

def generate_topology_change_pinboard(session, pinboard_id):
	topology_change_query = "change alert where message = 'Entity type VRF properties updated' and changedProperties.propertyPath in ('neighborVRFs', 'defaultNextHopRouterInterfaces')"
	topology_change_name = 'Changes in L3 topology'
	add_pin_to_pinboard(session, pinboard_id, topology_change_name, topology_change_query)

def generate_metrics_pinboard(session, pinboard_id):
	cpu_mem_tn_query = 'series(max(Memory Usage Rate)), series(max(cpu usage)) of NSX-T Transport Nodes group by name'
	cpu_mem_tn_name = 'Memory and CPU usage for Transport Nodes'
	add_pin_to_pinboard(session, pinboard_id, cpu_mem_tn_name, cpu_mem_tn_query)
	cpu_mem_host_query = 'series(max(Memory Usage Rate)), series(max(cpu usage)) of host group by name'
	cpu_mem_host_name = 'Memory & CPU usage for Hosts'
	add_pin_to_pinboard(session, pinboard_id, cpu_mem_host_name, cpu_mem_host_query)

	network_host_query = 'series(max(Max Packet Drop)), series(max(max network rate)) of hosts group by name'
	network_host_name = 'Network Usage for Hosts'
	add_pin_to_pinboard(session, pinboard_id, network_host_name, network_host_query)

	iops_today = 'avg(RW IOPS) of Hosts today'
	add_pin_to_pinboard(session, pinboard_id, iops_today, iops_today)
	iops_yesterday = 'avg(RW IOPS) of Hosts yesterday'
	add_pin_to_pinboard(session, pinboard_id, iops_yesterday, iops_yesterday)
	iops_avg_till_3_days_ago = 'avg(RW IOPS) of Hosts until 3 days ago'
	add_pin_to_pinboard(session, pinboard_id, iops_avg_till_3_days_ago, iops_avg_till_3_days_ago)

	system_uptime_host = 'System Uptime of host in last 15 minutes'
	add_pin_to_pinboard(session, pinboard_id, system_uptime_host, system_uptime_host)
	system_uptime_tn = 'System Uptime of NSX-T Transport Nodes in last 15 minutes'
	add_pin_to_pinboard(session, pinboard_id, system_uptime_tn, system_uptime_tn)


def add_pin_to_pinboard(session, pinboard_id, pin_name, pin_query):
	body = '''{{"name": "{0}", "query": "{1}"}}'''.format(pin_name, pin_query)
	response = session.post(url+"/api/ni/pinboards/{}/pins".format(pinboard_id), data=body, verify=False)
	if response.status_code != 201:
		print("Failed to create pin for {}".format(pin_name))
	loaded_json = json.loads(response.content)
	return

# returns the pinboard id if successful, None in case of failures.
def create_pinboard(session, pinboard_name, pinboard_description):
	body = '''{{"name": "{0}", "description": "{1}"}}'''.format(pinboard_name, pinboard_description)
	response = session.post(url+"/api/ni/pinboards", data=body, verify=False)
	if response.status_code == 201:
		loaded_json = json.loads(response.content)
		return loaded_json["id"]
	print("Failed to create pinboard, please check if the pinboard already exists or if you have used admin/member login credentials")
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

	parser.add_option("-n", "--name",
					  dest="pinboard_name",
					  help="[Optional] Name to be used for the important changes pinboard")


	(options, args) = parser.parse_args()

	if options.server is None or options.uid is None or options.password is None:
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
