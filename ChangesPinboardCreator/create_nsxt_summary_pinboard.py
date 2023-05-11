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

# def create_nsxt_summary_pinboard(session, pinboard_name, nsxt_manager_name):
#     pinboard_id = create_pinboard(session, pinboard_name, "")
#     print(pinboard_id)
#     if pinboard_id:
#         generate_nsxt_summary_pinboard(session, pinboard_id, nsxt_manager_name)
#     return


def get_nsxt_mks(session):
    data = '{"query": "NSX-T Manager"}'
    response = session.post(url+"/api/ni/search/ql", data=data, verify=False, headers={'content-type':'application/json', 'accept':'application/json'})
    print(response)
    nsxt_mks_names = {}
    if response.status_code != 200:
        print("Failed to authenticate")
        return

    loaded_json = json.loads(response.content)
    print(loaded_json)
    for nsxt_results in loaded_json["entity_list_response"]["results"]:
        nsxt_response = session.get(url+"/api/ni/entities/nsx-managers/"+nsxt_results["entity_id"], verify=False, headers={'content-type':'application/json', 'accept':'application/json'})
        print(nsxt_response)
        nsxt_loaded_json = json.loads(nsxt_response.content)
        print(nsxt_loaded_json)
        nsxt_mks_names[nsxt_loaded_json["entity_id"]] = nsxt_loaded_json["name"]
    print(nsxt_mks_names)
    return nsxt_mks_names

def create_nsxt_summary_pinboard(session, dashboard_name):
    nsxt_mks_names = get_nsxt_mks(session)
    for mk in nsxt_mks_names.keys():
        dashboard_name = "NSXT Manager "
        print(nsxt_mks_names[mk])
        dashboard_name += nsxt_mks_names[mk]
        print(dashboard_name)
        dashboard_id = create_pinboard(session, dashboard_name, "")
        print(dashboard_id)
        if dashboard_id:
            generate_nsxt_summary_pinboard(session, dashboard_id, nsxt_mks_names[mk], mk)

def generate_nsxt_summary_pinboard(session, pinboard_id, nsxt_manager_name, mk):
    print("generate_nsxt_manager_pinboards")

    discovery_pinboard_name = "Critical Open Alerts"
    discovery_query = "Alert where  status = 'OPEN' and Severity = 'Critical' and Manager  = '{}'".format(nsxt_manager_name)
    print(discovery_query)
    add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

    discovery_pinboard_name = "Warning Open Alerts"
    discovery_query = "Alert where  status = 'OPEN' and Severity = 'Warning' and Manager  = '{}'".format(nsxt_manager_name)
    print(discovery_query)
    add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

    discovery_pinboard_name = "Critical NSX-T System Alerts"
    discovery_query = "Alert where Severity = 'Critical' and status = 'OPEN' and Manager  = '{}' and type = 'NSX-T System Alert'".format(nsxt_manager_name)
    print(discovery_query)
    add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

    discovery_pinboard_name = "Critical, Warning Alerts for NSX-T Edge Transport Node"
    discovery_query = "Alert where (Severity = 'Critical' or Severity = 'Warning') and status = 'OPEN' and Manager  = '10.168.216.4' and  Problem Entity in (NSX-T Transport Node where manager = '10.168.216.4' and node type = 'Edgenode')".format(nsxt_manager_name)
    print(discovery_query)
    add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

    discovery_pinboard_name = "Top 10 Logical Switch by Rx packet drop ratio"
    discovery_query = "Rx Packet Drop Ratio of NSX-T Logical Switch where manager = '{}' order by Rx packet drop ratio desc limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

    discovery_pinboard_name = "Top 10 Logical Switch by Tx packet drop ratio"
    discovery_query = "Tx Packet Drop Ratio of NSX-T Logical Switch where manager = '{}' order by Tx packet drop ratio desc limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

    discovery_pinboard_name = "Top 10 Logical Port by Tx packet drop ratio"
    discovery_query = "Tx Packet Drop Ratio of NSX-T Logical Port where manager = '{}' order by Tx packet drop ratio desc limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

    discovery_pinboard_name = "Top 10 Logical Port by Rx packet drop ratio"
    discovery_query = "Rx Packet Drop Ratio of NSX-T Logical Port where manager = '{}' order by Rx packet drop ratio desc limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

    discovery_pinboard_name = "Top 10 Router Interface by Rx packet drop ratio"
    discovery_query = "Rx Packet Drop ratio of Router Interface where manager = '{}' order by Rx packet drop ratio desc limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

    discovery_pinboard_name = "Top 10 Router Interface by Tx packet drop ratio"
    discovery_query = "Tx Packet Drop ratio of Router Interface where manager = '{}' order by Tx packet drop ratio desc limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

    discovery_pinboard_name = "Top 10 Network Interface by Rx packet drop ratio"
    discovery_query = "Rx packet drop ratio of Network Interface where manager = '{}' order by Rx packet drop ratio limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

    discovery_pinboard_name = "Top 10 Network Interface by Tx packet drop ratio"
    discovery_query = "Tx packet drop ratio of Network Interface where manager = '{}' order by Tx packet drop ratio limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

    discovery_pinboard_name = "Top 10 Infra Consumption by VMs"
    discovery_query = "Rx PPs, Tx PPS, Network Rx Rate, Network Tx Rate of vm where NSX = '{}' order by  Total Network Traffic desc limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

    discovery_pinboard_name = "Top 10 NSX-T Transport Node memory usage"
    discovery_query = "nsx-t transport node where manager = '{}' order by mem.usage.absolute.latest.percent desc limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

    discovery_pinboard_name = "Top 10 NSX-T Transport Node 15 minutes cpu usage"
    discovery_query = "nsx-t transport node where manager = '{}' order by sys.loadFifteenMinutes.rate.latest.percent desc limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

    discovery_pinboard_name = "Firewall Rule by hit count"
    discovery_query = "firewall rule where manager = '{}' group by Rule ID, Name order by sum(Hit Count)".format(nsxt_manager_name)
    print(discovery_query)
    add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)


def add_pin_to_pinboard(session, pinboard_id, pin_name, pin_query):
    body = '''{{"name": "{0}", "query": "{1}"}}'''.format(pin_name, pin_query)
    response = session.post(url+"/api/ni/pinboards/{}/pins".format(pinboard_id), data=body, verify=False)
    print(response)
    loaded_json = json.loads(response.content)
    return

# returns the pinboard id if succcessful, None in case of failures.
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

    parser.add_option("-a", "--nsxt",
                      dest="nsxt_manager_name",
                      help="[Required] Name of the NSXT Manager to create pinboard")


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
    nsxt_manager_name = options.nsxt_manager_name
    session = open_vrni_session(url, user_id, password)
    if not session:
        print ("Unable to connect to vRNI")
        sys.exit(1)

    create_nsxt_summary_pinboard(session, pinboard_name)
