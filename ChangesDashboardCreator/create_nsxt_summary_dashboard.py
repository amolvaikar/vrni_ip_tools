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

        # data = '{"username":"' + user_id + '","password":"' + password + '", "domain": "localdomain"}'

        data = '{"username":"' + user_id + '","password":"' + password + '", "domain": '
        domain_value = "localdomain"

        if not "@local" in user_id:
            domain_value = user_id.split("@")[1]

        data += '"' + domain_value + '"' + '}'
        print(data)

        # Instead of requests.get(), you'll use session.get()
        response = session.post(url+"/api/auth/login", data=data, verify=False, headers={'content-type':'application/json', 'accept':'application/json'})
        print(response)
        #print response

        if response.status_code != 200:
            print("Failed to authenticate")
            return

        loaded_json = json.loads(response.content)
        print(loaded_json)
        session.headers["x-vrni-csrf-token"] = loaded_json["csrfToken"]
        session.headers["Content-Type"] = "application/json"
        session.headers["Accept"] = "application/json"
        session.auth = None
        return session
    except requests.exceptions.ConnectionError as connection_exception:
        print ("Failed to connect to " + url)
        print (connection_exception.message)
    return None


# def get_nsxt_mks(session):
#     response = session.get(url+"/api/search/query?searchString=NSX-T Manager&includeObjects=false&includeEvents=false&startIndex=0&maxItemCount=10&includeModelKeyOnly=false", verify=False, headers={'content-type':'application/json', 'accept':'application/json'})
#     print(response)
#     nsxt_mks = []
#     if response.status_code != 200:
#         print("Failed to authenticate")
#         return
#
#     loaded_json = json.loads(response.content)
#     print(loaded_json)
#     for nsxt_results in loaded_json["resultList"]:
#         nsxt_mks.append(nsxt_results["modelKey"])
#     print(nsxt_mks)
#     return nsxt_mks

def get_nsxt_mks(session):
    response = session.get(url+"/api/search/query?searchString=NSX-T Manager&startIndex=0&maxItemCount=10&includeModelKeyOnly=false", verify=False, headers={'content-type':'application/json', 'accept':'application/json'})
    print(response)
    nsxt_mks_names = {}
    if response.status_code != 200:
        print("Failed to authenticate")
        return

    loaded_json = json.loads(response.content)
    print(loaded_json)
    for nsxt_results in loaded_json["resultList"]:
        nsxt_mks_names[nsxt_results["searchContext"]["modelKey"]] = nsxt_results["searchContext"]["name"]
    print(nsxt_mks_names)
    return nsxt_mks_names

def create_nsxt_summary_dashboard(session, dashboard_name):
    nsxt_mks_names = get_nsxt_mks(session)
    for mk in nsxt_mks_names.keys():
        dashboard_name = "NSXT Manager "
        print(nsxt_mks_names[mk])
        dashboard_name += nsxt_mks_names[mk]
        print(dashboard_name)
        dashboard_id = create_dashboard(session, dashboard_name, "")
        print(dashboard_id)
        if dashboard_id:
            generate_nsxt_summary_dashboards(session, dashboard_id, mk, nsxt_mks_names[mk])


def generate_nsxt_summary_dashboards(session, dashboard_id, mk, nsxt_manager_name):
    print("generate_nsxt_summary_dashboards")

    discovery_dashboard_name = "NSXT_MANAGER_SUMMARY"
    discovery_query = ""
    add_apple_pin_to_dashboard(session, dashboard_id, discovery_dashboard_name, discovery_query, "true", mk)

    discovery_dashboard_name = "NSXT_FW_HIT_COUNT"
    discovery_query = ""
    add_apple_pin_to_dashboard(session, dashboard_id, discovery_dashboard_name, discovery_query, "true", mk)

    discovery_dashboard_name = "NSXT_MGR_TN_NODE_CPU_METRICS"
    discovery_query = ""
    add_apple_pin_to_dashboard(session, dashboard_id, discovery_dashboard_name, discovery_query, "true", mk)

    discovery_dashboard_name = "NSXT_MGR_TN_NODE_MEMORY_METRICS"
    discovery_query = ""
    add_apple_pin_to_dashboard(session, dashboard_id, discovery_dashboard_name, discovery_query, "true", mk)

    discovery_dashboard_name = "NSXT_NETWORK_UTILIZATION"
    discovery_query = ""
    add_apple_pin_to_dashboard(session, dashboard_id, discovery_dashboard_name, discovery_query, "true", mk)

    discovery_pinboard_name = "Critical NSX-T System Alerts"
    discovery_query = "Alert where Severity = 'Critical' and status = 'OPEN' and Manager  = '{}' and type = 'NSX-T System Alert'".format(nsxt_manager_name)
    print(discovery_query)
    add_query_pin_to_dashboard(session, dashboard_id, discovery_pinboard_name, discovery_query, "false")

    discovery_pinboard_name = "Critical, Warning Alerts for NSX-T Edge Transport Node"
    discovery_query = "Alert where (Severity = 'Critical' or Severity = 'Warning') and status = 'OPEN' and Manager  = '{}' and  Problem Entity in (NSX-T Transport Node where manager = '{}' and node type = 'Edgenode')".format(nsxt_manager_name, nsxt_manager_name)
    print(discovery_query)
    add_query_pin_to_dashboard(session, dashboard_id, discovery_pinboard_name, discovery_query, "false")

    discovery_pinboard_name = "Top 10 Logical Switch by Rx packet drop ratio"
    discovery_query = "Rx Packet Drop Ratio of NSX-T Logical Switch where manager = '{}' order by Rx packet drop ratio desc limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_query_pin_to_dashboard(session, dashboard_id, discovery_pinboard_name, discovery_query, "false")

    discovery_pinboard_name = "Top 10 Logical Switch by Tx packet drop ratio"
    discovery_query = "Tx Packet Drop Ratio of NSX-T Logical Switch where manager = '{}' order by Tx packet drop ratio desc limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_query_pin_to_dashboard(session, dashboard_id, discovery_pinboard_name, discovery_query, "false")

    discovery_pinboard_name = "Top 10 Logical Port by Tx packet drop ratio"
    discovery_query = "Tx Packet Drop Ratio of NSX-T Logical Port where manager = '{}' order by Tx packet drop ratio desc limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_query_pin_to_dashboard(session, dashboard_id, discovery_pinboard_name, discovery_query, "false")

    discovery_pinboard_name = "Top 10 Logical Port by Rx packet drop ratio"
    discovery_query = "Rx Packet Drop Ratio of NSX-T Logical Port where manager = '{}' order by Rx packet drop ratio desc limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_query_pin_to_dashboard(session, dashboard_id, discovery_pinboard_name, discovery_query, "false")

    discovery_pinboard_name = "Top 10 Router Interface by Rx packet drop ratio"
    discovery_query = "Rx Packet Drop ratio of Router Interface where manager = '{}' order by Rx packet drop ratio desc limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_query_pin_to_dashboard(session, dashboard_id, discovery_pinboard_name, discovery_query, "false")

    discovery_pinboard_name = "Top 10 Router Interface by Tx packet drop ratio"
    discovery_query = "Tx Packet Drop ratio of Router Interface where manager = '{}' order by Tx packet drop ratio desc limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_query_pin_to_dashboard(session, dashboard_id, discovery_pinboard_name, discovery_query, "false")

    discovery_pinboard_name = "Top 10 Network Interface by Rx packet drop ratio"
    discovery_query = "Rx packet drop ratio of Network Interface where manager = '{}' order by Rx packet drop ratio limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_query_pin_to_dashboard(session, dashboard_id, discovery_pinboard_name, discovery_query, "false")

    discovery_pinboard_name = "Top 10 Network Interface by Tx packet drop ratio"
    discovery_query = "Tx packet drop ratio of Network Interface where manager = '{}' order by Tx packet drop ratio limit 10".format(nsxt_manager_name)
    print(discovery_query)
    add_query_pin_to_dashboard(session, dashboard_id, discovery_pinboard_name, discovery_query, "false")


def add_apple_pin_to_dashboard(session, dashboard_id, pin_name, pin_query, is_applet, entities):
    body = '{"id":"' + pin_name + '","query":"' + pin_query + '", "isApplet": '+ is_applet +', "dataBlob": "{}", "entities":["' + entities + '"]}'
    print(body)
    response = session.post(url+"/api/custom-dashboards/{}/pins".format(dashboard_id), data=body, verify=False)
    print(response)
    loaded_json = json.loads(response.content)
    return

def add_query_pin_to_dashboard(session, dashboard_id, pin_name, pin_query, is_applet):
    body = '{"id":"' + pin_name + '","query":"' + pin_query + '", "isApplet": '+ is_applet +', "dataBlob": "{}", "entities":[]}'
    print(body)
    response = session.post(url+"/api/custom-dashboards/{}/pins".format(dashboard_id), data=body, verify=False)
    print(response)
    loaded_json = json.loads(response.content)
    return

# returns the dashboard id if succcessful, None in case of failures.
def create_dashboard(session, dashboard_name, dashboard_description):
    body = '''{{"name": "{0}", "description": "{1}"}}'''.format(dashboard_name, dashboard_description)
    response = session.post(url+"/api/custom-dashboards", data=body, verify=False)
    if response.status_code == 201:
        loaded_json = json.loads(response.content)
        return loaded_json["modelKey"]
    print("Failed to create dashboard, please check if the dashboard already exists or if you have used admin/member login credentials")
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
                      dest="dashboard_name",
                      help="[Optional] Name to be used for the important changes dashboard")

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
    dashboard_name = options.dashboard_name
    session = open_vrni_session(url, user_id, password)
    if not session:
        print ("Unable to connect to vRNI")
        sys.exit(1)

    create_nsxt_summary_dashboard(session, dashboard_name)
