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

def create_application_pinboard(session, pinboard_name, application_name):
    pinboard_id = create_pinboard(session, pinboard_name, "")
    print(pinboard_id)
    if pinboard_id:
        generate_application_pinboards(session, pinboard_id, application_name)
    return

def generate_application_pinboards(session, pinboard_id, application_name):
        print("generate_application_pinboards")

        discovery_pinboard_name = "Outgoing traffic from Current App to any Dst App"
        discovery_query = "flow where source application = '{}' and destination application != '{}' group by destination application order by sum(total traffic)".format(application_name, application_name)
        print(discovery_query)
        add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

        discovery_pinboard_name = "Outgoing traffic metric from Current App to any Dst App"
        discovery_query = "series(sum(Total traffic)), series(sum(traffic rate)), series(avg(TCP Retransmission Ratio)), series(avg(Average TCP RTT)) of flow where source application = '{}' and destination application != '{}' group by destination application order by sum(total traffic)".format(application_name, application_name)
        print(discovery_query)
        add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

        discovery_pinboard_name = "Incoming traffic from any Src App to Current App"
        discovery_query = "flow where source application != '{}' and destination application = '{}' group by source application order by sum(total traffic)".format(application_name, application_name)
        print(discovery_query)
        add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

        discovery_pinboard_name = "Incoming traffic metric from any Src App to Current App"
        discovery_query = "series(sum(Total traffic)), series(sum(traffic rate)), series(avg(TCP Retransmission Ratio)), series(avg(Average TCP RTT)) of flow where source application != '{}' and destination application = '{}' group by source application order by sum(total traffic)".format(application_name, application_name)
        print(discovery_query)
        add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)


        discovery_pinboard_name = "Outgoing traffic per Tier from Application"
        discovery_query = "sum(total traffic) of flow where source application = '{}' and destination application != '{}' group by source Tier".format(application_name, application_name)
        print(discovery_query)
        add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

        discovery_pinboard_name = "Outgoing traffic metric for Application"
        discovery_query = "series(sum(Total traffic)), series(sum(traffic rate)), series(avg(TCP Retransmission Ratio)), series(avg(Average TCP RTT))  of flow where source application = '{}' and destination application != '{}' group by source Tier".format(application_name, application_name)
        print(discovery_query)
        add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

        discovery_pinboard_name = "Incoming traffic to Application"
        discovery_query = "sum(total traffic) of flow where source application != '{}' and destination application = '{}' group by source application".format(application_name, application_name)
        print(discovery_query)
        add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

        discovery_pinboard_name = "Incoming traffic metric for Application"
        discovery_query = "series(sum(Total traffic)), series(sum(traffic rate)), series(avg(TCP Retransmission Ratio)), series(avg(Average TCP RTT))  of flow where source application != '{}' and destination application = '{}' group by source application".format(application_name, application_name)
        print(discovery_query)
        add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

        discovery_pinboard_name = "Outgoing East-West Traffic Metric from Application per Tier"
        discovery_query = "series(sum(Total traffic)), series(sum(traffic rate)), series(avg(TCP Retransmission Ratio)), series(avg(Average TCP RTT)) of flow where source application = '{}' and flow type = 'East-West' group by source Tier".format(application_name)
        print(discovery_query)
        add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

        discovery_pinboard_name = "Incoming East-West Traffic Metric to Application per Tier"
        discovery_query = "series(sum(Total traffic)), series(sum(traffic rate)), series(avg(TCP Retransmission Ratio)), series(avg(Average TCP RTT)) of flow where destination application = '{}' and flow type = 'East-West' group by destination Tier".format(application_name)
        print(discovery_query)
        add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

        discovery_pinboard_name = "Top services being accessed within application"
        discovery_query = "sum(total traffic) of flow where source application = '{}' and destination application = '{}' group by port".format(application_name, application_name)
        print(discovery_query)
        add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

        discovery_pinboard_name = "Metrics of Top services being accessed within application"
        discovery_query = "series(sum(Total traffic)), series(sum(traffic rate)), series(avg(TCP Retransmission Ratio)), series(avg(Average TCP RTT)) of flow where source application = '{}' and destination application = '{}' group by port".format(application_name, application_name)
        print(discovery_query)
        add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

        discovery_pinboard_name = "Top services being accessed from application"
        discovery_query = "sum(total traffic) of flow where source application = '{}' and destination application != '{}' group by port".format(application_name, application_name)
        print(discovery_query)
        add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

        discovery_pinboard_name = "Metrics of Top services being accessed from application"
        discovery_query = "series(sum(Total traffic)), series(sum(traffic rate)), series(avg(TCP Retransmission Ratio)), series(avg(Average TCP RTT)) of flow where source application = '{}' and destination application != '{}' group by port".format(application_name, application_name)
        print(discovery_query)
        add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)


        discovery_pinboard_name = "Top Talking Tiers"
        discovery_query = "flow where source application = '{}' and destination application = '{}' group by tier order by sum(Total traffic)".format(application_name, application_name)
        print(discovery_query)
        add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

        discovery_pinboard_name = "Top Talking Tier pair within application by traffic"
        discovery_query = "flow where source application = '{}' and destination application = '{}' group by source tier, destination tier order by sum(Total traffic)".format(application_name, application_name)
        print(discovery_query)
        add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

        discovery_pinboard_name = "Metrics of Top Talking Tier pairs within application by traffic:"
        discovery_query = "series(sum(Total traffic)), series(sum(traffic rate)), series(avg(TCP Retransmission Ratio)), series(avg(Average TCP RTT)) of flow where source application = '{}' and destination application = '{}' group by source tier, destination tier order by sum(Total traffic)".format(application_name, application_name)
        print(discovery_query)
        add_pin_to_pinboard(session, pinboard_id, discovery_pinboard_name, discovery_query)

        discovery_pinboard_name = "Metrics of overall flows per Tier for an application"
        discovery_query = "series(sum(Total traffic)), series(sum(traffic rate)), series(avg(TCP Retransmission Ratio)), series(avg(Average TCP RTT)) of flow where Tier in (Tier where application = '{}') group by Tier".format(application_name)
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

    parser.add_option("-a", "--application",
                      dest="application_name",
                      help="[Required] Name of the Application to create pinboard")


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
    application_name = options.application_name
    session = open_vrni_session(url, user_id, password)
    if not session:
        print ("Unable to connect to vRNI")
        sys.exit(1)

    create_application_pinboard(session, pinboard_name, application_name)
