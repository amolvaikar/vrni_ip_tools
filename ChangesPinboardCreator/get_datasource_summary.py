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

def get_datasource_details(session, url):
    response = session.get(url + "/api/ni/data-sources?size=100")
    loaded_json = json.loads(response.content)
    for result in loaded_json['results']:
        if "entity_type" not in result:
            continue
        if "ip" in result:
            print("{}, {}, {}".format(url, result["entity_type"], result["ip"]))
        else:
            print("{}, {}, {}".format(url, result["entity_type"], result["fqdn"]))

if __name__ == '__main__':

    parser = OptionParser()
    parser.add_option("-u", "--user",
                      dest="uid",
                      help="vRNI User")

    parser.add_option("-p", "--password",
                      dest="password",
                      help="vRNI User's password")

    parser.add_option("-n", "--name",
                      dest="csv_file",
                      help="CVS file containing vrni setup details")


    (options, args) = parser.parse_args()

    if options.uid is None or options.password is None or options.csv_file is None:
        parser.print_help()
        print ("Insufficient arguments")
        sys.exit(1)

    user_id = options.uid
    password = options.password

    with open(options.csv_file, "r") as fp:
        line = fp.readline().strip('\n')

        while line:
            line = "https://" + line
            session = open_vrni_session(line, user_id, password)
            if not session:
                print("Unable to connect to vRNI")
                sys.exit(1)
            get_datasource_details(session, line)
            line = fp.readline().strip('\n')
