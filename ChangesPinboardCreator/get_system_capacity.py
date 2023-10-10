import sys
import csv
import requests
import json
from optparse import OptionParser
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def open_vrni_session(url, user_id, password):
    try:
        session = requests.Session()
        session.auth = (user_id, password)

        data = '{"username":"' + user_id + '","password":"' + password + '", "domain": '
        domain_value = "localdomain"

        if not "@local" in user_id:
            domain_value = user_id.split("@")[1]

        data += '"' + domain_value + '"' + '}'
        #print(data)

        # Instead of requests.get(), you'll use session.get()
        response = session.post(url+"/api/auth/login", data=data, verify=False, headers={'content-type':'application/json', 'accept':'application/json'})
        #print response

        if response.status_code != 200:
            print("Failed to authenticate")
            return

        loaded_json = json.loads(response.content)
        session.headers["x-vrni-csrf-token"] = loaded_json["csrfToken"]
        session.headers["Content-Type"] = "application/json"
        session.headers["Accept"] = "application/json"
        session.auth = None
        return session
    except requests.exceptions.ConnectionError as connection_exception:
        print ("Failed to connect to " + url)
        print (connection_exception.message)
    return None

def get_capacity_details(session, url, setup_capacity_data_list):
    response = session.get(url + "/api/management/system-info")
    setup_capacity_data_list[url] = response.content

def append_data_csv(setup_capacity_data_list):
    data_list = []

    # Iterate over each JSON data string
    for json_data in setup_capacity_data_list:
        # Parse the JSON data
        data = json.loads(setup_capacity_data_list[json_data])

        # Extract specific fields from "platform"
        platform = data['data']['capacity']['platform']
        vmCount = platform['vmCount']
        flowCountPlatform = platform['flowCount']
        totalFlows = platform['totalFlows']
        networkRuleCount = platform['networkRuleCount']

        # Extract fields from all "proxies"
        proxies = data['data']['capacity']['proxies']

        # Create a dictionary to hold the data
        data_dict = {
            'setup': json_data,
            'vmCount': vmCount,
            'flowCountPlatform': flowCountPlatform,
            'totalFlows': totalFlows,
            'networkRuleCount': networkRuleCount
        }

        # Add data for each proxy
        for index, proxy in enumerate(proxies):
            data_dict[f'flowCountProxy{index + 1}'] = proxy['flowCount']

        # Append the data dictionary to the list
        data_list.append(data_dict)

    # Create a CSV file for writing
    with open('capacity.csv', 'w', newline='') as csvfile:
        # Get the fieldnames from the first data dictionary
        fieldnames = list(data_list[0].keys())
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        # Write the CSV header
        writer.writeheader()
        # Write the data to the CSV file
        writer.writerows(data_list)

    print("Data has been exported to 'capacity.csv'")

if __name__ == '__main__':

    parser = OptionParser()
    parser.add_option("-n", "--name",
                      dest="csv_file",
                      help="CSV file containing vrni setup details")


    (options, args) = parser.parse_args()
    # Your JSON data as a list of strings
    setup_capacity_data_list = {}

    if options.csv_file is None:
        parser.print_help()
        print ("Insufficient arguments")
        sys.exit(1)

    with open(options.csv_file, "r") as fp:
        csv_reader = csv.reader(fp)
        for row in csv_reader:
            #print(row)
            session = open_vrni_session("https://"+row[0], row[1], row[2])
            if not session:
                print("Unable to connect to vRNI")
                sys.exit(1)
            get_capacity_details(session, "https://"+row[0], setup_capacity_data_list)

    append_data_csv(setup_capacity_data_list)
