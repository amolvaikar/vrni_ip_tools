import sys
import csv
import requests
import json
from optparse import OptionParser
import urllib
import urllib3
import re

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

def open_vrni_session_using_vidm(url, user_id, password, domain):
    session = requests.Session()

    # Step 1: Get authentication domain options from vrni
    response = session.get(url + "/api/auth/authenticationDomains", verify=False)
    if response.status_code != 200:
        print("Step 1 failed to get authentication domains")
        return

    loaded_json = json.loads(response.content)
    if len(loaded_json) < 2:
        print("Insufficient authentication domain, is vidm enabled on this setup?")
        return

    vidm_redirect_url = loaded_json[1]["redirectUrl"]
    vidm_base_url = vidm_redirect_url.split("/SAAS")[0]

    # Step 2: Start VIDM authentication workflow
    response = session.get(vidm_redirect_url, verify=False)
    if response.status_code != 200:
        print("Step 2 failed for {}".format(vidm_redirect_url))
        return

    html_content = response.content.decode('utf-8')
    found_line = None
    userStoreUuid = None
    userDomainUuid = None
    for line in html_content.split("\n"):
        if "userStoreUuid" in line and domain in line:
            found_line = line
            break
    if found_line is not None:
        new_string = re.sub('<option value="{&quot;userStoreUuid&quot;:&quot;', "", found_line).strip()
        splits = new_string.split("&quot;")
        userStoreUuid = splits[0]
        userDomainUuid = splits[4]
    else:
        print("Step 2: Failed to find store UUIDs")
        return

    userStoreDomain = '{{"userStoreUuid":"{}","userDomainUuid":"{}"}}'.format(userStoreUuid, userDomainUuid)
    payload = {
        "isJavascriptEnabled":"",
        "areCookiesEnabled":"",
        "dest":vidm_redirect_url,
        "useragent":"Macintosh",
        "userInput":"",
        "workspaceId":"",
        "groupUuidStr":"",
        "username":"",
        "userStoreDomain":userStoreDomain,
        "userStoreFormSubmit":""
    }

    # Step 3: Get userstore information
    next_url = "{}/SAAS/auth/login/userstore".format(vidm_base_url)
    session.headers["Content-Type"] = "application/x-www-form-urlencoded"
    response = session.post(next_url, data=urllib.parse.urlencode(payload), verify=False)
    if response.status_code != 200:
        print("Step 3: failed to get user store info")
        return

    html_content = response.content.decode('utf-8')
    found_line = None
    protected_state = None
    for line in html_content.split("\n"):
        if "protected_state" in line:
            found_line = line
            break
    if found_line is not None:
        protected_state = found_line.split("value=")[1].strip().replace("/>", "").replace("\"", "")
    else:
        print("Step 3 failed to find the protected_state information")
        return

    # Step 4: Try to authenticate using all info gathered till now
    next_url = "{}/hc/3002/authenticate/".format(vidm_base_url)
    payload = {
        "protected_state":protected_state,
        "userstore":domain,
        "domain":domain,
        "email":"",
        "userInput":"",
        "username":user_id,
        "password":password,
        "userstoreDisplay": domain,
        "vk":""
    }
    response = session.post(next_url, data=urllib.parse.urlencode(payload), verify=False)
    if response.status_code != 200:
        print("Step 4 failed to authenticate, please check credentials and domain. Also, user id should not have the '@mydomain.com' domain part in it")
        return

    html_content = response.content.decode('utf-8')
    found_line = None
    saml_response = None
    relay_state = None
    for line in html_content.split("\n"):
        if found_line is not None and len(line.strip()) !=0 :
            relay_state = line
            break
        if "SAMLResponse" in line:
            found_line = line

    if found_line is not None:
        saml_response = found_line.split('"SAMLResponse">')[1].strip().replace("</textarea>", "")
        relay_state = relay_state.split('"RelayState">')[1].strip().replace('</textarea>', "")
    else:
        print("Step 4 failed to find saml and relay information")
        return

    # Step 5: Get SAML response, which should give us the code for the vrni token API
    next_url = "{}/SAAS/auth/saml/response".format(vidm_base_url)
    payload = {
        "SAMLResponse":saml_response,
        "RelayState":relay_state,
    }
    response = session.post(next_url, data=urllib.parse.urlencode(payload), verify=False)
    if response.status_code != 200:
        print("Step 5: Failed to get saml token")
        return

    vidm_code_token = response.url.split("code=")[1].split("&userstore")[0]

    # Step 6: Get the final token from vrni which we can use in the private API calls for getting data from vrni
    next_url = url + "/api/auth/vidm/login"
    data_raw = '{"code":"' + vidm_code_token + '"}'
    session.headers["Content-Type"] = "application/json"
    session.headers["Accept"] = "application/json"
    response = session.post(next_url, data=data_raw, verify=False)
    if response.status_code != 200:
        print("Step 6: failed to get final vRNI token")
        return

    loaded_json = json.loads(response.content)
    session.headers["X-Vrni-Csrf-Token"] = loaded_json["csrfToken"]
    return session

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
            if len(row) == 3:
                session = open_vrni_session("https://"+row[0], row[1], row[2])
            elif len(row) == 4:
                session = open_vrni_session_using_vidm("https://"+row[0], row[1], row[2], row[3])
            if not session:
                print("Unable to connect to vRNI")
                sys.exit(1)
            get_capacity_details(session, "https://"+row[0], setup_capacity_data_list)

    append_data_csv(setup_capacity_data_list)
