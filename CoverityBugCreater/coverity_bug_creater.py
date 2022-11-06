# Script to accept a csv of coverity exported csv and create bug tickets out of it if not already done
import base64
import sys
from urllib2 import Request, urlopen

import requests
import json
from optparse import OptionParser
import ipaddress
import urllib
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time

import ssl

ssl._create_default_https_context = ssl._create_unverified_context

def check_options(options):
	#ToDo: check if csv is in right format before we start.
	return True


def jira_rest_call(url, uid, password, fields):
	# Build the text for the JIRA ticket.
	cid = fields[0]
	displayType = fields[1]
	displayImpact = fields[2]
	displayCategory = fields[10]
	displayFile = fields[11]
	displayFuction = fields[12]
	lineNumber = fields[14]

	jira_summary = "COVERITY: CID {0} , Category: {1}, Function: {2}, LineNo: {3}".format(cid, displayCategory, displayFuction, lineNumber)
	jira_description = jira_summary + "\n File: {0}, Impact: {1}, Type: {2}".format(displayFile, displayImpact, displayType)

	# Build the JSON to post to JIRA
	json_data = json.dumps( {
	    "fields":{
	        "project":{
	            "key":"CYG"
	        },
	        "summary": jira_summary,
	        "components":[
	            {"name":"vrni-coverity"}
	            ],
	        "issuetype":{
	            "name":"Bug"
	        },
	        "description": jira_description,
	        "assignee": "gwagle"
	    } 
	})

	# Set the root JIRA URL, and encode the username and password
	url = url + '/rest/api/3/issue'

	headers = {
		"Accept": "application/json",
		"Content-Type": "application/json",
		"X-Atlassian-Token": "no-check"
	}
	auth = HTTPBasicAuth(uid, password)

	# Send the request and grab JSON response
	response = requests.request(
		"POST",
		url,
		data=json_data,
		headers=headers,
		auth=auth
	)

	# Load into a JSON object and return that to the calling function
	return json.loads(response.read())


def parse_csv_and_create_ticket(url, uid, password, csv):
	fp_out = open(csv+"_created_tickets.csv", "w")
	counter_new = 0
	counter_existing = 0
	with open(csv, "r") as fp:
		currentLine = fp.readline()
		while currentLine:
			if currentLine.startswith("#"):
				continue
			fields = currentLine.split(",")
			if len(fields) != 15:
				continue
			jira_title = fields[1]
			if not check_if_ticket_already_exists(url, uid, password, jira_title):
				response = jira_rest_call(url, uid, password, fields)
				fp_out.write(response)
				counter_new += 1
			else:
				counter_existing += 1
			currentLine = fp.readline()

	print "Existing JIRAs:", counter_existing, "New JIRAs:", counter_new
	return counter_new

def check_if_ticket_already_exists(url, uid, password, title_string):
	return False



if __name__ == '__main__':

	parser = OptionParser()
	#ToDo: If csv is not provided, also provide options for coverity server and creds
	# So that this script itself can dump the csv.
	parser.add_option("-j", "--jiraurl", dest="jiraserver",
					  help="Jira Server IP/fqdn")

	parser.add_option("-u", "--user",
					  dest="uid",
					  help="Jira User")

	parser.add_option("-p", "--password",
					  dest="password",
					  help="Jira User's password")

	parser.add_option("-c", "--csv",
					  dest="csv",
					  help="CSV file exported from coverity")

	(options, args) = parser.parse_args()

	if options.jiraserver is None or \
			options.uid is None or \
			options.password is None or \
			options.csv is None:
		parser.print_help()
		print "Insufficient arguments"
		sys.exit(1)

	if not check_options(options):
		sys.exit(1)

	url = "https://" + options.jiraserver
	user_id = options.uid
	password = options.password
	csv = options.csv
	parse_csv_and_create_ticket(url, user_id, password, csv)
