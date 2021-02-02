

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

sender = 'noreply@vmware.com'

message = """From: vRNI Summary Ninja <noreply@vmware.com>
To: vRNI Master <to@todomain.com>
Subject: vRNI Daily Summary

"""

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

def current_milli_time():
    return int(round(time.time() * 1000))

def send_summary_email(session, target_email):
	try:
		#Information to send:
		#Total traffic in last 24 hours, compared with previous day and same day last week
		#&timestamp=1612265665538&timeRangeString=+between+timestamp+1612178885460+and+timestamp+1612265285460
		current_time_stamp = current_milli_time()
		one_day_millisecond = 24 * 60 * 60 * 1000
		yesterday_time_stamp = current_time_stamp - one_day_millisecond
		day_before_yesterday_timestamp = yesterday_time_stamp - one_day_millisecond
		same_day_last_week_timestamp_start = current_time_stamp - (7 * one_day_millisecond)
		same_day_last_week_timestamp_end = current_time_stamp - (6 * one_day_millisecond)

		rx_bytes_query = urllib.quote_plus("sum(total rx bytes) of switch ports")

		#Find todays total Rx
		todays_time_range_string = "&timeRangeString= between timestamp " + str(
			yesterday_time_stamp) + " and timestamp " + str(current_time_stamp)
		todays_rx_bytes_query_request = "/api/search/query?searchString=" + rx_bytes_query + todays_time_range_string
		response = session.get(url + todays_rx_bytes_query_request, verify=False)
		found_metrics = json.loads(response.content)
		#todo: handle error
		todays_rx_bytes = int(found_metrics['aggregates2'][0]['aggs']['SUM'])

		#Find yesterday's total Rx
		yesterdays_time_range_string = "&timeRangeString= between timestamp " + str(
			day_before_yesterday_timestamp) + " and timestamp " + str(yesterday_time_stamp)
		yesterdays_rx_bytes_query_request = "/api/search/query?searchString=" + rx_bytes_query + yesterdays_time_range_string
		response = session.get(url + yesterdays_rx_bytes_query_request, verify=False)
		found_metrics = json.loads(response.content)
		#todo: handle error
		yesterdays_rx_bytes = int(found_metrics['aggregates2'][0]['aggs']['SUM'])

		#Find todays total tx
		tx_bytes_query = urllib.quote_plus("sum(total tx bytes) of switch ports")
		todays_tx_bytes_query_request = "/api/search/query?searchString=" + tx_bytes_query + todays_time_range_string
		response = session.get(url + todays_tx_bytes_query_request, verify=False)
		found_metrics = json.loads(response.content)
		#todo: handle error
		todays_tx_bytes = int(found_metrics['aggregates2'][0]['aggs']['SUM'])

		#Find yesterday's total tx
		yesterdays_tx_bytes_query_request = "/api/search/query?searchString=" + tx_bytes_query + yesterdays_time_range_string
		response = session.get(url + yesterdays_tx_bytes_query_request, verify=False)
		found_metrics = json.loads(response.content)
		#todo: handle error
		yesterdays_tx_bytes = int(found_metrics['aggregates2'][0]['aggs']['SUM'])

		total_today =  todays_rx_bytes + todays_tx_bytes
		total_yest = yesterdays_rx_bytes + yesterdays_tx_bytes

		email_message = "Total Network Traffic (Read + Write) for today is: " + str((total_today)/(1024*1024*1024)) + " GB\n"
		if (total_today > total_yest):
			email_message += "Which is "  + str(total_today - total_yest) + " bytes more than yesterday's traffic\n\n"
		else:
			email_message += "Which is " + str(total_yest - total_today) + " bytes less than yesterday's traffic\n\n"

		email_message += "To find more details about traffic patterns and problems, log on to " + url + "\n\nWith Best Regards,\nYour Friendly Neighborhood vRNI\n"

		smtpObj = smtplib.SMTP('email-smtp.us-west-2.amazonaws.com', 587)
		smtpObj.starttls()
		smtpObj.login("AKIAJCQMNKULV43XLG6A", "Ajg+/jfsHwCL9W+GBmhrYII1/blbLyJxbFiKPl/wDgOG")
		receivers = ['praving@vmware.com', 'avaikar@vmware.com']
		smtpObj.sendmail(sender, receivers, message + email_message)
	#Total open problems in last 24 hours (up by or down by nn over previous day)

	except requests.exceptions.ConnectionError as connection_exception:
		print "Failed to connect to " + url
		print connection_exception.message
		return None
	return ""

def check_options(options):
	if options.target_email == "":
		print "email id is mandatory"
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

	parser.add_option("-e", "--email",
					  dest="target_email",
					  help="email_id to send the summary email to")

	(options, args) = parser.parse_args()

	if options.server is None or options.uid is None or options.password is None or options.target_email is None:
		parser.print_help()
		print "Insufficient arguments"
		sys.exit(1)

	if not check_options(options):
		sys.exit(1)

	url = "https://" + options.server
	user_id = options.uid
	password = options.password
	session = open_vrni_session(url, user_id, password)
	if not session:
		print "Unable to connect to vRNI"
		sys.exit(1)

	send_summary_email(session, "")
