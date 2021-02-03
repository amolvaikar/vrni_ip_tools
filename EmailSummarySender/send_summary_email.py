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

def send_summary_email(session, options):
	try:
		email_message = get_traffic_summary(session)
		email_message += get_problem_summary(session)

		if options.email_server is None:
			options.email_server = "email-smtp.us-west-2.amazonaws.com"

		if options.email_server_login is None:
			options.email_server_login = "AKIAJCQMNKULV43XLG6A"

		if options.email_server_password is None:
			options.email_server_password = "Ajg+/jfsHwCL9W+GBmhrYII1/blbLyJxbFiKPl/wDgOG"

		if options.target_email is None:
			options.target_email = "avaikar@vmware.com"

		smtpObj = smtplib.SMTP(options.email_server, 587)
		smtpObj.starttls()
		smtpObj.login(options.email_server_login, options.email_server_password)
		receivers = [options.target_email]
		html = """\
		<html>
		  <head></head>
		  <body>
			<p>Hi Admin!</p>

			<p>This is your network summary for&nbsp;"""
		now = datetime.now()
		date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
		html += date_time + "</p>"

		html_footer = """<p>With Best Regards,</p><p>Your Friendly Neighborhood vRNI</p>
						  	</body>
						</html>
					  """

		# Create message container - the correct MIME type is multipart/alternative.
		msg = MIMEMultipart('alternative')
		msg['Subject'] = "vRNI Network Summary"
		msg['From'] = sender
		msg['To'] = options.target_email

		#part1 = MIMEText(message + email_message, 'plain')
		part2 = MIMEText(html + email_message + html_footer, 'html')

		#msg.attach(part1)
		msg.attach(part2)

		smtpObj.sendmail(sender, receivers, msg.as_string())
	#Total open problems in last 24 hours (up by or down by nn over previous day)

	except requests.exceptions.ConnectionError as connection_exception:
		print "Failed to connect to " + url
		print connection_exception.message
		return None
	return ""

current_time_stamp = current_milli_time()
one_day_millisecond = 24 * 60 * 60 * 1000
yesterday_time_stamp = current_time_stamp - one_day_millisecond
day_before_yesterday_timestamp = yesterday_time_stamp - one_day_millisecond
same_day_last_week_timestamp_start = current_time_stamp - (7 * one_day_millisecond)
same_day_last_week_timestamp_end = current_time_stamp - (6 * one_day_millisecond)

def get_problem_summary(session):
	#Information to send:
	# Total open problems in last 24 hours
	open_problems_query = urllib.quote_plus("open problems")
	# Find todays total Rx
	todays_time_range_string = "&timeRangeString= between timestamp " + str(
		yesterday_time_stamp) + " and timestamp " + str(current_time_stamp)
	todays_open_problems_query_request = "/api/search/query?searchString=" + open_problems_query + todays_time_range_string
	response = session.get(url + todays_open_problems_query_request, verify=False)
	found_metrics = json.loads(response.content)
	# todo: handle error
	todays_open_problems = int(found_metrics['count'])

	# Find yesterday's open problems
	yesterdays_time_range_string = "&timeRangeString= between timestamp " + str(
		day_before_yesterday_timestamp) + " and timestamp " + str(yesterday_time_stamp)
	yesterdays_open_problems_query_request = "/api/search/query?searchString=" + open_problems_query + yesterdays_time_range_string
	response = session.get(url + yesterdays_open_problems_query_request, verify=False)
	found_metrics = json.loads(response.content)
	# todo: handle error
	yesterdays_open_problems = int(found_metrics['count'])

	email_message = """<p><u><strong>Open Problems</strong></u></p>

						<p>&nbsp; &nbsp; Today&#39;s open problem count: <span style="color:#ff8c00"><u><strong>"""
	email_message += str(todays_open_problems)
	email_message += """</strong></u></span></p>

						<p>&nbsp; &nbsp; This is """
	if todays_open_problems > yesterdays_open_problems:
		email_message += str(todays_open_problems - yesterdays_open_problems) + '<u><strong><span style="color:#ff0000"> more</span></strong></u> than yesterday</p>'
	else:
		email_message += str(yesterdays_open_problems - todays_open_problems) + '<u><strong><span style="color:#008000"> less</span></strong></u> than yesterday</p>'
	email_message += '<p>&nbsp; &nbsp; To see a list of all open problems, click &nbsp;<a href="'\
					 + url + '/#search/query/%22open%20problems%22/timemeta/{%22timePreset%22%3A%22Last%2024%20hours%22}/sourceString/%22USER%22">'
	email_message += 'here</a></p>'
	return email_message

def get_traffic_summary(session):
	# Information to send:
	# Total traffic in last 24 hours, compared with previous day and same day last week
	# &timestamp=1612265665538&timeRangeString=+between+timestamp+1612178885460+and+timestamp+1612265285460

	rx_bytes_query = urllib.quote_plus("sum(total rx bytes) of switch ports")
	# Find todays total Rx
	todays_time_range_string = "&timeRangeString= between timestamp " + str(
		yesterday_time_stamp) + " and timestamp " + str(current_time_stamp)
	todays_rx_bytes_query_request = "/api/search/query?searchString=" + rx_bytes_query + todays_time_range_string
	response = session.get(url + todays_rx_bytes_query_request, verify=False)
	found_metrics = json.loads(response.content)
	# todo: handle error
	todays_rx_bytes = int(found_metrics['aggregates2'][0]['aggs']['SUM'])
	# Find yesterday's total Rx
	yesterdays_time_range_string = "&timeRangeString= between timestamp " + str(
		day_before_yesterday_timestamp) + " and timestamp " + str(yesterday_time_stamp)
	yesterdays_rx_bytes_query_request = "/api/search/query?searchString=" + rx_bytes_query + yesterdays_time_range_string
	response = session.get(url + yesterdays_rx_bytes_query_request, verify=False)
	found_metrics = json.loads(response.content)
	# todo: handle error
	yesterdays_rx_bytes = int(found_metrics['aggregates2'][0]['aggs']['SUM'])
	# Find todays total tx
	tx_bytes_query = urllib.quote_plus("sum(total tx bytes) of switch ports")
	todays_tx_bytes_query_request = "/api/search/query?searchString=" + tx_bytes_query + todays_time_range_string
	response = session.get(url + todays_tx_bytes_query_request, verify=False)
	found_metrics = json.loads(response.content)
	# todo: handle error
	todays_tx_bytes = int(found_metrics['aggregates2'][0]['aggs']['SUM'])
	# Find yesterday's total tx
	yesterdays_tx_bytes_query_request = "/api/search/query?searchString=" + tx_bytes_query + yesterdays_time_range_string
	response = session.get(url + yesterdays_tx_bytes_query_request, verify=False)
	found_metrics = json.loads(response.content)
	# todo: handle error
	yesterdays_tx_bytes = int(found_metrics['aggregates2'][0]['aggs']['SUM'])
	total_today = todays_rx_bytes + todays_tx_bytes
	total_yest = yesterdays_rx_bytes + yesterdays_tx_bytes
	email_message = "<p><u><strong>Network Usage:</strong></u></p>"
	email_message += '<p>&nbsp; &nbsp; Total Network Traffic (Read + Write) for today is <span style="font-size:14px"><span style="color:#ff8c00"><strong>'\
					 + str((total_today) / (1024 * 1024 * 1024)) + " GB</strong></span></span></p>"
	if (total_today > total_yest):
		email_message += "<p>&nbsp; &nbsp; This is <strong>" + str((total_today - total_yest)/ (1024 * 1024 * 1024))\
						 + ' GB </strong><span style="color:#ff0000"><u><strong> more </strong></u></span> than yesterday</p>'
	else:
		email_message += "<p>&nbsp; &nbsp; This is <strong>" + str((total_yest - total_today)/ (1024 * 1024 * 1024))\
						 + ' GB</strong> <span style="color:#008000"><u><strong>less</strong></u></span> than yesterday</p>'

	return email_message


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

	parser.add_option("-s", "--email-server",
					  dest="email_server",
					  help="email server for sending email from")

	parser.add_option("-U", "--email-server-login",
					  dest="email_server_login",
					  help="email server login for sending email")

	parser.add_option("-P", "--email-server-password",
					  dest="email_server_password",
					  help="email server password for sending email from")

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

	send_summary_email(session, options)
