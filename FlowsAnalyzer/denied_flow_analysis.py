import sys
from optparse import OptionParser

DENY_FREQUENCY = "deny_frequency"

ALLOW_FREQUENCY = "allow_frequency"

ALLOW_RULES = "allow_rules"
DENY_RULES = "deny_rules"
REPORTING_HOSTS = "reporting_hosts"


def check_options(options):
	#ToDo: check if csv is in right format before we start.
	return True


# Information we want to gather:
# 1. How many flows have source and destination with same IPs and atleast 1 shared port
#     e.g.: 100.88.218.221, 34939,  10.131.123.248,   443,......,       7,     866,   10.60.101.113,     0,     0, 294,  1,17799,  I,0,  0,664070B2472F4B5193A089C9E1A927B0
#           10.131.123.248,   443,  100.88.218.221, 56491,......,       1,      40,   10.60.101.113,     0,     0, 294,  3,  2,  I,0,  0,664070B2472F4B5193A089C9E1A927B0
# 2. How many of 1 above are allowed/denied flip flop (offset 11 in the csv)
# 3. Details of all such ip & port pairs to be dumped

dict_flip_flop_flow = dict() #Key for this dict is source-ip:dest-ip:dest-port and value is a dict of: all involved hosts, firewall rules for allow & deny
dict_allowed_flows = dict()
dict_denied_flows = dict()

total_flow_records_processed = 0
total_allow_deny_flip_flop_flows_count = 0

def initialize_data_dict():
	data_dict = dict()
	data_dict[REPORTING_HOSTS] = set()
	data_dict[ALLOW_RULES] = set()
	data_dict[DENY_RULES] = set()
	data_dict[ALLOW_FREQUENCY] = 0
	data_dict[DENY_FREQUENCY] = 0
	return data_dict

def record_flow_as_flip_flop_flow(key, firewall_action, firewall_rule_id, reporting_host):
	if key not in dict_flip_flop_flow:
		dict_flip_flop_flow[key] = initialize_data_dict()
		if key in dict_allowed_flows:
			dict_flip_flop_flow[key][ALLOW_RULES] = dict_allowed_flows[key][ALLOW_RULES].copy()
			dict_flip_flop_flow[key][ALLOW_FREQUENCY] = dict_allowed_flows[key][ALLOW_FREQUENCY]
			dict_flip_flop_flow[key][REPORTING_HOSTS] = dict_allowed_flows[key][REPORTING_HOSTS].copy()
		if key in dict_denied_flows:
			dict_flip_flop_flow[key][DENY_RULES] = dict_denied_flows[key][DENY_RULES].copy()
			dict_flip_flop_flow[key][DENY_FREQUENCY] = dict_denied_flows[key][DENY_FREQUENCY]
			dict_flip_flop_flow[key][REPORTING_HOSTS] = dict_denied_flows[key][REPORTING_HOSTS].copy()

	data_dict = dict_flip_flop_flow[key]

	# Record the reporting hosts
	data_dict[REPORTING_HOSTS].add(reporting_host)

	# Record the firewall rule id and frequency
	if firewall_action in ("0", "3"):
		data_dict[DENY_RULES].add(firewall_rule_id)
		data_dict[DENY_FREQUENCY] += 1
	else:
		data_dict[ALLOW_RULES].add(firewall_rule_id)
		data_dict[ALLOW_FREQUENCY] += 1

	global total_allow_deny_flip_flop_flows_count
	total_allow_deny_flip_flop_flows_count += 1

def record_flow_as_allowed_flow(key, firewall_rule_id, reporting_host):
	if key not in dict_allowed_flows:
		dict_allowed_flows[key] = initialize_data_dict()
	data_dict = dict_allowed_flows[key]
	data_dict[REPORTING_HOSTS].add(reporting_host)
	data_dict[ALLOW_RULES].add(firewall_rule_id)
	data_dict[ALLOW_FREQUENCY] += 1

def record_flow_as_denied_flow(key, firewall_rule_id, reporting_host):
	if key not in dict_denied_flows:
		dict_denied_flows[key] = initialize_data_dict()
	data_dict = dict_denied_flows[key]
	data_dict[REPORTING_HOSTS].add(reporting_host)
	data_dict[DENY_RULES].add(firewall_rule_id)
	data_dict[DENY_FREQUENCY] += 1

def parse_csv_and_generate_report(csv):
	global total_allow_deny_flip_flop_flows_count
	global total_flow_records_processed

	with open(csv, "r") as fp:
		while (True):
			currentLine = fp.readline().strip()
			if not currentLine:
				break
			fields = currentLine.strip().split(",")
			if currentLine.startswith("Proto"):
				continue
			if len(fields) != 17 and len(fields) != 18:
				continue
			index = 0
			if len(fields) == 18:
				index = 1
			total_flow_records_processed += 1
			source_ip = fields[0 + index].strip()
			source_port = fields[1 + index].strip()
			dest_ip = fields[2 + index].strip()
			dest_port = fields[3 + index].strip()
			reporting_host = fields[7 + index].strip()
			firewall_action = fields[11 + index].strip()
			firewall_rule_id = fields[12 + index].strip()

			if firewall_action in ("0", "3"): # i.e. Flow is denied flow
				# Find if there was a corresponding allowed flow for flipped source and destination
				key = ":".join([dest_ip, source_ip, source_port])
				if key in dict_allowed_flows:
					# So we have a flow that was found to be allowed some time earlier and is now denied
					record_flow_as_flip_flop_flow(key, firewall_action, firewall_rule_id, reporting_host)
				else:
					record_flow_as_denied_flow(key, firewall_rule_id, reporting_host)
			else:
				#allowed flow, add it to the allowed flow dict
				key = ":".join([source_ip, dest_ip, dest_port])
				if key in dict_denied_flows:
					# We found a flow that was found to be denied some time earlier and has been allowed now
					record_flow_as_flip_flop_flow(key, firewall_action, firewall_rule_id, reporting_host)
				else:
					record_flow_as_allowed_flow(key, firewall_rule_id, reporting_host)


def print_summary():
	print("\nTotal flow records processed: ", total_flow_records_processed)
	print("\nTotal flip/flop flow records found: ", total_allow_deny_flip_flop_flows_count)
	print("\nFlip/Flop percentage: ", float(total_allow_deny_flip_flop_flows_count*100)/float(total_flow_records_processed))

def print_detailed_report():
	for key in dict_flip_flop_flow:
		data_dict = dict_flip_flop_flow[key]
		key_fields = key.split(":")

		allowed_rules = ""
		for allow_rule in data_dict[ALLOW_RULES]:
			allowed_rules += allow_rule

		denied_rules = ""
		for deny_rule in data_dict[DENY_RULES]:
			denied_rules += deny_rule

		hosts = ""
		for host in data_dict[REPORTING_HOSTS]:
			hosts += host

		print ("\nSource IP: {}, Destination IP: {}, Destination Port: {}, Allow Rules: {}, Allow rules frequency: {}, Deny Rules: {}, Deny rules frequency: {}, Hosts: {}".format(key_fields[0],
																																												   key_fields[1],
																																												   key_fields[2],
																																												   allowed_rules,
																																												   data_dict[ALLOW_FREQUENCY],
																																												   denied_rules,
																																												   data_dict[DENY_FREQUENCY],
																																												   hosts))

	print("*"*20)
	print_summary()

if __name__ == '__main__':

	parser = OptionParser()
	#ToDo: If csv is not provided, also provide options for coverity server and creds
	# So that this script itself can dump the csv.
	parser.add_option("-c", "--csv",
					  dest="csv",
					  help="CSV file exported from coverity")
	parser.add_option("-d", "--detailed",
					  dest="detailed",
					  help="If a detailed report with all the flip flop IPs is needed, give this flag. By default only a summary is given")

	(options, args) = parser.parse_args()

	detailed_report = False
	if options.csv is None:
		parser.print_help()
		print "Insufficient arguments"
		sys.exit(1)
	if options.detailed is not None:
		detailed_report = True

	if not check_options(options):
		sys.exit(1)

	csv = options.csv
	parse_csv_and_generate_report(csv)
	if detailed_report:
		print_detailed_report()
	else:
		print_summary()