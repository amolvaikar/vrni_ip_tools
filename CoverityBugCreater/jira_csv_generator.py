csv = "/Users/avaikar/coverity/61704.csv"


ASSIGNEE_AMOL = "avaikar"
ASSIGNEE_YUSUF = "ybatterywala"
ASSIGNEE_SAMEER = "skarve"
ASSIGNEE_SHAILENDRA = "shailendrapa"
ASSIGNEE_AMARJIT = "guptaamarjit"
ASSIGNEE_LIST = [ASSIGNEE_AMOL, ASSIGNEE_YUSUF, ASSIGNEE_SAMEER, ASSIGNEE_SHAILENDRA, ASSIGNEE_AMARJIT]
ticketCounter = 0

def getAssignee(displayFile):
	global ticketCounter
	temp_displayfile = displayFile.lower()
	if "collector-framework" in temp_displayfile:
		if "nsx" in temp_displayfile or "vc" in temp_displayfile or "avi" in temp_displayfile or "tkg" in temp_displayfile:
			return ASSIGNEE_AMOL
		else:
			return ASSIGNEE_YUSUF
	if temp_displayfile.endswith(".c") or temp_displayfile.endswith(".cpp") or temp_displayfile.endswith(".h"):
		return ASSIGNEE_YUSUF
	if "/ui/" in temp_displayfile:
		return ASSIGNEE_SAMEER
	if "analytics" in temp_displayfile or "api" in temp_displayfile or "backup-restore" in temp_displayfile:
		return ASSIGNEE_SHAILENDRA
	if "day2ops" in temp_displayfile:
		return ASSIGNEE_AMARJIT
	idx = ticketCounter % len(ASSIGNEE_LIST)
	ticketCounter += 1
	return ASSIGNEE_LIST[idx]

def skipLine(fields):
	if not "High" in fields[2]:
		return True
	if fields[11].strip().endswith(".json"):
		return True
	if "test" in fields[11].lower():
		return True


with open(csv, "r") as fp:
	outfile = open("/Users/avaikar/coverity/input_file_for_jira_csv.csv", "w")
	outfile.write("summary, description, label, priority, epic, assignee, devContact\n")

	while (True):
		currentLine = fp.readline()
		if not currentLine:
			break
		if currentLine.startswith("cid"):
			continue

		fields = currentLine.split(",")
		if len(fields) != 15:
			continue
		if skipLine(fields):
			continue

		jira_title = fields[1]

		currentLine = fp.readline()
		cid = fields[0]
		displayType = fields[1]
		displayImpact = fields[2]
		displayCategory = fields[10]
		displayFile = fields[11]
		displayFuction = fields[12]
		lineNumber = fields[14].strip("\r\n")

		jira_summary = "COVERITY: CID {0} ; Category: {1}; Function: {2}; LineNo: {3}".format(cid, displayCategory,
																							  displayFuction,
																							  lineNumber)
		jira_description = jira_summary + "; File: {0}; Impact: {1}; Type: {2}".format(displayFile, displayImpact,
																						displayType)
		jira_label = "vrni-coverity"
		jira_priority = "Minor - P3"
		jira_epic = "CYG-83031"
		jira_assignee = getAssignee(displayFile)
		jira_devcontact = jira_assignee
		outfile.write("{0},{1},{2},{3},{4},{5},{6}\n".format(jira_summary,jira_description, jira_label, jira_priority, jira_epic, jira_assignee, jira_devcontact))



