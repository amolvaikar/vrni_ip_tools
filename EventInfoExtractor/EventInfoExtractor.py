

filep = open("/Users/avaikar/work/master/main/event-manager/src/main/resources/EventInfos.properties", "r")
filepOut = open("/Users/avaikar/eventinfo.csv", "w")
eventTypeToName = dict()
eventTypeToDescription = dict()
eventTypeToRecommendation = dict()

eventTypes = set()

while True:
	line = filep.readline()
	if not line:
		break
	if not (line.startswith("EventInfo") or line.startswith("SystemEventInfo")):
		continue
	splits = line.split("=", 1)
	keySplits = splits[0].split(".")
	eventType = keySplits[1]
	eventTypes.add(eventType)

	if line.find(".name") >= 0:
		eventTypeToName[eventType] = splits[1].replace("\n", "").replace(",", "")
	if line.find(".description") >= 0:
		eventTypeToDescription[eventType] = splits[1].replace("\n", "").replace(",", "")
	if line.find(".recommendation") >= 0:
		reco = ""
		if eventTypeToRecommendation.has_key(eventType):
			reco = eventTypeToRecommendation.get(eventType) + ","
		reco += splits[1].replace("\n", "").replace(",", "")
		eventTypeToRecommendation[eventType] = reco

filepOut.write("EventType,EventName,EventDescription,EventRecommendations\n")

for et in eventTypes:
	line = et+","
	if eventTypeToName.has_key(et):
		line += eventTypeToName.get(et)+","
	else:
		line += ","
	if eventTypeToDescription.has_key(et):
		line += eventTypeToDescription.get(et)+","
	else:
		line += ","
	if eventTypeToRecommendation.has_key(et):
		line += eventTypeToRecommendation.get(et)
	else:
		line += ","
	line += "\n"
	filepOut.write(line)

filep.close()
filepOut.close()
