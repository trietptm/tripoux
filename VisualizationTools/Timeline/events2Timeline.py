# Tripoux project - Joan Calvet - j04n.calvet@gmail.com
# Version : v0.1
# 
# This a script to generate the timeline view of the trace, in html.
# Very good example of what the lack of sleep can cause.

import os,string,sys
from datetime import datetime

LIGHT_MODE = 1

# CLASS
class Loop:
	
	id = 0
	smallReadAddresses = [] # <= 8 bytes
	smallWriteAddresses =[]
	bigReadAddresses = []
	bigWriteAddresses =[]

	def __init__(self, id):
		self.id = id

class Wave:

	id = 0
	startTime = ""
	endTime = ""
	sTimeInt = 0
	eTimeInt = 0
	
	def __init__(self, id, startTime, endTime):
		self.id = id
		self.startTime = startTime
		self.endTime = endTime

# CODE
timelineHeight = 650
if(len(sys.argv) == 3):
	if ((sys.argv[2] == "-h") | (sys.argv[2] == "-help")):
		print "Usage: python script.py timeline_heigth\n timeline_heigth: in pixels (optionnal, default: 650)"
	else:
		timelineHeight = int(sys.argv[2])
		
waveList = []
waveId = 0
waveEnded = 0
idWaveForLoop = 0xFF
currentWaveHasLoops = 0

loopsList = []

# Wave 0
currentWave = Wave(waveId, "Thu Jan  1 00:00:00 1970 GMT", 0)
currentWave.sTimeInt = 0

# Statistics
numberApiCalls = 0

# Javascript generation part
f = open(os.sys.argv[1])
outputJS = open("timeline.js","wb")
outputJS.write("var wave0 = {\n\'events\' : [")
loopCounter = 1
lastEventStr = ""
dynamicEntryStr = ""

zones = list([])
inZone = 0

lastEventTime = 1000
first = ""
second = ""
line = f.readline()
while line != "":
	if line.find("[=> EVENT:") != -1:
		
		eventType = line[line.find("[=> EVENT: ")+11:line.find(" <=]")]
		if eventType == "API CALL":
		
			numberApiCalls = numberApiCalls + 1
			
			# global header
			time = "0x" + line[line.find("TIME: ")+6:line.find("][@: ")]
			address = line[line.find("][@: ")+5:-2]
			#print "TIME ." + str(time) + "."
			d1 = datetime.utcfromtimestamp(int(time,16))
			time2 = d1.ctime() + " UTC"
			lastEventStr = time2
			
			if abs(int(time,16)-lastEventTime) < 180:
				if inZone:
					second = time2
				else:
					first = time2
					inZone = 1
			else:
				if inZone:
					zones.append([first,second])
					inZone = 0
					
			lastEventTime = int(time, 16)
		
			#specific header
			functionLine = f.readline()
			
			functionName = functionLine[3:functionLine.find("]")+1]
			# static or dynamic
			functionType = functionLine[1]
			functionArguments = functionLine[functionLine.find("]")+1:-1]
			functionArguments = functionArguments.replace("\\","\\\\")
			functionArguments = functionArguments.replace("]","]<br\>")
			
			outputJS.write("\n{\'start\': new Date(\'")
			outputJS.write(time2)
			outputJS.write("\'),\n\'title\': \'")
			outputJS.write(functionName[:-1])
			outputJS.write("()\',")
			outputJS.write("\n\'description\': \'") 
			if functionType == 'S':
				outputJS.write("Static ")
			else:
				outputJS.write("Dynamic ")
			outputJS.write("api call <br\>[@ ")
			outputJS.write(address)
			outputJS.write("][Time: ")
			outputJS.write(time)
			outputJS.write("]<br\><br\>")
			outputJS.write(functionArguments)

			desc = ""
			line = f.readline()
			while (line.find("[=> EVENT:") == -1) & (line != ""):
				line = line.replace("\\","\\\\")
				desc += line[:-1]
				desc += "<br\>"
				line = f.readline()
			desc += "\'"
			outputJS.write(desc)
			outputJS.write("},")
			
		elif eventType == "SYSTEM ACCESS":
			
			# # global header
			time = "0x" + line[line.find("TIME: ")+6:line.find("][@: ")]
			address = line[line.find("][@: ")+5:-2]
			d1 = datetime.utcfromtimestamp(int(time,16))
			time2 = d1.ctime() + " UTC"
			lastEventStr = time2
			
			outputJS.write("\n{\'start\': new Date(\'")
			outputJS.write(time2)
			outputJS.write("\'),\n\'title\': \'System Access\'")
			outputJS.write(",\n\'description\': \'") 
			outputJS.write("[@ ")
			outputJS.write(address)
			outputJS.write("][Time: ")
			outputJS.write(time)
			outputJS.write("]<br\><br\>")
			
			line = f.readline()
			line = line.replace("]","]<br\>")
			desc = line[:-1] + "\'},"
			outputJS.write(desc)
			
		elif eventType == "EXCEPTION":
				
			# # global header
			time = "0x" + line[line.find("TIME: ")+6:line.find("][@: ")]
			address = line[line.find("][@: ")+5:-2]
			d1 = datetime.utcfromtimestamp(int(time,16))
			time2 = d1.ctime() + " UTC"
			lastEventStr = time2
			
			outputJS.write("\n{\'start\': new Date(\'")
			outputJS.write(time2)
			outputJS.write("\'),\n\'title\': \'Exception\'")
			outputJS.write(",\n\'description\': \'") 
			outputJS.write("[@ ")
			outputJS.write(address)
			outputJS.write("][Time: ")
			outputJS.write(time)
			outputJS.write("]<br\><br\>")
			
			line = f.readline()
			desc = line[:-1] + "\'},"
			outputJS.write(desc)

		elif eventType.find("LOOP") != -1:

			if line.find("[H:") == -1:
				line = 	f.readline()
				continue
			
			if not waveEnded:
				currentWave.endTime = lastEventStr
				currentWave.eTimeInt = 0x0FFFFFFF
				waveList.append(currentWave)
				waveEnded = 1
			
			#global header
			timeStartStr = "0x" + line[line.find("[START: ")+8:line.find(" - END:")]
			timeEndStr = "0x" + line[line.find("- END: ")+7:line.find("][H:")]
			leadAddr = line[line.find("][H: ")+7:line.find(" - T:")]
			queueAddr = line[line.find(" - T: ")+8:-2]
			
			d1 = datetime.utcfromtimestamp(int(timeStartStr,16))
			timeStart = d1.ctime() + " UTC"
			d2 = datetime.utcfromtimestamp(int(timeEndStr,16))
			timeEnd = d2.ctime() + " UTC"
			lastEventStr = timeEnd
		
			# Look for the corresponding wave, assuming that loops are written in their time order
			for i in range(0,len(waveList)):
				if ((int(timeStartStr,16) >= waveList[i].sTimeInt) & (int(timeStartStr,16) <= int(waveList[i].eTimeInt))):
					if (idWaveForLoop != waveList[i].id):
						idWaveForLoop = waveList[i].id
						outputJS.write("]\n}\n")
						outputJS.write("var wave" + str(idWaveForLoop) + "LOOP = {\n\'events\' : [")
			
			outputJS.write("\n{\'start\': new Date(\'")
			outputJS.write(timeStart)
			outputJS.write("\'),\n\'end\': new Date(\'")
			outputJS.write(timeEnd)
			outputJS.write("\'),\n\'title\': \'Loop")
			outputJS.write(str(loopCounter))
			newLoop = Loop(loopCounter)
			loopCounter = loopCounter+1
			outputJS.write("\',")
			outputJS.write("\n\'description\': \'") 
			outputJS.write("[H: 0x")
			outputJS.write(leadAddr)
			outputJS.write("][T: 0x")
			outputJS.write(queueAddr)
			outputJS.write("][Entry time: ")
			outputJS.write(timeStartStr)
			outputJS.write("][Exit time: ")
			outputJS.write(timeEndStr)
			outputJS.write("]<br\><br\>")
			
			line = f.readline()
			
			if not LIGHT_MODE:
				desc=""
				while (line.find("[=> EVENT:") == -1) & (line != ""):
					if (line.find("| READ AREAS :") != -1) | (line.find("| WRITE AREAS :") != -1):
						desc += line[:-1].replace("B]","B]<br\>")
					else:
						desc += line[:-1]
					desc += "<br\>"
					line = f.readline()
				desc += "\'"
			else:
				desc=""
				while (line.find("[=> EVENT:") == -1) & (line != ""):
					if (line.find("| READ AREAS :") != -1):
						desc+="---------------------------------<br\>"
						t = line[line.find("| READ AREAS :")+14:].split("][")
						t[0] = t[0][2:]
						if len(t) > 1:
							t[len(t)-1] = t[len(t)-1][:-2]
						else:
							t[0] = t[0][:-2]
						desc+= "| READ AREAS : <br\>|(Size > 8 Bytes)"
						for i in t:
							if i != "":
								lengthByte = int(i[i.find(" 0x")+3:-2],16)
								if (lengthByte <= 8):
									newLoop.smallReadAddresses.append(i)
								else:
									newLoop.bigReadAddresses.append(i)
									desc+= "<br\>|->" + i
					elif (line.find("| WRITE AREAS :") != -1):
						desc+="---------------------------------<br\>"
						t = line[line.find("| WRITE AREAS :")+15:].split("][")
						t[0] = t[0][2:]
						if len(t) > 1:
							t[len(t)-1] = t[len(t)-1][:-2]
						else:
							t[0] = t[0][:-2]
						desc+= "| WRITE AREAS : <br\>|(Size > 8 Bytes)"
						for i in t:
							if i != "":
								lengthByte = int(i[i.find(" 0x")+3:-2],16)
								if (lengthByte <= 8):
									newLoop.smallReadAddresses.append(i)
								else:
									newLoop.bigReadAddresses.append(i)
									desc+= "<br\>|->" + i
					else:
						desc+="---------------------------------<br\>"
						if (line.find("TURN : ") != -1):
							t = line.replace("TURN : ", "NUMBER OF TURN : 0x")[:-1]
						else:
							t = line[:-1]
						desc += t
					desc += "<br\>"
					line = f.readline()	
				desc += "\'"
			
			
			outputJS.write(desc)
			outputJS.write("},")

		elif eventType == "NEW WAVE":
		
			# # # global header
			time = "0x" + line[line.find("TIME: ")+6:line.find("][LastBR: ")]
			address = line[line.find("][@: ")+5:-2]
			lastBr= line[line.find("LastBR: ")+8:line.find("][@:")]
			d1 = datetime.utcfromtimestamp(int(time,16))
			dynamicEntryStr = d1.ctime() + " UTC"
			lastEventStr = dynamicEntryStr
			
			# Add the wave for labels/colors
			# Close the previous wave
			currentWave.endTime = dynamicEntryStr
			currentWave.eTimeInt = int(time,16)
			waveList.append(currentWave)
			
			# Create a new wave
			waveId = waveId + 1
			currentWave = Wave(waveId,dynamicEntryStr,0)
			currentWave.sTimeInt = int(time,16)
			
			
			# create new variable
			outputJS.write("\n]\n}\nvar wave" + str(waveId) + " = {\n\'events\' : [")
			
			outputJS.write("\n{\'start\': new Date(\'")
			outputJS.write(dynamicEntryStr)
			outputJS.write("\'),\n\'title\': \'Entry in new wave\'")
			outputJS.write(",\n\'description\': \'") 
			outputJS.write("[Branch: " + lastBr + "]<br\>")
			outputJS.write("[Entry Address: ")
			outputJS.write(address)
			outputJS.write("]<br\>[Time: ")
			outputJS.write(time)
			outputJS.write("]<br\><br\>")
			outputJS.write("\'},")
			line = f.readline()	
	
		else:
			 line = 	f.readline()
	else:
		line = 	f.readline()	
f.close()			
outputJS.write("]\n}")

# Only one wave ! Useless ?
if dynamicEntryStr == "":
	dynamicEntryStr = lastEventStr

# Close the last wave if not done
if not waveEnded:
	currentWave.endTime = lastEventStr
	waveList.append(currentWave)
	
# HTML PART
eventFile = open(os.sys.argv[1])
canvas = open("canvas.html","rb")
outputHTML = open("timeline.html","wb")

# first step: write before the decorators
for line in canvas:
	if line.find("zones: [") != -1:
		outputHTML.write(line)
		break
	else:
		outputHTML.write(line)
		
canvas.close()

for z in zones[:-1]:
	outputHTML.write("\n{   start:    \"")
	outputHTML.write(z[0])
	outputHTML.write("\",\n end:      \"")
	outputHTML.write(z[1])
	outputHTML.write("\",\nmagnify:  10,\nunit:     Timeline.DateTime.MINUTE\n},")

outputHTML.write("],\n")

canvas = open("canvas.html","rb")
ok = 0
for line in canvas:
	if line.find("bandInfos[1].highlight = true;") != -1:
		outputHTML.write(line)
		break
	else:
		if ok:
			outputHTML.write(line)
		else:
			if line.find("eventSource:    eventSource,") != -1:
				ok = 1
				outputHTML.write(line)
canvas.close()
			
# dynamic code and start/end decorators
outputHTML.write("\tbandInfos[1].decorators = [ ")
for i in range(0,len(waveList)):
	if (i != 0):
		outputHTML.write(",\n")
	outputHTML.write("new Timeline.SpanHighlightDecorator({ \n startDate:  \"")
	outputHTML.write(waveList[i].startTime)
	outputHTML.write("\",\n endDate:    \"")
	outputHTML.write(waveList[i].endTime)
	if (i == len(waveList) -1):
		outputHTML.write("\",\n endLabel:    \"End")
	label = "Wave " + str(waveList[i].id)
	color = 0xCCFFFF - (0x3300 * i)
	outputHTML.write("\",\nstartLabel: \"" + label + "\",\ncolor:      \"" + str(hex(color)).replace("0x","#") + "\",                    \nopacity:    50,\ntheme:      theme\n})")
	

outputHTML.write("\n];\nbandInfos[0].decorators = [ ")
for i in range(0,len(waveList)):
	if (i != 0):
		outputHTML.write(",\n")
	outputHTML.write("new Timeline.SpanHighlightDecorator({ \n startDate:  \"")
	outputHTML.write(waveList[i].startTime)
	outputHTML.write("\",\n endDate:    \"")
	outputHTML.write(waveList[i].endTime)
	if (i == len(waveList) -1):
		outputHTML.write("\",\n endLabel:    \"End")
	label = "Wave " + str(waveList[i].id)
	color = 0xCCFFFF - (0x3300 * i)
	outputHTML.write("\",\nstartLabel: \"" + label + "\",\ncolor:      \"" + str(hex(color)).replace("0x","#") + "\",                    \nopacity:    50,\ntheme:      theme\n})")
outputHTML.write("\n];")


canvas = open("canvas.html","rb")
ok = 0
for line in canvas:
	if ok:
		if line.find("<a href=\"javascript:centerTimelineByInstruction(0);\">Wave 0</a>") != -1:
			outputHTML.write("&nbsp;-------------------------><br/>")
			outputHTML.write(line)
			
			for i in range(1,len(waveList)):
			
				outputHTML.write("&nbsp;&nbsp;&nbsp;&nbsp;<a href=\"javascript:centerTimelineByDate(new Date(\'")
				outputHTML.write(waveList[i].startTime)
				outputHTML.write("\'));\">Wave " + str(waveList[i].id) + "</a>")
				
			# End !
			outputHTML.write("&nbsp;&nbsp;&nbsp;&nbsp;<a href=\"javascript:centerTimelineByDate(new Date(\'")
			outputHTML.write(currentWave.endTime)
			outputHTML.write("\'));\">End</a>&nbsp;| Display code :&nbsp;")
			
			for i in range(0,len(waveList)):
				#outputHTML.write("<input type=\"button\" value=\"Display Wave " + str(i) + "\" onclick=\"waveCode(" + str(i) + ");\" />")
				outputHTML.write("<a href=\"javascript:waveCode(" + str(i) + ");\">Wave " + str(i) + "</a>&nbsp;&nbsp;&nbsp;&nbsp;")
			break;
		
		outputHTML.write(line)
	if line.find("bandInfos[1].highlight = true;") != -1:
		ok = 1
outputHTML.write("<br/>&nbsp;------------------------->")
outputHTML.write("\n<div id=\"tl\" class=\"timeline-default\" style=\"height: " + str(timelineHeight) + "px; border: 1px solid #aaa\"> </div>\n")

outputHTML.write("<BR/><FORM name=\"form1\"><INPUT type=\"text\" name=\"Texte\"><BR/><INPUT type=\"button\" value=\"Go To Timestamp !\" onClick=\"MoveTimeline()\"></FORM></div> <div class=\"controls\" id=\"controls\" style=\" border: 1px solid #aaa\">")
outputHTML.write("</div>")

outputHTML.write("Execution summary : <br/>* Number of waves : " + str(len(waveList)) + "<br/>* Number of API calls : " + str(numberApiCalls) + "</div> </html>")
			