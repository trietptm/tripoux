# Tripoux project - Joan Calvet - j04n.calvet@gmail.com
# Version : v0.1

# This is the IDA python script to import the output files of the Tripoux core engine into IDA.

import os

class Event:

	startAddress = 0
	endAddress = 0 # stay to zero for one shot event
	type = ""
	startTime = 0
	endTime = 0 # stay to zero for one shot event
	desc = ""

	def display(self):
		print "Start@:" + str(hex(self.startAddress)),
		if (self.endAddress != 0):
			print " - End@:" + str(hex(self.endAddress)),
		print " Type: " + self.type,
		print " StartTime: " + str(hex(self.startTime)),
		if(self.endTime != 0):
			print "- EndTime: " + str(hex(self.endTime))
		print "Description: " + self.desc
		
class Loop(Event):

	dynamicProfile = []
	ID = 0
	turn = 0
	
	def __init__(self):
		self.dynamicProfile = []

	def displayLoop(self):
		print "ID:" + str(hex(self.ID))
		print "Turn:" + str(self.turn)
		print "Dynamic Profile:"
		for i in self.dynamicProfile:
			print " " + str(hex(i)) + " ",
		print "\n"

def main():
	#function
	eventsList = list()
	codeXrefs = list()

	print "-----------------------------------------"
	print "Welcome into the Tripoux import script..."
	print "Please choose your events file"

	eventsFileName = AskFile(0,"*.log","Choose your Tripoux events file.")
	eventsFile = open(eventsFileName)

	print "Please choose your intemporal information file"
	intempInfoName = AskFile(0,"*.log","Choose your Tripoux intemporal info file.")
	intempInfoFile = open(intempInfoName)

	print "Please choose your wave file"
	waveFileName = AskFile(0,"*.log","Choose your Tripoux wave file.")
	waveFile = open(waveFileName)
	print "-----------------------------------------"


	###################################################
	# Initialisation phase : get the wave       #
	###################################################

	# Read Wave header : start time, end time
	line = waveFile.readline()
	entryTime = int(line[line.find("[Entry:")+7:line.find("-Exit")],16)
	exitTime = int(line[line.find("-Exit")+6:-2],16)
	if exitTime == 0:
		exitTime = 0xFFFFFFFF

	debug = 0
	patchTable = dict()
	minAddress = 0xFFFFFFFF
	maxAddress = 0x0

	line = waveFile.readline()
	while line != "":
		address = line[:line.find(" ")]
		opcode = line[line.find(" ")+1:-1]
		counter = 0
		for i in range(0,len(opcode),2):
			cursor = int(address,16) + counter
			counter = counter + 1
			newOpcode = int(opcode[i] + opcode[i+1],16)
			
			patchTable[cursor] = newOpcode
			
			if(cursor > maxAddress):
				maxAddress = cursor
			if(cursor < minAddress):
				minAddress = cursor

		line = waveFile.readline()

	print "Gathering finished..."
	# Are the wave instructions inside an IDA segment ?
	needNewSegment = 1
	for seg_ea in Segments():
		if(minAddress) in range(seg_ea,SegEnd(seg_ea)):
			if(maxAddress) in range(seg_ea,SegEnd(seg_ea)):
				needNewSegment = 0

	if needNewSegment:
		print "New segment creation..."
		SegCreate(minAddress,maxAddress+1,0,1,0,0)

	print "Patch!"

	for i in range(minAddress, maxAddress+1):
		if i in patchTable.keys():
			PatchByte(i,patchTable[i])
		else:
			if not isLoaded(i): # Dirty solution to make IDA happy : NOPs everywhere !
				PatchByte(i,0x90)

	print "Import events"

	line = eventsFile.readline()
	while line != "":
		if line.find("[=> EVENT:") != -1:
			type = line[line.find("[=> EVENT: ")+11:line.find(" <=]")]
			
			if type == "API CALL":
				newEvent = Event()
				newEvent.type = type
				# global header
				newEvent.startTime = int(line[line.find("TIME: ")+6:line.find("][@: ")],16)
				newEvent.startAddress = int(line[line.find("][@: ")+5:-2],16)
				
				# function description
				functionLine = eventsFile.readline()
				# static or dynamic
				functionType = functionLine[1]
				newEvent.type = functionType + " " + newEvent.type
				newEvent.desc = functionLine
				
				if((newEvent.startTime >= entryTime) & (newEvent.startTime <= exitTime)):
					eventsList.append(newEvent)
				#else:
				#	print "Fail " + str(newEvent.startTime)
				
			elif type == "SYSTEM ACCESS":
				newEvent = Event()
				newEvent.type = type
				# global header
				newEvent.startTime = int(line[line.find("TIME: ")+6:line.find("][@: ")],16)
				newEvent.startAddress = int(line[line.find("][@: ")+5:-2],16)
				newEvent.desc = eventsFile.readline()
				
				if((newEvent.startTime >= entryTime) & (newEvent.startTime <= exitTime)):
					eventsList.append(newEvent)
			
			elif type == "EXCEPTION":
				newEvent = Event()
				newEvent.type = type
				# global header
				newEvent.startTime = int(line[line.find("TIME: ")+6:line.find("][@: ")],16)
				newEvent.startAddress = int(line[line.find("][@: ")+5:-2],16)
				newEvent.desc = eventsFile.readline()
				
				if((newEvent.startTime >= entryTime) & (newEvent.startTime <= exitTime)):
					eventsList.append(newEvent)
			
			elif type.find("LOOP") != -1:
				newEvent = Loop()
				newEvent.type = "LOOP"
				newEvent.ID = int(type[5:],16)
				
				newEvent.startTime = int(line[line.find("[START: ")+8:line.find(" - END:")],16)
				newEvent.endTime = int(line[line.find("- END: ")+7:line.find("][H:")],16)
				newEvent.startAddress = int(line[line.find("][H: ")+7:line.find(" - T:")],16)
				newEvent.endAddress = int(line[line.find(" - T: ")+8:-2],16)
				
				# get the turn
				line = eventsFile.readline()
				newEvent.turn = int(line[line.find("TURN : ")+7:],16)
				
				while (line.find("[=> EVENT:") == -1) & (line != ""):
					if line.find("DYNAMIC PROFILE : ") != -1:
						dp = line[line.find("DYNAMIC PROFILE : ")+18:]
						for i in dp.split(" ")[:-1]:
							newEvent.dynamicProfile.append(int(i,16))
					line = eventsFile.readline()

				if((newEvent.startTime >= entryTime) & (newEvent.endTime <= exitTime)):
					eventsList.append(newEvent)
				continue	

			line = eventsFile.readline()
			
		else:
			line = 	eventsFile.readline()

	# Fakebr : translate the intemporal info as temporal event (one per fakebr)
	for line in intempInfoFile:

		address = int(line[2:line.find(" ")],16)
		target = "0x" + line[line.find("JAT ")+4:]
		
		newEvent = Event()
		newEvent.type = "JAT"
		newEvent.startAddress = address
		newEvent.desc = "Jump Always To " + target
		eventsList.append(newEvent)
		
	print "Import part ..."
	######################################
	# Step 2 :Import into the IDA database
	######################################
	for e in eventsList:
		if e.type == "SYSTEM ACCESS":
		
			p = e.desc.split("][")
			
			# Type
			if(p[0].find("READ") != -1):
				type = "READ"
			else:
				type = "WRITE"
			
			# Structure
			if(p[1].find("PEB") != -1):
				structure = "PEB"
			elif((p[1].find("PE") != -1) | (p[1].find("DOS") != -1)):
				structure = "PE"
			elif(p[1].find("TEB") != -1):
				structure = "TEB"
			
			# Module/Field
			if ((structure != "TEB") & (structure != "PEB")):
				module = p[2][p[2].find("[M:")+3:]
				field = p[3][p[3].find("[F:")+3:-2]
				comment = type + " " + module + "_" + structure + ".[" + field + "]"
			else:
				field = p[2][p[2].find("[F:")+3:-2]
				comment = type + " " + structure + ".[" + field + "]"
			
			comment = "/T\ " + comment
			oldComment = GetCommentEx(e.startAddress,0)
			if oldComment != None:
				MakeComm(e.startAddress,oldComment + "\n" + comment)
			else:
				MakeComm(e.startAddress,comment)
		
		elif e.type.find("API CALL") != -1:
			
			p = e.desc.split("][")
			
			# if the call is not named by IDA, add the name!
			currentName = Name(GetOperandValue(e.startAddress,0))
			if(currentName == ""):
				apiName = p[0][p[0].find("_")+1:]
			else:
				apiName = ""
			
			if(currentName.find("dword_") != -1): # This is not an API function name.
				apiName = p[0][p[0].find("_")+1:]
			
			arguments = "/T\ "
			for i in range(1,len(p)):
				arguments += p[i] + "\n/T\ " 
			arguments = arguments[:-7]
			
			if apiName != "":
				comment = "/T\ " + apiName + "()\n" + arguments
			else:
				comment = arguments
			
			if comment != "":
				oldComment = GetCommentEx(e.startAddress,0)
			
				if oldComment != None:
					# get the old API Name
					oldAPIName = oldComment[oldComment.find("/T\ ")+4:oldComment.find("()\n")]

					if(oldAPIName == apiName):
						# Already called ?
						if(oldComment.find("Called") != -1):
							number = int(oldComment[oldComment.find("Called ")+7:oldComment.find("times")])
							number = number + 1
							if apiName != "":
								comment = "/T\ " + apiName + "()\n" + "/T\ Called "+ str(number) + " times - Last time arguments:\n" + arguments
							else:
								comment = "/T\ Called "+ str(number) + " times - Last time arguments:\n" + arguments
						else:
							if apiName != "":
								comment = "/T\ " + apiName + "()\n" + "/T\ Called 2 times - Last time arguments:\n" + arguments
							else:
								comment = "/T\ Called 2 times - Last time arguments:\n" + arguments
								
						MakeComm(e.startAddress,comment)
					else:
						MakeComm(e.startAddress,oldComment + "\n" + comment)
				else:
					MakeComm(e.startAddress,comment)
				
		
		elif e.type == "EXCEPTION":
			handler = e.desc[3:e.desc.find("][")]
			errorCode = e.desc[e.desc.find("][")+4:-2]
			comment = "/T\ EXCEPTION - Handler " + handler + "\n/T\ Error code : " + errorCode
			
			oldComment = GetCommentEx(e.startAddress,0)
			if oldComment != None:
				MakeComm(e.startAddress,oldComment + "\n" + comment)
			else:
				MakeComm(e.startAddress,comment)
		
		elif e.type.find("LOOP") != -1:
			
			# First instance ?
			oldComment = GetCommentEx(e.startAddress,0)
			if(oldComment == None):
				comment = "/T\ LOOP [Head: 0x" + str(hex(e.startAddress)) + "-Tail: 0x" + str(hex(e.endAddress)) + "]\n/T\ IDs: [" + str(hex(e.ID)) + "]"
			else:
				if((len(oldComment) - 1) - oldComment.rfind("\n") > 60):
					comment = oldComment + "\n[" + str(hex(e.ID)) + "]"
				else:
					comment = oldComment + "[" + str(hex(e.ID)) + "]"
						
			MakeComm(e.startAddress,comment)
			
			# Dynamic profile
			for a in e.dynamicProfile:
				SetColor(a, CIC_ITEM, 0xFEAB9C)
				
		elif e.type == "JAT":
			comment = "/T\ " + e.desc[:-1]
			# Set a code xref
			fromAddr = e.startAddress
			toAddr = int(e.desc[e.desc.find("To ")+3:-1],16)
			
			#AddCodeXref(fromAddr, toAddr, fl_JN|XREF_USER)
			codeXrefs.append([fromAddr,toAddr])
			
			oldComment = GetCommentEx(e.startAddress,0)
			if oldComment != None:
				if oldComment.find("/T\\")== -1:
					MakeComm(e.startAddress,oldComment + "\n" + comment)
			else:
				MakeComm(e.startAddress,comment)

	# Set up code xrefs
	# To allow IDA to build functions
	i = 0
	while(i != len(codeXrefs)):
		if(Rfirst(codeXrefs[i][0]) == BADADDR):
			if(GetFunctionName(codeXrefs[i][0]) != ""):
				AddCodeXref(codeXrefs[i][0], codeXrefs[i][1], fl_JN|XREF_USER)
				idaapi.autoWait() # magic function...
				i=0
			else:
				i = i+1
		else:
			i = i+1

	# For the last xrefs...		
	i = 0
	while(i != len(codeXrefs)):
		if(Rfirst(codeXrefs[i][0]) == BADADDR):
			AddCodeXref(codeXrefs[i][0], codeXrefs[i][1], fl_JN|XREF_USER)
		i = i+1


	eventsFile.close()
	intempInfoFile.close()
		
if __name__ == "__main__":
	main()