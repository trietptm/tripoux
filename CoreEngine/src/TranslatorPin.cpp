/*

Tripoux project - Joan Calvet - j04n.calvet@gmail.com
Version : v0.1

This is the core engine of the project that translate the trace coming out from Pin into something usable.
It defines some high-level abstractions on the code.

TODO-LIST:
1- Divide into the Pin-specific part and the "real" core engine

*/

// STL headers
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cassert>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <bitset>
#include <limits>
#include <locale>
#include <set>
#include <map>
#include <list>

// Windows headers
#include <windows.h>
#include <winbase.h>

using namespace std;

// My header
#include "TranslatorPin.h"

string dynamicTraceFile;
string staticInstructionsFile;
string memFingerprint;

std::ofstream* translatorLog = 0;
std::ofstream* eventsFile = 0;
std::ofstream* intemporalInfo = 0;


bool checkArguments(int argc, char * argv[])
{
	// We need 3 arguments
	int i;
	int found = 0;

	for(i = 1; i < argc; i++)
	{

		/* Help */
		if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
		{
			cout << "Usage: translatorPin.exe -t dynamicTraceFile -s staticInstructionsFile -m memFingerprint\n"
				"These 3 files come from the Pin tracer of the Tripoux project."
			  << endl;
			cout << "Optionnal arguments : --no-loops, --no-waves, --no-apicalls, --no-exceptions, --no-systemaccess, --no-fakebr" << endl;
		  exit(0);
		}

		/* Dynamic trace file */
		if(strcmp(argv[i], "-t") == 0)
		{	
			if(i+1<argc) 
			{
				dynamicTraceFile = argv[i+1];
				found++;
			}
			else
			{
				cout << "Missing parameter : filename behind -t" << endl;
				return false;
			}
		}

		/* Static instructions file */
		if(strcmp(argv[i], "-s") == 0)
		{	
			if(i+1<argc) 
			{
				staticInstructionsFile = argv[i+1];
				found++;
			}
			else
			{
				cout << "Missing parameter : filename behind -s" << endl;
				return false;
			}
		}

		/* Memory fingerprint file */
		if(strcmp(argv[i], "-m") == 0)
		{	
			if(i+1<argc) 
			{
				memFingerprint = argv[i+1];
				found++;
			}
			else
			{
				cout << "Missing parameter : filename behind -m" << endl;
				return false;
			}
		}

		if(strcmp(argv[i], "--no-loops") == 0)
		{
			cout << "No loops mode" << endl;
			NO_LOOPS = 1;
		}
		
		if(strcmp(argv[i], "--no-waves") == 0)
		{
			cout << "No waves mode" << endl;
			NO_WAVES = 1;
		}

		if(strcmp(argv[i], "--no-apicalls") == 0)
		{
			cout << "No API calls mode" << endl;
			NO_APICALLS = 1;
		}

		if(strcmp(argv[i], "--no-exceptions") == 0)
		{
			cout << "No exceptions mode" << endl;
			NO_EXCEPTIONS = 1;
		}

		if(strcmp(argv[i], "--no-systemaccess") == 0)
		{
			cout << "No system access mode" << endl;
			NO_SYSTEMACCESS = 1;
		}

		if(strcmp(argv[i], "--no-fakebr") == 0)
		{
			cout << "No fake branch mode" << endl;
			NO_FAKEBR = 1;
		}

	}

	if(found != 3) // Missing parameters
	{
		cout << "Missing parameters : check -h" << endl;
		return false;
	}
	else
		return true;
}

void initStaticInformation()
{
	// All the static information are readen and stored
	ifstream staticFileBinary (staticInstructionsFile.c_str(), ios::in | ios::binary );
	ifstream staticFile (staticInstructionsFile.c_str(), ifstream::in);

	string line;

	while(staticFile.good())
	{
		getline(staticFile,line);

		char buff[64];
		memset(buff,'\x0',64);
		
		// Do it nasty, do it quicky, do it with sscanf()

		staticX86Instruction currentStaticInstruction;
	
		int currentHash=0;

		sscanf(line.c_str(),"%x ! %x ! %hx ! %*x ! %*x ! %s",
			&currentHash,
			&currentStaticInstruction.instructionLength,
			&currentStaticInstruction.typeS,
			buff);

		currentStaticInstruction.binaryCode = buff;

		staticInformation[currentHash] = currentStaticInstruction;

	}
}

void initMemFingerprint()
{
	ifstream memFingerprintFile (memFingerprint.c_str(), ifstream::in );

	string line;

	while(memFingerprintFile.good())
	{
		getline(memFingerprintFile,line);
		
		int baseAddress;
		char typeBuff[8];
		char nameBuff[16];
		memset(typeBuff,'\x0',8);
		memset(nameBuff,'\x0',16);

		sscanf(line.c_str(),"%s %s %x",
			typeBuff,
			nameBuff,
			&baseAddress);
		
		dynamicModule newModule;
		newModule.name = nameBuff;
		newModule.type = typeBuff;

		// Update the gate
		if(gateToMemModules>baseAddress)
			gateToMemModules = baseAddress;

		if(newModule.type.compare("PE32H") == 0)
			newModule.interval = addressInterval32b(baseAddress,baseAddress+PE32_HEADER_SIZE);
		else if(newModule.type.compare("DOSH") == 0)
			newModule.interval = addressInterval32b(baseAddress,baseAddress+DOS_HEADER_SIZE);
		else if(newModule.type.compare("PEB") == 0)
			newModule.interval = addressInterval32b(baseAddress,baseAddress+PEB_SIZE); 
		else if(newModule.type.compare("TEB") == 0)
			newModule.interval = addressInterval32b(baseAddress,baseAddress+TEB_SIZE);
		else
			if(!newModule.type.empty())
				*translatorLog << "Problem during parsing the memory fingerprint file : Type " << newModule.type << " not found" << endl;

		memModules.push_back(newModule);

	}
}

void checkMemAccessInsideModules(dynamicX86Instruction instr, int type)
{
	
	int address;
	
	if(type)
		address = instr.memReadAddress;
	else
		address = instr.memWriteAddress;

	vector<dynamicModule>::iterator it;
	for(it = memModules.begin(); it != memModules.end(); it++)
	{
		if(it->interval.isInside(address))
		{
			*eventsFile << "[=> EVENT: SYSTEM ACCESS <=][TIME: " << hex << instr.time <<  "][@: 0x" << hex << instr.address << "]" << endl;
			if(type)
				*eventsFile << "[READ]";
			else
				*eventsFile << "[WRITE]";

			if((it->type.compare("TEB") == 0) || (it->type.compare("PEB") == 0))
				*eventsFile << "[S:" << it->type << "]";
			else

				*eventsFile << "[S:" << it->type << "][M:" << it->name << "]";

			int offset = address - it->interval.startAddress;

			if(it->type.compare("PE32H") == 0)
			{
				if(PE32Header.find(offset) != PE32Header.end())
					*eventsFile << "[F:" << PE32Header[offset] << "]" << endl;
				else
					*eventsFile << "[F:Unknown field]" << endl;
			}
			if(it->type.compare("DOSH") == 0)
			{
				if(DOSHeader.find(offset) != DOSHeader.end())
					*eventsFile << "[F:" << DOSHeader[offset] << "]" << endl;
				else
					*eventsFile << "[F:Unknown field]" << endl;
			}
			if(it->type.compare("PEB") == 0)
			{
				if(PEBStruct.find(offset) != PEBStruct.end())
					*eventsFile << "[F:" << PEBStruct[offset] << "]" << endl;
				else
					*eventsFile << "[F:Unknown field]" << endl;
			}
			if(it->type.compare("TEB") == 0)
			{
				if(TEBStruct.find(offset) != TEBStruct.end())
					*eventsFile << "[F:" << TEBStruct[offset] << "]" << endl;
				else
					*eventsFile << "[F:Unknown field]" << endl;
			}


			
		}
	}
}

// Kind of garbage collector
void cleanLoops(int currentTime)
{
	map<int, Loop>::iterator itLoop = loopsMap.begin();
	while(itLoop != loopsMap.end())
	{
		if(itLoop->second.valid == 0)
		{
			if((currentTime - itLoop->second.entryTime) > 100000) // rick rolled
			{
				//*translatorLog << "Fake loop vire H: 0x"<< hex << itLoop->second.head.address << " L: 0x" << hex << itLoop->second.tail.address << endl ;
				int id = itLoop->first;
				itLoop++;
				loopsMap.erase(id);
			}
			else
				itLoop++;
		}
		else
			itLoop++;		
	}
}

template <class T>
bool from_string(T& t, 
                 const std::string& s, 
                 std::ios_base& (*f)(std::ios_base&))
{
  std::istringstream iss(s);
  return !(iss >> f >> t).fail();
}


void analysis(list<dynamicX86Instruction> dTrace)
{
	list<dynamicX86Instruction>::iterator it;

	for(it = dTrace.begin() ; it != dTrace.end() ; it++)
	{

		// ** LOOP DETECTION ** //
		if(!NO_LOOPS)
		{
			// Is the instruction already in cache ?
			if(cacheS.find(*it) != cacheS.end())
			{
				/**translatorLog << "ALREADY IN CACHE : T:" << it->time <<" @:"
				<< hex << it->address << " "
				<< hex << it->hash << "->[B:" << staticInformation[it->hash].binaryCode << "!S:" << staticInformation[it->hash].instructionLength 
				<< "!T:" << staticInformation[it->hash].typeS << "] "
				<< "RM:" << hex << it->memReadAddress << "_" << it->memReadSize
				<< " WM:" << hex << it->memWriteAddress << "_" << it->memWriteSize;
				if (!it->comments.empty())
					*translatorLog << " C:" << it->comments;
				*translatorLog << endl;		*/

				// Create h and t
				loopExtremity head(it->address,it->hash);
				loopExtremity tail(cacheL.front().address, cacheL.front().hash);

				// Look if there is an associated non closed loop (valid or not!)
				if(tailToNCLoop.find(tail) != tailToNCLoop.end())
				{
					int id = tailToNCLoop.find(tail)->second;

					loopsMap[id].valid = 1;
					loopsMap[id].turn++;
					loopsMap[id].endTime = it->time;
					headToVTails[head].insert(tail);
				}
				else
				{
					// Check if the tail is not valid for this head
					if(headToVTails[head].find(tail) == headToVTails[head].end())
					{
						// We have to close all the current loops with head
						set<loopExtremity>::iterator it2;

						// Loop on the tails attached to the head
						for(it2 = headToVTails[head].begin();
							it2 != headToVTails[head].end();
							it2++)
						{
							// Close the associated non-closed and valid loops
							if(tailToNCLoop.find(*it2) != tailToNCLoop.end())
							{
								if((loopsMap[tailToNCLoop[*it2]].closed == 0) && (loopsMap[tailToNCLoop[*it2]].valid))
								{
									loopsMap[tailToNCLoop[*it2]].closed = 1;
									tailToNCLoop.erase(*it2);
								}
							}
						}
					}

					// Loop creation
					Loop newLoop;
					newLoop.id = loopID;
					loopID++;
					newLoop.head = head;
					newLoop.tail = tail;
					newLoop.entryTime = cacheS.find(*it)->time;
					newLoop.endTime = 0;
					newLoop.valid = 0;
					newLoop.closed = 0;
					newLoop.turn = 1;

					loopsMap[newLoop.id] = newLoop;

					tailToNCLoop[tail]=newLoop.id;
					

				}

				// Pop the cache !
				list<dynamicX86Instruction>::iterator it3;
				//int found = 0;

				// Find the position of the other instance of the instruction
				for(it3 = cacheL.begin();
					it3 != cacheL.end();
					it3++)
				{
					if(*it3 == *it)
					{
						//found = 1;
						break;
					}
				}
					
				// Pop loop
				int countToPop = distance(cacheL.begin(),it3)+1;
				for(int i=0;i<countToPop;i++)
				{
					int loopId = tailToNCLoop[tail];

					// Clusterize the memory effects of the loop body instructions
					if(cacheL.front().memReadSize != 0)
					{
						// Build a new address interval
						addressInterval32b readInterval = addressInterval32b(cacheL.front().memReadAddress, 
							cacheL.front().memReadAddress + cacheL.front().memReadSize - 1);
						
						// Look for possible intersections with the current clusters
						vector<addressInterval32b>::iterator itR = loopsMap[loopId].readAddresses.begin();
						while(itR != loopsMap[loopId].readAddresses.end())
						{
							if(readInterval.intersect(*itR))
							{
								// Create a new interval with fusion
								readInterval = readInterval.fusion(*itR);
								loopsMap[loopId].readAddresses.erase(itR);
								// Relaunch the loop
								itR = loopsMap[loopId].readAddresses.begin();
							}
							else
								itR++;
						}
						// Add the new interval
						loopsMap[loopId].readAddresses.push_back(readInterval);
					}

					// Same for write
					if(cacheL.front().memWriteSize != 0)
					{
						// Build a new address interval
						addressInterval32b writeInterval = addressInterval32b(cacheL.front().memWriteAddress, 
							cacheL.front().memWriteAddress + cacheL.front().memWriteSize - 1);
						
						// Look for possible intersections with the current clusters
						vector<addressInterval32b>::iterator itW = loopsMap[loopId].writeAddresses.begin();
						while(itW != loopsMap[loopId].writeAddresses.end())
						{
							if(writeInterval.intersect(*itW))
							{
								// Create a new interval with fusion
								writeInterval = writeInterval.fusion(*itW);
								loopsMap[loopId].writeAddresses.erase(itW);
								// Relaunch the loop
								itW = loopsMap[loopId].writeAddresses.begin();
							}
							else
								itW++;
						}
						// Add the new interval
						loopsMap[loopId].writeAddresses.push_back(writeInterval);
					}

					// Build dynamic profile (i.e. gather the instructions that have different memory effects during the loop execution)
					int currentInstAddress = cacheL.front().address;
					if(loopsMap[loopId].dynamicProfile.find(currentInstAddress) == loopsMap[loopId].dynamicProfile.end())
					{
						if(loopsMap[loopId].staticProfile.find(currentInstAddress) != loopsMap[loopId].staticProfile.end())
						{
							vector<int> sProfile = loopsMap[loopId].staticProfile[currentInstAddress];
							if((cacheL.front().memReadAddress != sProfile[0]) || 
								(cacheL.front().memWriteAddress != sProfile[1]))
							{
								loopsMap[loopId].dynamicProfile.insert(currentInstAddress);
								loopsMap[loopId].staticProfile.erase(currentInstAddress);
							}
						}
						else
						{
							vector<int> sProfile;
							sProfile.push_back(cacheL.front().memReadAddress);
							sProfile.push_back(cacheL.front().memWriteAddress);
							loopsMap[loopId].staticProfile[currentInstAddress] = sProfile;
						}
					}

					// Finally pop !
					cacheS.erase(cacheL.front());
					cacheL.pop_front();
				}
			}
			else
			{
				loopExtremity head(it->address,it->hash);
				// Close all the valid tails associated
				if(!headToVTails[head].empty())
				{
					set<loopExtremity>::iterator it4;
					for(it4 = headToVTails[head].begin();
						it4 != headToVTails[head].end();
						it4++)
					{
						if(tailToNCLoop.find(*it4) != tailToNCLoop.end())
						{
							loopsMap[tailToNCLoop[*it4]].closed = 1;
							tailToNCLoop.erase(*it4);
						}
					}
				}
			}

			// Push the current instruction !
			cacheS.insert(*it);
			cacheL.push_front(*it);

			if(cacheS.size() > CACHE_DEPTH)
			{
				cacheS.erase(cacheL.back());
				cacheL.pop_back();
			}
		}
		// ** WAVES DETECTION ** //
		// !! WARNING : without wave detection, some others algorithms could fail !! 
		if(!NO_WAVES)
		{
			// Detect
			if(currentWriteSet.find(it->address) != currentWriteSet.end())
			{
				*eventsFile << "[=> EVENT: NEW WAVE <=][TIME: " << hex << it->time << "][LastBR: 0x" << hex << lastBranch << "][@: 0x" << hex << it->address << "]" << endl;
				currentWriteSet.clear();

				dumpFakeBR();
				fakeBr.clear();
				trueBr.clear();

				currentWave->exitTime = it->time - 1;
				dumpCurrentWave();

				// Create the new wave
				currentWave->id = currentWave->id + 1;
				currentWave->startTime = it->time;
				currentWave->machineCode.clear();


				// TEST TEST
				//exit(1);
			}
		
			// Store the last branch
			if((staticInformation[it->hash].typeS & 0x8000) != 0)
				lastBranch = it->address;

			// Add write address
			if(it->memWriteAddress != 0)
			{
				for(int i = 0; i<it->memWriteSize; i++)
					currentWriteSet.insert(it->memWriteAddress + i);
			}
		
			// Store the machine code
			currentWave->machineCode[it->address] = staticInformation[it->hash].binaryCode;

		}

		// ** API CALLS ** //
		if(!NO_APICALLS)
		{
			if(it->comments.find("callAPI") != string::npos)
			{
				*eventsFile << "[=> EVENT: API CALL <=][TIME: " << hex << it->time << "][@: 0x" << hex << it->address << "]" << endl;
				*eventsFile << it->comments.substr(it->comments.find("callAPI")+8) << endl;
			}
		}

		// ** EXCEPTIONS ** //
		if(!NO_EXCEPTIONS)
		{
			if(it->comments.find("EXCEPTION") != string::npos)
			{
				*eventsFile << "[=> EVENT: EXCEPTION <=][TIME: " << hex << it->time << "][@: 0x" << hex << it->address << "]" << endl;
				*eventsFile << "[H:" << it->comments.substr(it->comments.find("HANDLER:")+8,it->comments.rfind("]")-(it->comments.find("HANDLER:")+8)) << "]";
				*eventsFile << "[C:" << it->comments.substr(it->comments.find("EXCEPTION")+11,11) << endl;
				
			}
		}

		// ** ACCESS PE HEADER/TEB/PEB ** //
		if(!NO_SYSTEMACCESS)
		{
			// Check read access
			if(it->memReadAddress > gateToMemModules)
				checkMemAccessInsideModules(*it,1);

			// Check write access
			if(it->memWriteAddress > gateToMemModules)
				checkMemAccessInsideModules(*it,0);
		}

		// ** FAKE CONDITIONNAL/INDIRECT BRANCHS ** //
		if(!NO_FAKEBR)
		{
			if(checkFollowerBr)
			{
				if(fakeBr.find(checkFollowerBr)->second != it->address)
				{
					fakeBr.erase(checkFollowerBr);
					trueBr.insert(checkFollowerBr);
				}
				checkFollowerBr = 0;
			}
			else if(insertFollowerBr)
			{
				fakeBr[insertFollowerBr] = it->address;
				insertFollowerBr = 0;
			}

			// Check if it's a branch
			if((staticInformation[it->hash].typeS & 0x8000) != 0)
			{
				// API calls are indirect branchs but not interesting here
				if(it->comments.find("callAPI") != string::npos)
					continue;

				// Conditionnal or indirect branch
				if(((staticInformation[it->hash].typeS & 0x4000) != 0) || ((staticInformation[it->hash].typeS & 0x2000) == 0))
				{
					if(trueBr.find(it->address) == trueBr.end())
					{
						if(fakeBr.find(it->address) != fakeBr.end())
							checkFollowerBr = it->address;
						else
							insertFollowerBr = it->address;
					}
				}
			}

		}

	}
}

void dumpCurrentWave()
{
	// 1. File creation

	std::stringstream out;
	out << hex << currentWave->id;

	string fileName = "tripoux_wave_";
	fileName.append(out.str());
	fileName.append(".log");
	
	std::ofstream waveFile(fileName.c_str());

	// 2. Write header
	waveFile << "[WAVE " << hex << currentWave->id << "][Entry:" << hex << currentWave->startTime << "-Exit:" << hex << currentWave->exitTime << "]" << endl;

	// 3. Dump actual instructions
	map<int,string>::iterator itOnMachineCode;
	for(itOnMachineCode = currentWave->machineCode.begin();
		itOnMachineCode != currentWave->machineCode.end();
		itOnMachineCode++)
		waveFile << hex << itOnMachineCode->first << " " << itOnMachineCode->second << endl;

	waveFile.close();
}

void dumpFakeBR()
{
	map<int,int>::iterator itBR;

	for(itBR = fakeBr.begin();
		itBR != fakeBr.end();
		itBR++)
	{
		*intemporalInfo << "0x" << hex << itBR->first << " JAT " << hex << itBR->second << endl;
	}
	
}

void dumpLoopsAsEvents()
{

	map<int, Loop>::iterator it;
	int realID = 0;

	for(it = loopsMap.begin();
		it != loopsMap.end();
		it++)
	{
		if(it->second.valid)
		{

			*eventsFile << "[=> EVENT: LOOP " << realID << " <=][START: " << it->second.entryTime << " - END: " <<  it->second.endTime 
				<<  "][H: 0x" << hex << it->second.head.address
				<< " - T: 0x" << hex << it->second.tail.address << "]" << endl;
			*eventsFile << "| TURN : " << it->second.turn << endl;
			*eventsFile << "| READ AREAS : ";
			vector<addressInterval32b>::iterator itR;
			
			for(itR = it->second.readAddresses.begin();
				itR != it->second.readAddresses.end();
				itR++)
				*eventsFile << "[0x" << hex << itR->startAddress << "-0x" << hex << itR->endAddress << ": 0x" << itR->endAddress - itR->startAddress + 1<< " B]";
			
			*eventsFile << endl;

			*eventsFile << "| WRITE AREAS : ";
			vector<addressInterval32b>::iterator itW;
			
			for(itW = it->second.writeAddresses.begin();
				itW != it->second.writeAddresses.end();
				itW++)
				*eventsFile << "[0x" << hex << itW->startAddress << "-0x" << hex << itW->endAddress << ": 0x" << hex << itW->endAddress - itW->startAddress + 1 <<" B]";

			*eventsFile << endl;
	
			*eventsFile << "| DYNAMIC PROFILE : ";
			set<int>::iterator itDP;
			for(itDP = it->second.dynamicProfile.begin();
				itDP != it->second.dynamicProfile.end();
				itDP++)
				*eventsFile << "0x" << hex << *itDP << " ";

			*eventsFile << endl;
		
			realID++;
		}
	}

}

int main(int argc, char * argv[])
{
	translatorLog = new std::ofstream("translator.log"); // Errors and bullshit file
	eventsFile = new std::ofstream("events.log");
	intemporalInfo = new std::ofstream("intemporalInfo.log");

	if(!checkArguments(argc,argv))
		return 1;

	initStaticInformation();
	initWinStructures();
	initMemFingerprint();

	char line[512]; // yes, that exists
	memset(line,0,512);

	int numberOfInstructions;
	int currentAddress = 0;

	dynamicX86Instruction currentInst;
	currentInst.address = 0;
	currentInst.typeD = 0;

	int newTime=1;
	int turn = 1;

	currentWave = new waveDynamicCode();
	currentWave->id = 0; // first (fake) wave
	currentWave->startTime = 0;
	currentWave->exitTime = 0;

	// Read the dynamic trace : mmap() style !
	HANDLE dTraceFile = CreateFile(dynamicTraceFile.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if(dTraceFile == INVALID_HANDLE_VALUE)
	{
		*translatorLog << "Error when opening dynamic trace file : " << GetLastError() << endl;
		ExitProcess(1);
	}

	HANDLE dTraceMapping = CreateFileMapping(dTraceFile,
		NULL,
		PAGE_READONLY,
		0,
		0,
		NULL);

	if(dTraceMapping == NULL)
	{
		*translatorLog << "Error when mapping dynamic trace file : " << GetLastError() << endl;
		ExitProcess(1);
	}

	LPVOID cursorDTrace = MapViewOfFile(dTraceMapping,
		FILE_MAP_READ,
		0,
		0,
		0);

	if(cursorDTrace == NULL)
	{
		*translatorLog << "Error when viewing mapped dynamic trace file : " << GetLastError() << endl;
		ExitProcess(1);
	}

	// Get the size of the mapped view
	MEMORY_BASIC_INFORMATION infBuffer;
	VirtualQuery(cursorDTrace,&infBuffer,sizeof(MEMORY_BASIC_INFORMATION));

	void* endLine = memchr(cursorDTrace,0x0d0a,512);
	list<dynamicX86Instruction> dTrace;
	
	while(endLine != NULL)
	{
		numberOfInstructions = 0;
		int gatherNextInstruction = 0;

		while((numberOfInstructions < INSTRUCTIONS_LOAD)&&(endLine != NULL))
		{

				memset(line,0,512);
				memcpy(line,cursorDTrace,((char*)endLine-(char*)cursorDTrace) - 1); // getline()
				cursorDTrace = (char*)endLine + 1;

				/*if((unsigned)(int)cursorDTrace + 512 < (unsigned)((int)infBuffer.BaseAddress + infBuffer.RegionSize)) // To avoid mem access violation :)
					endLine = memchr(cursorDTrace,0x0d0a,512);
				else
				{
					if((unsigned)(int)cursorDTrace + 256 < (unsigned)((int)infBuffer.BaseAddress + infBuffer.RegionSize))
						endLine = memchr(cursorDTrace,0x0d0a,256);
					else
					{
						if((unsigned)(int)cursorDTrace + 128 < (unsigned)((int)infBuffer.BaseAddress + infBuffer.RegionSize))
							endLine = memchr(cursorDTrace,0x0d0a,128);
						else
							endLine = NULL;
					}
					//break;
				}*/

				if((unsigned)(int)cursorDTrace + 512 > (unsigned)((int)infBuffer.BaseAddress + infBuffer.RegionSize)) // To avoid mem access violation :)
					endLine = memchr(cursorDTrace,0x0d0a,(unsigned)((int)infBuffer.BaseAddress + infBuffer.RegionSize) - (unsigned)(int)cursorDTrace);
				else
					endLine = memchr(cursorDTrace,0x0d0a,512);

				int address = 0;
				int hash = 0;
				char buff[32];
				memset(buff,'\x0',32);

				// Check comments
				if(line[0] == '[')
				{
					currentInst.comments = line;
					if(line[1] == 'E') // Only do that for exceptions...
						gatherNextInstruction = 1; // gather handler address

					if(endLine == NULL)
						dTrace.push_back(currentInst);
					continue;
					
				}
		
				if((line[0] == 'R') || (line[0] == 'W'))
					sscanf(line,"%s",
						buff);
				else
				{
					sscanf(line,"%*x ! %x ! %x ! %s",
						&address,
						&hash,
						buff);
					if(gatherNextInstruction)
					{
						std::stringstream out;
						out << hex << address;

						currentInst.comments.append("[HANDLER:0x");
						currentInst.comments.append(out.str());
						currentInst.comments.append("]");
						gatherNextInstruction = 0;
					}
				}
				
				
				// First instruction
				if(currentInst.address == 0)
				{
					currentInst.address = address;
					currentInst.hash = hash;
					currentInst.time = newTime;
					currentInst.typeD = 0;
				}

				if((address != 0) && (address != currentInst.address))
				{
						// Add the current instruction to the trace
						//*translatorLog << "T:" << currentInst.time <<" @:"
						//<< hex << currentInst.address << " "
						//<< hex << currentInst.hash << "->[B:" << staticInformation[currentInst.hash].binaryCode << "!S:" << staticInformation[currentInst.hash].instructionLength 
						//<< "!T:" << staticInformation[currentInst.hash].typeS << "] "
						//<< "RM:" << hex << currentInst.memReadAddress << "_" << currentInst.memReadSize
						//<< " WM:" << hex << currentInst.memWriteAddress << "_" << currentInst.memWriteSize;
						//if (!currentInst.comments.empty())
						//	*translatorLog << " C:" << currentInst.comments;
						//*translatorLog << endl;

						dTrace.push_back(currentInst);

						numberOfInstructions++;
						newTime++;
						currentInst.address = address;
						currentInst.hash = hash;
						currentInst.time = newTime;
						currentInst.typeD = 0;
						currentInst.memReadAddress = 0;
						currentInst.memReadSize = 0;
						currentInst.memWriteAddress = 0;
						currentInst.memWriteSize = 0;
						currentInst.comments = string();
				}

				// Fusion effets
				string effect = buff;
				if(!effect.empty())
				{
					switch(effect[0])
					{
						case 'R':
							if(effect[1] == 'M')
							{
								string memR = effect.substr(effect.find("_")+1,(effect.find_last_of("_") - (effect.find("_")+1)));
								string size = effect.substr(effect.find_last_of("_")+1);
								from_string<int>(currentInst.memReadAddress, memR, std::hex);
								from_string<int>(currentInst.memReadSize, size, std::hex);
							}
							break;
						case 'W':
							if(effect[1] == 'M')
							{
								string memW = effect.substr(effect.find("_")+1,(effect.find_last_of("_") - (effect.find("_")+1)));
								string size = effect.substr(effect.find_last_of("_")+1);
								from_string<int>(currentInst.memWriteAddress, memW, std::hex);
								from_string<int>(currentInst.memWriteSize, size, std::hex);
							}
							break;
						default:
							*translatorLog << "Error during parsing dynamic trace : unknown effect" << endl;
							break;
					}
				}
			
				

		}
		
		// Analysis function called here with a subset of the trace
	
		analysis(dTrace);
		
		cout << "Instructions analyzed: " << dec <<  INSTRUCTIONS_LOAD * turn << endl;

		turn++;
		dTrace.clear();
		
		cleanLoops(newTime);

		//if(turn == 10)
		//{
		//	cout << "END !" << endl;
		//	dumpFakeBR();
		//	dumpLoopsAsEvents();
		//	exit(1);
		//}
	}

	currentWave->exitTime = 0;
	dumpCurrentWave();
	dumpFakeBR();
	dumpLoopsAsEvents();

	return 0;
}

void initWinStructures()
{
	// I assume that malware don't read the middle of the fields.. lazy bastard !

	// DOS header (OllyDbg names)
	DOSHeader[0] = "DOS_Signature";
	DOSHeader[2] = "DOS_PartPag";
	DOSHeader[4] = "DOS_PageCnt";
	DOSHeader[6] = "DOS_ReloCnt";
	DOSHeader[8] = "DOS_HdrSize";
	DOSHeader[10] = "DOS_MinMem";
	DOSHeader[12] = "DOS_MaxMem";
	DOSHeader[14] = "DOS_RelSS";
	DOSHeader[16] = "DOS_ExeSP";
	DOSHeader[18] = "DOS_ChkSum";
	DOSHeader[20] = "DOS_ExeIP";
	DOSHeader[22] = "DOS_RelCS";
	DOSHeader[24] = "DOS_RelocOffset";
	DOSHeader[26] = "DOS_Overlay";
	DOSHeader[28] = "DOS_Reserved1";
	DOSHeader[30] = "DOS_Reserved1";
	DOSHeader[32] = "DOS_Reserved1";
	DOSHeader[34] = "DOS_Reserved1";
	DOSHeader[36] = "DOS_OEM_ID";
	DOSHeader[38] = "DOS_OEM_Info";
	DOSHeader[40] = "DOS_Reserved2";
	DOSHeader[42] = "DOS_Reserved2";
	DOSHeader[44] = "DOS_Reserved2";
	DOSHeader[46] = "DOS_Reserved2";
	DOSHeader[48] = "DOS_Reserved2";
	DOSHeader[50] = "DOS_Reserved2";
	DOSHeader[52] = "DOS_Reserved2";
	DOSHeader[54] = "DOS_Reserved2";
	DOSHeader[56] = "DOS_Reserved2";
	DOSHeader[58] = "DOS_Reserved2";
	DOSHeader[60] = "DOS_PEOffset";

	// PE Header (OllyDbg names)
	PE32Header[0] = "IMAGE_NT_SIGNATURE";
	PE32Header[4] = "Machine";
	PE32Header[6] = "NumberOfSections";
	PE32Header[8] = "TimeDateStamp";
	PE32Header[12] = "PointerToSymbolTable";
	PE32Header[16] = "NumberOfSymbols";
	PE32Header[20] = "SizeOfOptionalHeader";
	PE32Header[22] = "Characteristics";
	PE32Header[24] = "MagicNumber";
	PE32Header[26] = "MajorLinkerVersion";
	PE32Header[27] = "MinorLinkerVersion";
	PE32Header[28] = "SizeOfCode";
	PE32Header[32] = "SizeOfInitializedData";
	PE32Header[36] = "SizeOfUninitializedData";
	PE32Header[40] = "AddressOfEntryPoint";
	PE32Header[44] = "BaseOfCode";
	PE32Header[48] = "BaseOfData";
	PE32Header[52] = "ImageBase";
	PE32Header[56] = "SectionAlignment";
	PE32Header[60] = "FileAlignment";
	PE32Header[64] = "MajorOSVersion";
	PE32Header[66] = "MinorOSVersion";
	PE32Header[68] = "MajorImageVersion";
	PE32Header[70] = "MinorImageVersion";
	PE32Header[72] = "MajorSubsystemVersion";
	PE32Header[74] = "MinorSubsystemVersion";
	PE32Header[76] = "Win32VersionValue";
	PE32Header[80] = "SizeOfImage";
	PE32Header[84] = "SizeOfHeaders";
	PE32Header[88] = "CheckSum";
	PE32Header[92] = "Subsystem";
	PE32Header[94] = "DLLCharacteristics";
	PE32Header[96] = "SizeOfStackReserve";
	PE32Header[100] = "SizeOfStackCommit";
	PE32Header[104] = "SizeOfHeapReserve";
	PE32Header[108] = "SizeOfHeapCommit";
	PE32Header[112] = "LoaderFlags";
	PE32Header[116] = "NumberOfRvaAndSizes";
	PE32Header[120] = "Export Table address";
	PE32Header[124] = "Export Table size";
	PE32Header[128] = "Import Table address";
	PE32Header[132] = "Import Table size";
	PE32Header[136] = "Resource Table address";
	PE32Header[140] = "Resource Table size";
	PE32Header[144] = "Exception Table address";
	PE32Header[148] = "Exception Table size";
	PE32Header[152] = "Certificate File pointer";
	PE32Header[156] = "Certificate Table size";
	PE32Header[160] = "Relocation Table address";
	PE32Header[164] = "Relocation Table size";
	PE32Header[168] = "Debug Data address";
	PE32Header[172] = "Debug Data size";
	PE32Header[176] = "Architecture Data address";
	PE32Header[180] = "Architecture Data size";
	PE32Header[184] = "Global Ptr address";
	PE32Header[188] = "Reserved";
	PE32Header[192] = "TLS Table address";
	PE32Header[196] = "TLS Table size";
	PE32Header[200] = "Load Config Table address";
	PE32Header[204] = "Load Config Table size";
	PE32Header[208] = "Bound Import Table address";
	PE32Header[212] = "Bound Import Table size";
	PE32Header[216] = "Import Address Table address";
	PE32Header[220] = "Import Address Table size";
	PE32Header[224] = "Delay Import Descriptor address";
	PE32Header[228] = "Delay Import Descriptor size";
	PE32Header[232] = "COM+ Runtime Header address";
	PE32Header[236] = "Import Address Table size";
	PE32Header[240] = "Reserved";
	PE32Header[244] = "Reserved";

	// PEB (OllyDbg names)
	PEBStruct[0] = "InheritedAddressSpace";
	PEBStruct[1] = "ReadImageFileExecOptions";
	PEBStruct[2] = "BeingDebugged";
	PEBStruct[3] = "SpareBool";
	PEBStruct[4] = "Mutant";
	PEBStruct[8] = "ImageBaseAddress";
	PEBStruct[12] = "LoaderData";
	PEBStruct[16] = "ProcessParameters";
	PEBStruct[20] = "SubSystemData";
	PEBStruct[24] = "ProcessHeap";
	PEBStruct[28] = "FastPebLock";
	PEBStruct[32] = "FastPebLockRoutine";
	PEBStruct[36] = "FastPebUnlockRoutine";
	PEBStruct[40] = "EnvironmentUpdateCount";
	PEBStruct[44] = "KernelCallbackTable";
	PEBStruct[48] = "Reserved";
	PEBStruct[52] = "ThunksOrOptions";
	PEBStruct[56] = "FreeList";
	PEBStruct[60] = "TlsExpansionCounter";
	PEBStruct[64] = "TlsBitmap";
	PEBStruct[68] = "TlsBitmapBits";
	PEBStruct[72] = "TlsBitmapBits";
	PEBStruct[76] = "ReadOnlySharedMemoryBase";
	PEBStruct[80] = "ReadOnlySharedMemoryHeap";
	PEBStruct[84] = "ReadOnlyStaticServerData";
	PEBStruct[88] = "AnsiCodePageData";
	PEBStruct[92] = "OemCodePageData";
	PEBStruct[96] = "UnicodeCaseTableData";
	PEBStruct[100] = "NumberOfProcessors";
	PEBStruct[104] = "NtGlobalFlag";
	PEBStruct[108] = "Reserved";
	PEBStruct[112] = "CriticalSectionTimeout_Lo";
	PEBStruct[116] = "CriticalSectionTimeout_Hi";
	PEBStruct[120] = "HeapSegmentReserve";
	PEBStruct[124] = "HeapSegmentCommit";
	PEBStruct[128] = "HeapDeCommitTotalFreeThreshold";
	PEBStruct[132] = "HeapDeCommitFreeBlockThreshold";
	PEBStruct[136] = "NumberOfHeaps";
	PEBStruct[140] = "MaximumNumberOfHeaps";
	PEBStruct[144] = "ProcessHeaps";
	PEBStruct[148] = "GdiSharedHandleTable";
	PEBStruct[152] = "ProcessStarterHelper";
	PEBStruct[156] = "GdiDCAttributeList";
	PEBStruct[160] = "LoaderLock";
	PEBStruct[164] = "OSMajorVersion";
	PEBStruct[168] = "OSMinorVersion";
	PEBStruct[172] = "OSBuildNumber";
	PEBStruct[173] = "OSCSDVersion";
	PEBStruct[175] = "OSPlatformId";
	PEBStruct[179] = "ImageSubsystem";
	PEBStruct[183] = "ImageSubsystemMajorVersion";
	PEBStruct[187] = "ImageSubsystemMinorVersion";
	PEBStruct[191] = "ImageProcessAffinityMask";
	PEBStruct[195] = "GdiHandleBuffer";
	PEBStruct[199] = "GdiHandleBuffer";
	PEBStruct[203] = "GdiHandleBuffer";
	PEBStruct[207] = "GdiHandleBuffer";
	PEBStruct[211] = "GdiHandleBuffer";
	PEBStruct[215] = "GdiHandleBuffer";
	PEBStruct[219] = "GdiHandleBuffer";
	PEBStruct[223] = "GdiHandleBuffer";
	PEBStruct[227] = "GdiHandleBuffer";
	PEBStruct[231] = "GdiHandleBuffer";
	PEBStruct[235] = "GdiHandleBuffer";
	PEBStruct[239] = "GdiHandleBuffer";
	PEBStruct[243] = "GdiHandleBuffer";
	PEBStruct[247] = "GdiHandleBuffer";
	PEBStruct[251] = "GdiHandleBuffer";
	PEBStruct[255] = "GdiHandleBuffer";
	PEBStruct[259] = "GdiHandleBuffer";
	PEBStruct[263] = "GdiHandleBuffer";
	PEBStruct[267] = "GdiHandleBuffer";
	PEBStruct[271] = "GdiHandleBuffer";
	PEBStruct[275] = "GdiHandleBuffer";
	PEBStruct[279] = "GdiHandleBuffer";
	PEBStruct[283] = "GdiHandleBuffer";
	PEBStruct[287] = "GdiHandleBuffer";
	PEBStruct[291] = "GdiHandleBuffer";
	PEBStruct[295] = "GdiHandleBuffer";
	PEBStruct[299] = "GdiHandleBuffer";
	PEBStruct[303] = "GdiHandleBuffer";
	PEBStruct[307] = "GdiHandleBuffer";
	PEBStruct[311] = "GdiHandleBuffer";
	PEBStruct[315] = "GdiHandleBuffer";
	PEBStruct[319] = "GdiHandleBuffer";
	PEBStruct[323] = "GdiHandleBuffer";
	PEBStruct[327] = "GdiHandleBuffer";
	PEBStruct[331] = "PostProcessInitRoutine";
	PEBStruct[335] = "TlsExpansionBitmap";
	PEBStruct[339] = "TlsExpansionBitmapBits";
	PEBStruct[343] = "TlsExpansionBitmapBits";
	PEBStruct[347] = "TlsExpansionBitmapBits";
	PEBStruct[351] = "TlsExpansionBitmapBits";
	PEBStruct[355] = "TlsExpansionBitmapBits";
	PEBStruct[359] = "TlsExpansionBitmapBits";
	PEBStruct[363] = "TlsExpansionBitmapBits";
	PEBStruct[367] = "TlsExpansionBitmapBits";
	PEBStruct[371] = "TlsExpansionBitmapBits";
	PEBStruct[375] = "TlsExpansionBitmapBits";
	PEBStruct[379] = "TlsExpansionBitmapBits";
	PEBStruct[383] = "TlsExpansionBitmapBits";
	PEBStruct[387] = "TlsExpansionBitmapBits";
	PEBStruct[391] = "TlsExpansionBitmapBits";
	PEBStruct[395] = "TlsExpansionBitmapBits";
	PEBStruct[399] = "TlsExpansionBitmapBits";
	PEBStruct[403] = "TlsExpansionBitmapBits";
	PEBStruct[407] = "TlsExpansionBitmapBits";
	PEBStruct[411] = "TlsExpansionBitmapBits";
	PEBStruct[415] = "TlsExpansionBitmapBits";
	PEBStruct[419] = "TlsExpansionBitmapBits";
	PEBStruct[423] = "TlsExpansionBitmapBits";
	PEBStruct[427] = "TlsExpansionBitmapBits";
	PEBStruct[431] = "TlsExpansionBitmapBits";
	PEBStruct[435] = "TlsExpansionBitmapBits";
	PEBStruct[439] = "TlsExpansionBitmapBits";
	PEBStruct[443] = "TlsExpansionBitmapBits";
	PEBStruct[447] = "TlsExpansionBitmapBits";
	PEBStruct[451] = "TlsExpansionBitmapBits";
	PEBStruct[455] = "TlsExpansionBitmapBits";
	PEBStruct[459] = "TlsExpansionBitmapBits";
	PEBStruct[463] = "TlsExpansionBitmapBits";
	PEBStruct[467] = "SessionId";
	PEBStruct[471] = "AppCompatFlags_Lo";
	PEBStruct[475] = "AppCompatFlags_Hi";
	PEBStruct[479] = "AppCompatFlagsUser_Lo";
	PEBStruct[483] = "AppCompatFlagsUser_Hi";
	PEBStruct[487] = "pShimData";
	PEBStruct[491] = "pAppCompatInfo";
	PEBStruct[495] = "CSDVersion_Length";
	PEBStruct[497] = "CSDVersion_MaximumLength";
	PEBStruct[499] = "CSDVersio";
	PEBStruct[503] = "pActivationContextData";
	PEBStruct[507] = "pProcessAssemblyStorageMap";
	PEBStruct[511] = "pSysDefActivationContextData";
	PEBStruct[515] = "pSystemAssemblyStorageMap";
	PEBStruct[519] = "MinimumStackCommit";
	PEBStruct[523] = "FlsCallback";
	PEBStruct[527] = "FlsListHead_Flink";
	PEBStruct[531] = "FlsListHead_Blink";
	PEBStruct[535] = "FlsBitmap";
	PEBStruct[539] = "FlsBitmapBits";
	PEBStruct[543] = "FlsBitmapBits";
	PEBStruct[547] = "FlsBitmapBits";
	PEBStruct[551] = "FlsBitmapBits";
	PEBStruct[555] = "FlsHighIndex";

	// TEB (OllyDbg names)
	TEBStruct[0] = "SEH chain";
	TEBStruct[4] = "Thread's stack base";
	TEBStruct[8] = "Thread's stack limit";
	TEBStruct[12] = "TIB of OS/2 Subsystem";
	TEBStruct[16] = "Fiber data";
	TEBStruct[20] = "Arbitrary user data";
	TEBStruct[24] = "TIB linear address";
	TEBStruct[28] = "Environment pointer";
	TEBStruct[32] = "Process ID";
	TEBStruct[36] = "Thread ID";
	TEBStruct[40] = "RPC handle";
	TEBStruct[44] = "TLS array";
	TEBStruct[48] = "Process database";
	TEBStruct[52] = "Thread's last error";
	TEBStruct[56] = "Number of critical sections";
	TEBStruct[60] = "CSR client thread";
	TEBStruct[64] = "Thread information";
	TEBStruct[68] = "Client information";
	TEBStruct[72] = "Client information";
	TEBStruct[76] = "Client information";
	TEBStruct[80] = "Client information";
	TEBStruct[84] = "Client information";
	TEBStruct[88] = "Client information";
	TEBStruct[92] = "Client information";
	TEBStruct[96] = "Client information";
	TEBStruct[100] = "Client information";
	TEBStruct[104] = "Client information";
	TEBStruct[108] = "Client information";
	TEBStruct[112] = "Client information";
	TEBStruct[116] = "Client information";
	TEBStruct[120] = "Client information";
	TEBStruct[124] = "Client information";
	TEBStruct[128] = "Client information";
	TEBStruct[132] = "Client information";
	TEBStruct[136] = "Client information";
	TEBStruct[140] = "Client information";
	TEBStruct[144] = "Client information";
	TEBStruct[148] = "Client information";
	TEBStruct[152] = "Client information";
	TEBStruct[156] = "Client information";
	TEBStruct[160] = "Client information";
	TEBStruct[164] = "Client information";
	TEBStruct[168] = "Client information";
	TEBStruct[172] = "Client information";
	TEBStruct[176] = "Client information";
	TEBStruct[180] = "Client information";
	TEBStruct[184] = "Client information";
	TEBStruct[188] = "Client information";
	TEBStruct[192] = "Wow32 reserved";
	TEBStruct[196] = "Current locale";
	TEBStruct[200] = "FP status register";
	TEBStruct[204] = "OS reserved";
	TEBStruct[208] = "OS reserved";
	TEBStruct[212] = "OS reserved";
	TEBStruct[216] = "OS reserved";
	TEBStruct[220] = "OS reserved";
	TEBStruct[224] = "OS reserved";
	TEBStruct[228] = "OS reserved";
	TEBStruct[232] = "OS reserved";
	TEBStruct[236] = "OS reserved";
	TEBStruct[240] = "OS reserved";
	TEBStruct[244] = "OS reserved";
	TEBStruct[248] = "OS reserved";
	TEBStruct[252] = "OS reserved";
	TEBStruct[256] = "OS reserved";
	TEBStruct[260] = "OS reserved";
	TEBStruct[264] = "OS reserved";
	TEBStruct[268] = "OS reserved";
	TEBStruct[272] = "OS reserved";
	TEBStruct[276] = "OS reserved";
	TEBStruct[280] = "OS reserved";
	TEBStruct[284] = "OS reserved";
	TEBStruct[288] = "OS reserved";
	TEBStruct[292] = "Pointer to ETHREAD";
	TEBStruct[296] = "OS reserved";
	TEBStruct[300] = "OS reserved";
	TEBStruct[304] = "OS reserved";
	TEBStruct[308] = "OS reserved";
	TEBStruct[312] = "OS reserved";
	TEBStruct[316] = "OS reserved";
	TEBStruct[320] = "OS reserved";
	TEBStruct[324] = "OS reserved";
	TEBStruct[328] = "OS reserved";
	TEBStruct[332] = "OS reserved";
	TEBStruct[336] = "OS reserved";
	TEBStruct[340] = "OS reserved";
	TEBStruct[344] = "OS reserved";
	TEBStruct[348] = "OS reserved";
	TEBStruct[352] = "OS reserved";
	TEBStruct[356] = "OS reserved";
	TEBStruct[360] = "OS reserved";
	TEBStruct[364] = "OS reserved";
	TEBStruct[368] = "OS reserved";
	TEBStruct[372] = "OS reserved";
	TEBStruct[376] = "OS reserved";
	TEBStruct[380] = "OS reserved";
	TEBStruct[384] = "OS reserved";
	TEBStruct[388] = "OS reserved";
	TEBStruct[392] = "OS reserved";
	TEBStruct[396] = "OS reserved";
	TEBStruct[400] = "OS reserved";
	TEBStruct[404] = "OS reserved";
	TEBStruct[408] = "OS reserved";
	TEBStruct[412] = "OS reserved";
	TEBStruct[416] = "OS reserved";
	TEBStruct[420] = "Exception code";

}