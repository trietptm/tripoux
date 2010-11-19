int NO_LOOPS = 0;
int NO_WAVES = 0;
int NO_APICALLS = 0;
int NO_EXCEPTIONS = 0;
int NO_SYSTEMACCESS = 0;
int NO_FAKEBR = 0;

#define INSTRUCTIONS_LOAD 100000 // number of instructions analyzed in a row

class waveDynamicCode
{
	public:
		map<int,string> machineCode; // executed address -> machine code
		int startTime;
		int exitTime; // 0 for the last wave
		int id;
		
};

waveDynamicCode* currentWave;
void dumpCurrentWave();

// We only need these information atm (flags are missing)
typedef struct staticX86Instruction{
	int instructionLength;
	short typeS; // not full, missing API calls and exceptions detection that are done dynamically
	string binaryCode;
} staticX86Instruction;

map<int,staticX86Instruction> staticInformation;

class dynamicX86Instruction{
	
	public:
		int time;
		int address;
		int hash;
		int memReadAddress; // forgot the registers ATM
		int memReadSize;
		int memWriteAddress;
		int memWriteSize;
		int typeD;
		string comments;

		// WARNING ! We consider two dynamic instructions equal even if their time is different!
		bool operator==(dynamicX86Instruction arg1) const{
			return((this->address == arg1.address) && (this->hash == arg1.hash));
		}

		bool operator!=(dynamicX86Instruction arg1) const{
			return((this->address != arg1.address) || (this->hash != arg1.hash));
		}

			
		bool operator<(dynamicX86Instruction arg1) const{
			return(this->address < arg1.address);
		}

		bool operator>(dynamicX86Instruction arg1) const{
			return(this->address > arg1.address);
		}
};



void initWinStructures();

class addressInterval32b{

	public:

		int startAddress; 
		int endAddress;

		addressInterval32b(){}

		addressInterval32b(int start, int end){
			if(start<=end)
			{
				this->startAddress = start;
				this->endAddress = end;
			}
		}

		addressInterval32b(const addressInterval32b& arg1):startAddress(arg1.startAddress),endAddress(arg1.endAddress){
		}
		
		~addressInterval32b() { }

		bool operator==(addressInterval32b arg1) const{
			return((this->startAddress == arg1.startAddress) && (this->endAddress == arg1.endAddress));
		}

			
		bool operator<(addressInterval32b arg1) const{
			return(this->startAddress < arg1.startAddress);
		}

		bool operator>(addressInterval32b arg1) const{
			return(this->startAddress > arg1.startAddress);
		}

		bool intersect(addressInterval32b arg1)
		{
			if((this->startAddress <= arg1.startAddress) && (this->endAddress >= arg1.startAddress))
				return true;
			if((this->endAddress >= arg1.endAddress) && (arg1.endAddress >= this->startAddress))
				return true;
			if(this->endAddress == arg1.startAddress - 1)
				return true;
			if(arg1.endAddress == this->startAddress - 1)
				return true;
			return false;
		}

		bool isInside(int testAddress){
			return((testAddress <= this->endAddress)&&(testAddress >= this->startAddress));
		}

		addressInterval32b fusion(addressInterval32b arg1)
		{
			int newStart, newEnd;
			newStart = min(arg1.startAddress,this->startAddress);
			newEnd = max(arg1.endAddress, this->endAddress);
			return addressInterval32b(newStart,newEnd);
		}
};

// Loop detection
list<dynamicX86Instruction> cacheL; // Two versions of the cache, one for access, one for iteration
set<dynamicX86Instruction> cacheS;
#define CACHE_DEPTH 1000

class loopExtremity
{
	public:

		int address;
		int hash; // address is not enough to identify an instruction (self-modifying code!)

		loopExtremity(){}	

		loopExtremity(int address, int hash):
		address(address),hash(hash)
		{}

		loopExtremity(const loopExtremity& arg1){
			address = arg1.address;
			hash = arg1.hash;
		}

		void operator=(loopExtremity arg1){
			this->address = arg1.address;
			this->hash = arg1.hash;
		}

		bool operator==(loopExtremity arg1) const{
			return ((this->address == arg1.address)&&
				(this->hash == arg1.hash));
		}

		bool operator<(loopExtremity arg1) const{
			return ((this->address < arg1.address));
		}

		bool operator>(loopExtremity arg1) const{
			return (this->address > arg1.address);
		}
};

class Loop
{
	public:

		int id;
		loopExtremity head;
		loopExtremity tail;
		int entryTime;
		int endTime;
		bool valid;
		bool closed;
		int turn;
		vector<addressInterval32b> readAddresses;
		vector<addressInterval32b> writeAddresses;
		map<int,vector<int>> staticProfile; // static instruction address -> [read @ or 0, write @ or 0]
		set<int> dynamicProfile; // dynamic instruction addresses

	Loop(){}

};

map<loopExtremity,int> tailToNCLoop; // one tail can correspond to one non-closed loop maximum
map<loopExtremity,set<loopExtremity>> headToVTails; // store the valid tails for a head
map<int, Loop> loopsMap; // ID to loop
int loopID = 0;

// Memory fingerprint
class dynamicModule
{
	public:
	string name;
	string type;
	addressInterval32b interval;

};

vector<dynamicModule> memModules;
int gateToMemModules = 0x7FFFFFFF;

// PE header is composed by a DOS Header and a PE32 Header
map<int,string> DOSHeader;
map<int,string> PE32Header;
map<int,string>	PEBStruct;
map<int,string>	TEBStruct;

#define DOS_HEADER_SIZE 64
#define PE32_HEADER_SIZE 248
#define PEB_SIZE 559
#define TEB_SIZE 424

// Waves
set<int> currentWriteSet;
int lastBranch = 0;

// Fake branch : only true in one wave
void dumpFakeBR();
map<int,int> fakeBr; // @br <-> @follower
set<int> trueBr; // @br
int checkFollowerBr = 0;
int insertFollowerBr = 0;

int debugMode = 0;