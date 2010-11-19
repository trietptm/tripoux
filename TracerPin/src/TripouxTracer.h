// ** Architecture specific ** //

#define ADDRESS_LENGTH 4 // in bytes

// ** Information that are fixed when we execute several times the same instruction with same machine state ** //
class staticX86Instruction{

	public:

	char instructionLength;
	short instructionType; // not full, missing API calls and exceptions detection that are done dynamically
	int writtenFlags;
	int readFlags;
	int encodingInstruction[16]; // could be better

	staticX86Instruction(){
		this->instructionLength = '0';
		this->instructionType = (short)0;
		this->writtenFlags = 0;
		this->readFlags = 0;
		for(int i = 0; i<16 ; i++)
			this->encodingInstruction[i] = 0;
	}
	
};

void dumpStaticX86Instruction(staticX86Instruction myInstruction);
void dumpRegister(int registerDef);
int hashStaticX86Instruction(staticX86Instruction myInstruction);
int addRegister(int registerDef, string registerName);

// ** API dumps, cf. associated prototypes file ** //
VOID printAPIWorld();
int displayArg(int argType, int num, ADDRINT argPointer, int first);
VOID dumpOutArgs(ADDRINT esp, ADDRINT eax, int Arg0Type, int Arg1Num, int Arg1Type, int Arg2Num, int Arg2Type, int Arg3Num, int Arg3Type, int Arg4Num, int Arg4Type);

int argAPITypes[5][2] = {{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1}}; // (num arg, type arg)
int dumpToDo = 0;
ADDRINT savEsp;

map<string, int> typeIntMap; // "CHAR" -> 0 ...
map<int,string> typeReverseIntMap; // 0 -> "CHAR" ...
map<int, vector<int>> basicTypeMap; // 0 -> [[0,1]] ..., means "CHAR" is type D1 (= 0,1), direct dump 1 byte.
map<int, vector<int>> complexTypeMap;
map<string, vector<vector<int>>> protoMap;  // "LoadLibrary" -> [[0,4][1,18]], where typeReverseIntMap[4] = "HMODULE" (return value type) and IN TYPE

map<int, string> staticFunctions;
