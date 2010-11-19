/*BEGIN_LEGAL Intel
Intel Open Source License 

Copyright (c) 2002-2009 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */

/*

Tripoux project - Joan Calvet - j04n.calvet@gmail.com
Version : v0.1

This is the Pin tracer of the project (only suitable for x86-32bits processor and Windows binaries)

TODO-LIST:
1- Hash everything into a static instruction
2- Rewrite the API display code

*/

#include "pin.H"
extern "C" {
#include "xed-interface.h"
}

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

#include "TripouxTracer.h"
using namespace std;


/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */
int timeInstruction=0;
set<int> hashesStaticInstruction;
int pause=0;
int nextAddress=0;

int start = 1;
int startAddress = 0; // overload by "-s" parameter

int gateToAPIworld = 0x7FFFFFFF; // maximum @ in userland

std::ofstream* dynamicTr = 0;
std::ofstream* staticInstructions = 0;
std::ofstream* memoryFingerprint = 0;
std::ofstream* tripouxLog = 0;

/* ===================================================================== */
/* Code */
/* ===================================================================== */

/* ===================================================================== */
/* 1. Pin specific functions */
/* ===================================================================== */

/*! analysisFunction
 *  Called one time for each effect of one instruction : e.g. if an instruction reads the memory and writes EAX, it will be called two times
 *
 * @param[in]   pc			program counter
 * @param[in]   myHash		hash of the corresponding "static" instruction
 * @param[in]   mode		=0 if first call for this instruction, elsewhere 1
 * @param[in]   type		distinction between r/w memory, r/w registers, call or "simple" instruction
 * @param[in]   eax			value of the EAX register (usefull to dump API return values)
 * @param[in]   addr		effect address (if the instruction writes the memory @4010FF, then addr = 0x4010FF)
 * @param[in]	size		size of the effect, in bytes
 * @param[in]	esp			value of the ESP register (usefull to dump args)
 *
 * Some of these arguments are overloaded for some specific instrumentations, cf. instrumentation function.
 * This is bad programmation method but it's done for performance reason: Pin analysis functions have to limit their parameters number to be efficient.
 */
VOID analysisFunction(ADDRINT pc, int myHash, int mode, int type, ADDRINT eax, ADDRINT addr, int size, ADDRINT esp) 
{

		if(dumpToDo != 0)
		{	
			dumpOutArgs(savEsp, eax, argAPITypes[0][1],argAPITypes[1][0],argAPITypes[1][1],argAPITypes[2][0],argAPITypes[2][1],argAPITypes[3][0],argAPITypes[3][1],argAPITypes[4][0],argAPITypes[4][1]);
			
			dumpToDo = 0;
			argAPITypes[0][0] = -1;
			argAPITypes[0][1] = -1;
			argAPITypes[1][0] = -1;
			argAPITypes[1][1] = -1;
			argAPITypes[2][0] = -1;
			argAPITypes[2][1] = -1;
			argAPITypes[3][0] = -1;
			argAPITypes[3][1] = -1;
			argAPITypes[4][0] = -1;
			argAPITypes[4][1] = -1;

			*dynamicTr << endl;
		}

		// Check if paused
		if((pause == 1)&&((int)pc == nextAddress))
			pause=0;
		if(pause)
			return;

		/** DYNAMIC INFORMATION (not collected if it's a call)**/
		if((type!=5) && (mode==0))
		{
			// Time 
			*dynamicTr << hex << timeInstruction << "!";
			timeInstruction++;

			// Address
			*dynamicTr <<hex << pc << "!";
				
			// Hash (link to the static information)
			*dynamicTr << hex << myHash << "!";
		}

		string nameAPI = RTN_FindNameByAddress(addr);
		switch(type)
		{
			case 0:
				*dynamicTr << endl;
				break;
			case 1: // Read memory
				*dynamicTr << "RM_" << hex << addr << "_" << size << endl;
				break;
			case 2: // Write memory
				*dynamicTr << "WM_" << hex << addr << "_" << size << endl;
				break;
			case 3: // Read register
				*dynamicTr << "RR";
				dumpRegister(size);
				*dynamicTr << endl;
				break;
			case 4: // Write register
				*dynamicTr << "WR";
				dumpRegister(size);
				*dynamicTr << endl;
				break;
			case 5: 
				if  ((((nameAPI == ".text") || (nameAPI == "unnamedImageEntryPoint")) && (!staticFunctions[int(addr)].empty())) || // Static API call
					((nameAPI != ".text") && (!nameAPI.empty()) && (nameAPI != "unnamedImageEntryPoint"))) // Dynamic API call
				{
					if(((nameAPI == ".text") || (nameAPI == "unnamedImageEntryPoint")) && (!staticFunctions[int(addr)].empty()))
					{
						nameAPI = staticFunctions[int(addr)];
						*dynamicTr << "[callAPI][S_" << nameAPI << "]";
						pause = 1;
						nextAddress = (int) pc + size;
					}
					else
						*dynamicTr << "[callAPI][D_" << nameAPI << "]";


					// Do we know the prototype for this function ?
					if (protoMap.find(nameAPI) != protoMap.end())
					{
						vector<vector<int>>::iterator itOnVector;
						int count = 0;
						int nbArg = 0;

						savEsp = esp;
						
						for ( itOnVector = protoMap.find(nameAPI)->second.begin() ; 
							itOnVector != protoMap.find(nameAPI)->second.end() ; 
							itOnVector++)
						{
							if(((*itOnVector)[0] == 1) || ((*itOnVector)[0] == 2)) // OUT or IN_OUT args
							{
								dumpToDo = 1;
								argAPITypes[count][0] = nbArg;
								argAPITypes[count][1] = (*itOnVector)[1];
								count++;
							}
							if(((*itOnVector)[0] == 0) || ((*itOnVector)[0] == 2)) // IN or IN_OUT args
								displayArg((*itOnVector)[1],nbArg,esp+(nbArg-1)*ADDRESS_LENGTH,1);


							nbArg++;
							if (count == 4)
								break;	
						}
					}
					else
						*dynamicTr << endl;
				}
			default:
				break;
		}

		
}


/*! instrumentationFunction
 * @param[in]   ins				instruction to instrument
 * @param[in]   v				? (Pin magic)
 * @rv
 */
VOID instrumentationFunction(INS ins, VOID *v)
{

    static const xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b}; // 32 bits !

    xed_decoded_inst_t xedd; 
    xed_decoded_inst_zero_set_mode(&xedd,&dstate);

	// Address
	ADDRINT pc = INS_Address(ins);

	// Check if paused
	if((pause == 1)&&((int)pc == nextAddress))
		pause=0;
	if(pause)
		return;

	// Start the tracing at the.. start address
	if(!start && ((int)pc == startAddress))
		start = 1;
	if(!start)
		return;
	
	// Don't follow the API code!
	if((int)pc > gateToAPIworld) 
		return;

	// Xed decoding
    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(pc), 15);
    BOOL xed_ok = (xed_code == XED_ERROR_NONE);


    if (xed_ok) {	

		/** STATIC INFORMATION **/

		staticX86Instruction newInstruction;

		// Instruction encoding
		char buff[16];
		memset(buff,'\x0',16);
		
		xed_encoder_request_init_from_decode(&xedd);
		
		unsigned int olen;
		xed_encode(&xedd,(unsigned char *)buff,16,&olen);
	
		// Convert the binary code into int to display it as a nice string, for easy parsing after (mixing binary and ascii code sucks)
		for(unsigned int i = 0; i<olen; i++)
			newInstruction.encodingInstruction[i] = 0x000000FF & int(buff[i]);

		for(int i = olen; i<16; i++)
			newInstruction.encodingInstruction[i] = 0x00;

		// Length
		newInstruction.instructionLength = (char) olen;

		// Instruction type

		// b0...b15
		newInstruction.instructionType = 0x0;

		const char * category = xed_category_enum_t2str(xed_decoded_inst_get_category(&xedd));

		// Check JMP*
		if(strcmp(category,"COND_BR")==0)
		{
			// Branch : b0 = 1
			newInstruction.instructionType |= 0x8000;

			// Conditionnal : b1 = 1
			newInstruction.instructionType |= 0x4000;

			// Direct or indirect ?
			const xed_inst_t* xi = xed_decoded_inst_inst(&xedd);
			const xed_operand_t* op = xed_inst_operand(xi,0);
			xed_operand_enum_t op_name = xed_operand_name(op);

			if(op_name == XED_OPERAND_RELBR) // Direct operand
				newInstruction.instructionType |= 0x2000;
		
		}
		else if(strcmp(category,"UNCOND_BR")==0) // jmp only
		{
			// Branch : b0 = 1
			newInstruction.instructionType |= 0x8000;
			
			// Direct or indirect ?
			const xed_inst_t* xi = xed_decoded_inst_inst(&xedd);
			const xed_operand_t* op = xed_inst_operand(xi,0);
			xed_operand_enum_t op_name = xed_operand_name(op);

			if(op_name == XED_OPERAND_RELBR) // Direct operand
				newInstruction.instructionType |= 0x2000;
	
		}
		// Check CALL
		else if(strcmp(category,"CALL")==0)
		{
			// Branch : b0 = 1
			newInstruction.instructionType |= 0x8000;

			// Direct or indirect ?
			const xed_inst_t* xi = xed_decoded_inst_inst(&xedd);
			const xed_operand_t* op = xed_inst_operand(xi,0);
			xed_operand_enum_t op_name = xed_operand_name(op);
			
			if(op_name == XED_OPERAND_RELBR) // Direct operand
				newInstruction.instructionType |= 0x2000;

			// Call : b3 = 1
			newInstruction.instructionType |= 0x1000;

			// Stack-related : b10 = 1
			newInstruction.instructionType |= 0x0020;
		
		} else if(strcmp(category,"RET")==0)
		{
			// Branch : b0 = 1
			newInstruction.instructionType |= 0x8000;

			// Return : b4 = 1
			newInstruction.instructionType |= 0x0800;

			// Stack-related : b10 = 1
			newInstruction.instructionType |= 0x0020;		
		}

		// Check POP
		if(strcmp(category,"POP")==0)
		{
			// Pop : b9 = 1
			newInstruction.instructionType |= 0x0040;

			// Stack-related : b10 = 1
			newInstruction.instructionType |= 0x0020;			
		}
		else if(strcmp(category,"PUSH")==0)
		{
			// Push : b9 = 1
			newInstruction.instructionType |= 0x0080;

			// Stack-related : b10 = 1
			newInstruction.instructionType |= 0x0020;
		}
	
		newInstruction.readFlags = 0x0;
		newInstruction.writtenFlags = 0x0;

		if (xed_decoded_inst_uses_rflags(&xedd)) 
		{
			const xed_simple_flag_t* rfi = xed_decoded_inst_get_rflags_info(&xedd);
			if (xed_simple_flag_reads_flags(rfi)) 
			{
				const xed_flag_set_t* read_set = xed_simple_flag_get_read_flag_set(rfi);
				newInstruction.readFlags = xed_flag_set_mask(read_set);
			}
			else if (xed_simple_flag_writes_flags(rfi)) 
			{
				const xed_flag_set_t* written_set = xed_simple_flag_get_written_flag_set(rfi);
				newInstruction.writtenFlags = xed_flag_set_mask(written_set);
			}
		}
    

		int myHash = hashStaticX86Instruction(newInstruction);

		// Have we already seen this instruction ?
		if(hashesStaticInstruction.find(myHash) == hashesStaticInstruction.end())
		{
			// If it's not the case, store it into the static information file
			*staticInstructions << hex << myHash << "!";
			dumpStaticX86Instruction(newInstruction);
			*staticInstructions << endl;

			hashesStaticInstruction.insert(myHash);
		}

		// A simple instruction doesn't read/write memory
		int isSimpleInstr = 1;

		// An instruction is instrumented one time for each effect : mem read, mem write, reg read, reg write

		// Memory reads
		if (INS_IsMemoryRead(ins)) // Deal also with the natural reads (POP & RET on the stack)
		{
			isSimpleInstr = 0;
			INS_InsertPredicatedCall(
						ins, IPOINT_BEFORE,(AFUNPTR)analysisFunction,
						IARG_INST_PTR,
						IARG_UINT32,
						myHash,
						IARG_UINT32,
						0,
						IARG_UINT32,
						1,
						IARG_REG_VALUE,REG_EAX,
						IARG_MEMORYREAD_EA,
						IARG_UINT32,INS_MemoryReadSize(ins), // miss the value actually read
						IARG_END);

			if(INS_HasMemoryRead2(ins)) // e.g. "CMPS" instruction
				INS_InsertPredicatedCall(
						ins, IPOINT_BEFORE,(AFUNPTR)analysisFunction,
						IARG_INST_PTR,
						IARG_UINT32,
						myHash,
						IARG_UINT32,
						0,
						IARG_UINT32,
						1,
						IARG_REG_VALUE,REG_EAX,
						IARG_MEMORYREAD2_EA,
						IARG_UINT32,INS_MemoryReadSize(ins), // miss the value actually read
						IARG_END);
		}
		
		// Memory writes
		if(INS_IsMemoryWrite(ins)) // Deal with the natural writes (PUSH & CALL on the stack)
		{
			int mode;
			if(isSimpleInstr == 0)
				mode = 1;
			else
			{
				isSimpleInstr = 0;
				mode = 0;
			}
			INS_InsertPredicatedCall(
						ins, IPOINT_BEFORE,(AFUNPTR)analysisFunction,
						IARG_INST_PTR,
						IARG_UINT32,
						myHash,
						IARG_UINT32,
						mode,
						IARG_UINT32,
						2,
						IARG_REG_VALUE,REG_EAX,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32,INS_MemoryWriteSize(ins), // miss the value actually read
						IARG_END);
		}

		int registersRead = 0x0;
		int registersWrite = 0x0;

		// Register reads
		REG readReg = INS_RegR(ins,0);
		if(REG_valid(readReg))
		{
			int k = 0;
			while (REG_valid(readReg))
			{
				registersRead=addRegister(registersRead,REG_StringShort(readReg));
				k=k+1;
				readReg = INS_RegR(ins,k);
			}

			if(registersRead != 0x0) // We only deal with GPRs + ebp/esp
			{
				int mode;
				if(isSimpleInstr == 0)
					mode = 1;
				else
				{
					isSimpleInstr = 0;
					mode = 0;
				}
				INS_InsertPredicatedCall(
						ins, IPOINT_BEFORE,(AFUNPTR)analysisFunction,
						IARG_INST_PTR,
						IARG_UINT32,
						myHash,
						IARG_UINT32,
						mode,
						IARG_UINT32,
						3,
						IARG_REG_VALUE,REG_EAX,
						IARG_ADDRINT,
						(ADDRINT) 0,
						IARG_UINT32,registersRead, // nasty overload to limit the number of parameters
						IARG_END);
			}
		}

		// Register writes
		REG writeReg = INS_RegW(ins,0);
		if(REG_valid(writeReg))
		{
			

			int k = 0;
			while (REG_valid(writeReg))
			{
				registersWrite=addRegister(registersWrite,REG_StringShort(writeReg));
				k=k+1;
				writeReg = INS_RegW(ins,k);
			}

			if(registersWrite!= 0x0) // We only deal with GPRs + ebp/esp
			{
				int mode;
				if(isSimpleInstr == 0)
					mode = 1;
				else
				{
					isSimpleInstr = 0;
					mode = 0;
				}

				INS_InsertPredicatedCall(
						ins, IPOINT_BEFORE,(AFUNPTR)analysisFunction,
						IARG_INST_PTR,
						IARG_UINT32,
						myHash,
						IARG_UINT32,
						mode,
						IARG_UINT32,
						4,
						IARG_REG_VALUE,REG_EAX,
						IARG_ADDRINT,
						(ADDRINT) 0,
						IARG_UINT32,registersWrite, // nasty overload to limit the number of parameters
						IARG_END);
			}
		}
		
		// Call
		if(INS_IsCall(ins))
		{
			int mode;
			if(isSimpleInstr == 0)
				mode = 1;
			else
			{
				isSimpleInstr = 0;
				mode = 0;
			}
			INS_InsertPredicatedCall(
							ins, IPOINT_BEFORE,(AFUNPTR)analysisFunction,
							IARG_INST_PTR,
							IARG_UINT32,
							myHash,
							IARG_UINT32,
							mode,
							IARG_UINT32,
							5,
							IARG_REG_VALUE,REG_EAX,
							IARG_BRANCH_TARGET_ADDR,
							IARG_UINT32,INS_Size(ins), // nasty overload to limit the number of parameters
							IARG_REG_VALUE,REG_ESP,
							IARG_END);
		}

		if(isSimpleInstr)
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)analysisFunction, 
                   IARG_INST_PTR,
				   IARG_UINT32,
					myHash,
				   IARG_UINT32,
					0,
				   IARG_UINT32,
				   0,
				   IARG_REG_VALUE,REG_EAX,
                   IARG_END);
	}
	
}

/*! RecordCallExceptionDispatcher : to detect exceptions, instrument the KiUserExceptionDispatcher()
 * @param[in]   esp			value of the ESP register
 */
VOID RecordCallExceptionDispatcher(ADDRINT esp)
{
	*dynamicTr << "[EXCEPTION]" ;

	int faultAddress, errorCode;
	PIN_SafeCopy(&faultAddress,(void*)(esp+20),4); // win32 specific
	PIN_SafeCopy(&errorCode,(void*)(esp+8),4);
	
	*dynamicTr << "[0x" << hex << errorCode << "]";
	*dynamicTr << "[0x" << hex << faultAddress << "]" << endl;
}


/*! imgInstrumentation : collect the base addresses of the libraries, the PEB and the TEB
 * Also instrument the exception handler of ntdll
 *
 * @param[in]   img			image to instrument
 * @param[in]   val			Pin magic
 */
VOID imgInstrumentation(IMG img, VOID * val)
{
	if(!IMG_IsMainExecutable(img))
	{
		if((int)IMG_LowAddress(img)<gateToAPIworld)
			gateToAPIworld = IMG_LowAddress(img);	

		if(IMG_Name(img).find("ntdll") != string::npos)
		{
			// Detect exception by instrumenting KiUserExceptionDispatcher() (win32 specific!)
			RTN KiUserExceptionRTN = RTN_FindByName(img,"KiUserExceptionDispatcher");
			if(KiUserExceptionRTN != RTN_Invalid())
			{
				RTN_Open(KiUserExceptionRTN);
				RTN_InsertCall(KiUserExceptionRTN,
					IPOINT_BEFORE, (AFUNPTR)RecordCallExceptionDispatcher,
					IARG_REG_VALUE,REG_ESP,
					IARG_END);
				RTN_Close(KiUserExceptionRTN);
			}


			// PEB & TEB addresses
			// Don't dump the actual values ATM

			int PEBaddress = 0;
			int * addressToWrite = &PEBaddress;
			_asm
			{
				push ebx
				push eax
				mov ebx, addressToWrite
				mov eax, FS:[0x30] // win32 specific
				mov [ebx], eax
				pop eax
				pop ebx
			}
			*memoryFingerprint << "PEB PEB " << hex << PEBaddress << endl;
		
			int TEBaddress = 0;
			addressToWrite = &TEBaddress;
			_asm
			{
				push ebx
				push eax
				mov ebx, addressToWrite
				mov eax, FS:[0x18] // win32 specific
				mov [ebx], eax
				pop eax
				pop ebx
			}
			*memoryFingerprint << "TEB TEB " << hex << TEBaddress << endl;

		}

		string moduleName = IMG_Name(img).substr(IMG_Name(img).find_last_of("\\")+1);
		*memoryFingerprint << "DOSH " << moduleName << " " << hex << IMG_LowAddress(img)<< endl;
		
		int offsetToPEHeader;
		PIN_SafeCopy(&offsetToPEHeader,(void *)(IMG_LowAddress(img)+0x3c),4);
		*memoryFingerprint << "PE32H " << moduleName << " " << hex << IMG_LowAddress(img) + offsetToPEHeader << endl;

	}
}

VOID Fini(INT32 code, VOID *v)
{
    *dynamicTr << endl;
	*staticInstructions << endl;
}

/* ===================================================================== */
/* 2. Miscellaneous functions for instruction analysis */
/* ===================================================================== */

/*! PJWHash
 * Stolen from http://www.partow.net/programming/hashfunctions/
 * Calculate the hash of a string
 * @param[in]   str     string to hash
 * @param[in]	len		length of the string
 * @rv					hash
 */
unsigned int PJWHash(char* str, unsigned int len)
{
   const unsigned int BitsInUnsignedInt = (unsigned int)(sizeof(unsigned int) * 8);
   const unsigned int ThreeQuarters     = (unsigned int)((BitsInUnsignedInt  * 3) / 4);
   const unsigned int OneEighth         = (unsigned int)(BitsInUnsignedInt / 8);
   const unsigned int HighBits          = (unsigned int)(0xFFFFFFFF) << (BitsInUnsignedInt - OneEighth);
   unsigned int hash              = 0;
   unsigned int test              = 0;
   unsigned int i                 = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = (hash << OneEighth) + (*str);

      if((test = hash & HighBits)  != 0)
      {
         hash = (( hash ^ (test >> ThreeQuarters)) & (~HighBits));
      }
   }

   return hash;
}

/*! hashStaticX86Instruction
 * Calculate the hash of the binary code of a "static" x86 instruction
 *
 * !! PROBLEM : There is very bad choice made here : 
 * the x86 instruction can have a different semantic depending on the arguments! Need to hash everything (flags, mem access...)
 *
 * @param[in]   myInstruction   instruction to hash
 * @rv							hash
 */
int hashStaticX86Instruction(staticX86Instruction myInstruction)
{
	char buff[64];
	memset(buff,'\x0',64);

	memcpy(buff,&myInstruction.encodingInstruction,64);

	// Better hash function ?
	return PJWHash(buff,64);
}

/*! dumpStaticX86Instruction
 * @param[in]   myInstruction   instruction to dump
 */
void dumpStaticX86Instruction(staticX86Instruction myInstruction)
{
	*staticInstructions << (int)myInstruction.instructionLength << "!";
	*staticInstructions << hex << myInstruction.instructionType << "!";
	*staticInstructions << myInstruction.readFlags << "!";
	*staticInstructions << myInstruction.writtenFlags << "!";
	for(int i = 0; i<(int)myInstruction.instructionLength; i++)
		*staticInstructions << hex << std::setfill('0') << std::setw(2) << myInstruction.encodingInstruction[i];
}

/*! dumpRegister
 * @param[in]   registerDef   Registers flags
 */
void dumpRegister(int registerDef)
{

	if(registerDef & 0x00000001)
		*dynamicTr << "_eax";
	if(registerDef & 0x00000002)
		*dynamicTr << "_ax";
	if(registerDef & 0x00000004)
		*dynamicTr << "_ah";
	if(registerDef & 0x00000008)
		*dynamicTr << "_al";
	if(registerDef & 0x00000010)
		*dynamicTr << "_ebx";
	if(registerDef & 0x00000020)
		*dynamicTr << "_bx";
	if(registerDef & 0x00000040)
		*dynamicTr << "_bh";
	if(registerDef & 0x00000080)
		*dynamicTr << "_bl";
	if(registerDef & 0x00000100)
		*dynamicTr << "_ecx";
	if(registerDef & 0x00000200)
		*dynamicTr << "_cx";
	if(registerDef & 0x00000400)
		*dynamicTr << "_ch";
	if(registerDef & 0x00000800)
		*dynamicTr << "_cl";
	if(registerDef & 0x00001000)
		*dynamicTr << "_edx";
	if(registerDef & 0x00002000)
		*dynamicTr << "_dx";
	if(registerDef & 0x00004000)
		*dynamicTr << "_dh";
	if(registerDef & 0x00008000)
		*dynamicTr << "_dl";
	if(registerDef & 0x00010000)
		*dynamicTr << "_ebp";
	if(registerDef & 0x00020000)
		*dynamicTr << "_esp";
	if(registerDef & 0x00040000)
		*dynamicTr << "_esi";
	if(registerDef & 0x00080000)
		*dynamicTr << "_edi";
}

/*! addRegister
 * @param[in]   registerDef   register flags
 * @param[in]   registerName  register to add
 * @rv						  new register flags
 */
int addRegister(int registerDef, string registerName)
{
	int newRegisterDef = registerDef;

	if(registerName.compare(string("eax"))==0)
		newRegisterDef |= 0x00000001;
	else if(registerName.compare(string("ax"))==0)
		newRegisterDef |= 0x00000002;
	else if(registerName.compare(string("ah"))==0)
		newRegisterDef |= 0x00000004;
	else if(registerName.compare(string("al"))==0)
		newRegisterDef |= 0x00000008;
	else if(registerName.compare(string("ebx"))==0)
		newRegisterDef |= 0x00000010;
	else if(registerName.compare(string("bx"))==0)
		newRegisterDef |= 0x00000020;
	else if(registerName.compare(string("bh"))==0)
		newRegisterDef |= 0x00000040;
	else if(registerName.compare(string("bl"))==0)
		newRegisterDef |= 0x00000080;
	else if(registerName.compare(string("ecx"))==0)
		newRegisterDef |= 0x00000100;
	else if(registerName.compare(string("cx"))==0)
		newRegisterDef |= 0x00000200;
	else if(registerName.compare(string("ch"))==0)
		newRegisterDef |= 0x00000400;
	else if(registerName.compare(string("cl"))==0)
		newRegisterDef |= 0x00000800;
	else if(registerName.compare(string("edx"))==0)
		newRegisterDef |= 0x00001000;
	else if(registerName.compare(string("dx"))==0)
		newRegisterDef |= 0x00002000;
	else if(registerName.compare(string("dh"))==0)
		newRegisterDef |= 0x00004000;
	else if(registerName.compare(string("dl"))==0)
		newRegisterDef |= 0x00008000;
	else if(registerName.compare(string("ebp"))==0)
		newRegisterDef |= 0x00010000;
	else if(registerName.compare(string("esp"))==0)
		newRegisterDef |= 0x00020000;
	else if(registerName.compare(string("esi"))==0)
		newRegisterDef |= 0x00040000;
	else if(registerName.compare(string("edi"))==0)
		newRegisterDef |= 0x00080000;

	return newRegisterDef;

}


/* ===================================================================== */
/* 3. API functions related code */
/* ===================================================================== */

/*! displayArg
 * !!PROBLEM : The dirtiest code in the world, rewrite this shit.
 *
 * @param[in]   argType		  type of the arg to dump
 * @param[in]   num			  argument number
 * ...				  
 */
int displayArg(int argType, int num, ADDRINT argPointer, int first)
{
		
		map<int, vector<int>>::iterator it1;
		vector<int>::iterator it2;
		vector<int> type;

		char * argDirect = NULL;
		char * argIndirect = NULL ;
		int length, i;
		
		it1 = complexTypeMap.find(argType);
		if (it1 != complexTypeMap.end())
		{
			if(first == 1)
				*dynamicTr << "[A" << num << ":" << typeReverseIntMap[argType];

			if ((it1->second)[0] == 0)
			{
				PIN_SafeCopy((void*)argDirect,(void*)argPointer,ADDRESS_LENGTH);
				if ((argPointer == NULL) || (argDirect == NULL))
				{
					*dynamicTr << " (null)]";
					return 0;
				}
				else
					return displayArg((it1->second)[1], num, (ADDRINT) argDirect,0);
			}
			// complex type
			type = it1->second;
			i = 0;
			for(it2 = type.begin(); it2 != type.end(); it2++)
			{
				length = displayArg((*it2), num, argPointer + i, 0);
				i+= length;
			}
			return i;
		}
		
		it1 = basicTypeMap.find(argType);
		
		switch ((it1->second)[0])
		{
			case 0: // DIRECT MODE
				
				length = (it1->second)[1];
				argDirect = (char *)malloc(length);

				if (num != 0) // arguments
				{
					if (first == 1) // non-complex
						*dynamicTr << "[A" << num << ":";

					PIN_SafeCopy((void*)argDirect,(void*)argPointer,length);
					if (length == 4)
							*dynamicTr << typeReverseIntMap[argType] << " 0x" << hex << *(int*)argPointer << "]";
					else
					{
						if (typeReverseIntMap[argType] != "VOID")
							// Complex types
							*dynamicTr << typeReverseIntMap[argType] << " 0x" << hex << *argDirect << "]";
						else
							*dynamicTr << typeReverseIntMap[argType]<< "]";
					}
				}
				else
				{
					*dynamicTr << "[RV:" << typeReverseIntMap[argType];

					if (typeReverseIntMap[argType] != "VOID")
						*dynamicTr << " 0x" << hex << argPointer << "]";
					else
						*dynamicTr << "]";
				}

				free(argDirect);
				return length;			
				break;
			case 1: // INDIRECT MODE

				length = (it1->second)[1];
				argDirect = (char *)malloc(ADDRESS_LENGTH); // Pointer to arg (assuming 32 bits pointer)
				argIndirect = (char *)malloc(length); // Actual argument

				if (num != 0) // Arguments (no return value)
				{
					PIN_SafeCopy((void*)argDirect,(void*)argPointer,ADDRESS_LENGTH);
					
					if(*(int*)argDirect == 0x0)
					{
						*dynamicTr << "[A" << num << ":" << typeReverseIntMap[argType] << " (null)]";
						return 0;
					}

					PIN_SafeCopy((void*)argIndirect,(void*)argDirect,length); // not implemented yet
					
				}
				// Display begin
				if (num != 0)
				{
					if(first == 1)
					{
						if(length == 4)
							*dynamicTr << "[A" << num << ":" << typeReverseIntMap[argType] << " 0x" << hex << *argDirect << "]";
						else
							*dynamicTr << "[A" << num << ":" << typeReverseIntMap[argType] << "NotImplemented 0x" << hex << *argDirect << "]";
					}
					else
					{
						if(length == 4)
							*dynamicTr << "[A" << num << ":" << typeReverseIntMap[argType] << " 0x" << hex << *argDirect << "]";
						else
							*dynamicTr << "[A" << num << ":" << typeReverseIntMap[argType] << "NotImplemented 0x" << hex << *argDirect << "]";
					}
				}
				else
						*dynamicTr << "[RV:" << typeReverseIntMap[argType] << " 0x" << hex << argPointer << "]";
				free(argDirect);
				free(argIndirect);
				return 4;
				break;
			case 2: // STRING MODE
				
				if (num != 0) 
					// Arguments
					PIN_SafeCopy((void*)&argDirect,(void*)argPointer,ADDRESS_LENGTH);
				else	
					// Return Value in EAX
					PIN_SafeCopy((void*)&argDirect,(void*)&argPointer,ADDRESS_LENGTH);

				if(argDirect == 0x0)
				{
					if(num != 0)
						*dynamicTr << "[A" << num << ":" << typeReverseIntMap[argType] << " (null)]";
					else
						*dynamicTr << "[RV:" << typeReverseIntMap[argType] << " (null)]";

					return 0;
				}

				// In some Win32 API functions, a string can actually be an ordinal... (GetProcAddress())
				// We detect this by checking the high-order bytes
				if(((int)argDirect & 0xFFFF0000) == 0x0)
				{
					*dynamicTr << "[A" << num << ":" << typeReverseIntMap[argType] << " 0x" << hex << (int)argDirect << "]";
					return 4;
				}

				// Display begin
				length = (it1->second)[1];
				if (length == 0) //ANSI MODE
				{
					if (num != 0)
					{
						if (first == 1)
							*dynamicTr << "[A" << num << ":" << typeReverseIntMap[argType] << " \"" << (char *)argDirect << "\"]";
						else
							*dynamicTr << "[A" << num << ":" << typeReverseIntMap[argType] << " \"" << (char *)argDirect << "\"]";
					}
					else
						*dynamicTr << "[RV:" << typeReverseIntMap[argType] << " \"" << (char *)argDirect << "\"]";

				}
				else if (length == 1) //UNICODE
				{
					if (num != 0)
						*dynamicTr << "[A" << num << ":" << typeReverseIntMap[argType];
					else
						*dynamicTr << "[RV:" << typeReverseIntMap[argType];

					// Convert unicode to ANSI, pain in the ass.
					wstring uniString = wstring((wchar_t *)argDirect);
					string convertUniToAnsiStr(uniString.begin(), uniString.end());
					convertUniToAnsiStr.assign(uniString.begin(), uniString.end());
					
					*dynamicTr << " \"" << convertUniToAnsiStr  << "\"]";

				}
				// Display end
				return 4;
				break;

			case 3: // CHAR MODE
				
				length = (it1->second)[1];
				argDirect = (char *)malloc(length);

				// Display begin
				if (num != 0)
				{
					// Arguments (no return value)

					PIN_SafeCopy((void*)argDirect,(void*)argPointer,length);
					if (typeReverseIntMap[argType] != "VOID")
						{
							*dynamicTr << "[A" << num << ":" << typeReverseIntMap[argType] << " \"";

							for(i = length-1; i >= 0 ; i--)
								*dynamicTr << (char)((*argDirect) + i);
							*dynamicTr << "\"]";
						}
					else
						*dynamicTr << "[A" << num << ":" << typeReverseIntMap[argType];
				}
				else
					*dynamicTr << "[RV:" << typeReverseIntMap[argType] << " " << (char)argPointer << "]";
				return length;
			default:
				return 0;
		}		
}

VOID dumpOutArgs(ADDRINT esp, ADDRINT eax, int Arg0Type, int Arg1Num, int Arg1Type, int Arg2Num, int Arg2Type, int Arg3Num, int Arg3Type, int Arg4Num, int Arg4Type)
{

	if (Arg0Type != -1) // Return value
	{
		displayArg(Arg0Type,0,eax,1);
	}
	if (Arg1Type != -1)
	{
		displayArg(Arg1Type,Arg1Num,esp+(Arg1Num-1)*ADDRESS_LENGTH,1);
	}
	if (Arg2Type != -1)
	{
		displayArg(Arg2Type,Arg2Num,esp+(Arg2Num-1)*ADDRESS_LENGTH,1);
	}
	if (Arg3Type != -1)
	{
		displayArg(Arg3Type,Arg3Num,esp+(Arg3Num-1)*ADDRESS_LENGTH,1);
	}
	if (Arg4Type != -1)
	{
		displayArg(Arg4Type,Arg4Num,esp+(Arg4Num-1)*ADDRESS_LENGTH,1);
	}
}

/* ===================================================================== */
/* 4. Initialization functions
/* ===================================================================== */

void initTypes(string configFileAPI) {


	int countType=1;

	string line, typeName, typeRepresentation;
	int first, last, checkComment;

	vector<int> currentType;
	currentType.push_back('0');
	currentType.push_back('0');

	ifstream APIfile ( configFileAPI.c_str() , ifstream::in );
	
	int lookForBasicTypes = 1;
	int lookForComplexTypes = 1;

	// Default element when no types found
	typeIntMap["UNKNOWN"]=0;
	typeReverseIntMap[0]="UNKNOWN";

	// Look for basic types section
	while (APIfile.good() && lookForBasicTypes)
	{
			getline(APIfile,line);
			if (line.find("** BASIC_TYPES **") != string::npos)
				lookForBasicTypes = 0;
	}
	
	if(lookForBasicTypes)
	{
		*tripouxLog << "-> Config API file problem : basic types" << endl;
		exit(1);
	}

	// Store basic types and look for complex types
	while (APIfile.good() && lookForComplexTypes)
	{
		
		getline(APIfile,line);

		if (line.find("** COMPLEX_TYPES **") != string::npos)
			lookForComplexTypes = 0;
		else
		{
			checkComment = line.find_first_of("#");
			if(checkComment == 0)
				continue;

			first = line.find_first_of("\t");
			if (first != string::npos)
			{
				typeName = line.substr(0,first);
				if(typeIntMap.find(typeName) == typeIntMap.end())
				{
					typeIntMap[typeName]=countType;
					typeReverseIntMap[countType]=typeName;
					countType++;
				}

				last = line.find_last_of("\t");
				typeRepresentation = line.substr(last+1,string::npos);
				
				switch(typeRepresentation[0])
				{
					case 'D': // Direct dump
						currentType[0]=0;
						currentType[1]=atoi(&typeRepresentation[1]);
						break;
					case 'I': // Indirect dump
						currentType[0]=1;
						currentType[1]=atoi(&typeRepresentation[1]);
						break;
					case 'S': // C-String style
						currentType[0]=2;
						if(typeRepresentation[1]=='A')
							currentType[1]=0;
						else
						{
							if(typeRepresentation[1]=='W')
								currentType[1]=1;
							else
								*tripouxLog << "Config API file problem : basic type : " << typeRepresentation << endl;
						}
						break;
					case 'C': // Like "D" but display it as characters
						currentType[0]=3;
						currentType[1]=atoi(&typeRepresentation[1]);
						break;
					default:
						*tripouxLog << "Config API file problem : basic type : " << typeRepresentation << endl;
						return;
				}

				basicTypeMap[typeIntMap[typeName]] = currentType;
			}
		}
	}

	currentType.pop_back();
	currentType.pop_back();

	if(lookForComplexTypes)
	{
		*tripouxLog << "Config API file problem : complex types" << endl;
		exit(1);
	}

	while (APIfile.good())
	{
		getline(APIfile,line);
		
		checkComment = line.find_first_of("#");
		if(checkComment == 0)
				continue;
		first = line.find_first_of("\t");
		if (first != string::npos)
		{
			vector<int> currentType;
			typeName = line.substr(0,first);
			if(typeIntMap.find(typeName) == typeIntMap.end())
			{
				typeIntMap[typeName]=countType;
				typeReverseIntMap[countType]=typeName;
				countType++;
			}

			last = line.find_last_of("\t");
			typeRepresentation = line.substr(last+1,string::npos);

			switch(typeRepresentation[0])
			{
				case 'D':
					typeRepresentation = typeRepresentation.substr(2,string::npos);
					first = typeRepresentation.find(",");
					while(first != string::npos)
					{
						currentType.push_back(typeIntMap[typeRepresentation.substr(0,first)]);
						typeRepresentation = typeRepresentation.substr(first+1,string::npos);
						first = typeRepresentation.find(",");
					}
					last = typeRepresentation.find("]");
					currentType.push_back(typeIntMap[typeRepresentation.substr(0,last)]);
					break;
				case 'I':
					last = typeRepresentation.find("]");
					currentType.push_back(0);
					currentType.push_back(typeIntMap[typeRepresentation.substr(2,last-2)]);
					break;
				default:
					*tripouxLog << "Config API file problem : complex types" << endl;
					exit(1);
					break;
			}
			complexTypeMap[typeIntMap[typeName]]=currentType;
		}		
	}

	APIfile.close();
}

void initPrototypes(string configFileAPI) {

	string line, functionName, functionReturnType, functionCurrentType;
	int first, firstPar, endPar, checkComment, virg1, virg2;
	
	ifstream APIfile ( configFileAPI.c_str() , ifstream::in );

	int lookForPrototypes = 1;

	// Look for prototypes section
	while (APIfile.good() && lookForPrototypes)
	{
		getline(APIfile,line);
		if (line.find("** PROTOTYPES **") != string::npos)
			lookForPrototypes = 0;
	}

	if(lookForPrototypes)
	{
		*tripouxLog << "Config API file problem : prototypes" << endl;
		exit(1);
	}

	
	while (APIfile.good())
	{
		getline(APIfile,line);
		
		checkComment = line.find_first_of("#");
		if(checkComment == 0)
			continue;

		first = line.find_first_of(" ");
		if(first != string::npos)
		{
			vector<vector<int>> currentProto;
			vector<int> currentType;
			string * arrayStr = NULL;

			functionReturnType = line.substr(0,first);
			firstPar = line.find_first_of("(");
			endPar = line.find_last_of(")");
			if(firstPar>first)
			{
				functionName = line.substr(first+1,firstPar-(first+1));

				// Return value
				currentType.push_back(1);
				currentType.push_back(typeIntMap[functionReturnType]);
				currentProto.push_back(currentType);


				virg2 = line.find(",");
				if (virg2 == string::npos) // 1 argument
				{
					if(line.substr(firstPar+1,endPar - (firstPar+1)).find("IN_OUT ") != string::npos)
					{	
						currentType[0]=2;
						currentType[1]=typeIntMap[line.substr(firstPar+8,endPar - (firstPar+8))];
						currentProto.push_back(currentType);
					}
					else if(line.substr(firstPar+1,endPar - (firstPar+1)).find("IN ") != string::npos)
					{
						currentType[0]=0;
						currentType[1]=typeIntMap[line.substr(firstPar+4,endPar - (firstPar+4))];
						currentProto.push_back(currentType);
					}
					else if(line.substr(firstPar+1,endPar - (firstPar+1)).find("OUT ") != string::npos)
					{
						currentType[0]=1;
						currentType[1]=typeIntMap[line.substr(firstPar+5,endPar - (firstPar+5))];
						currentProto.push_back(currentType);
					}
					else // by default IN arg
					{
						currentType[0]=0;
						currentType[1]=typeIntMap[line.substr(firstPar+1,endPar - (firstPar+1))];
						currentProto.push_back(currentType);
					}
				}
				else
				{
					
					virg1 = firstPar;
					
					while(virg2 !=  string::npos)
					{
						if(line.substr(virg1+1,virg2-(virg1+1)).find("IN_OUT ") != string::npos)
						{
							currentType[0]=2;
							currentType[1]=typeIntMap[line.substr(virg1+8,virg2-(virg1+8))];
							currentProto.push_back(currentType);
						}
						else if(line.substr(virg1+1,virg2-(virg1+1)).find("IN ") != string::npos)
						{
							currentType[0]=0;
							currentType[1]=typeIntMap[line.substr(virg1+4,virg2-(virg1+4))];
							currentProto.push_back(currentType);
						}
						else if(line.substr(virg1+1,virg2-(virg1+1)).find("OUT ") != string::npos)
						{
							currentType[0]=1;
							currentType[1]=typeIntMap[line.substr(virg1+5,virg2-(virg1+5))];
							currentProto.push_back(currentType);
						}
						else // by default IN arg
						{
							currentType[0]=0;
							currentType[1]=typeIntMap[line.substr(virg1+1,virg2-(virg1+1))];
							currentProto.push_back(currentType);
						}

						virg1 = virg2;
						virg2 = line.find(",",virg2+1);			
					}
					
					// Last argument
					// We don't deal with variable parameter number functions, but plan to do something more clean here
					if(line.substr(virg1+1,endPar - (virg1+1)) != "...")
					{
						if(line.substr(virg1+1,endPar - (virg1+1)).find("IN_OUT ") != string::npos)
						{
							currentType[0]=2;
							currentType[1]=typeIntMap[line.substr(virg1+8,endPar - (virg1+8))];
							currentProto.push_back(currentType);
						}
						else if(line.substr(virg1+1,endPar - (virg1+1)).find("IN ") != string::npos)
						{
							currentType[0]=0;
							currentType[1]=typeIntMap[line.substr(virg1+4,endPar - (virg1+4))];
							currentProto.push_back(currentType);
						}
						else if(line.substr(virg1+1,endPar - (virg1+1)).find("OUT ") != string::npos)
						{
							currentType[0]=1;
							currentType[1]=typeIntMap[line.substr(virg1+5,endPar - (virg1+5))];
							currentProto.push_back(currentType);
						}
						else // by default IN arg
						{
							currentType[0]=0;
							currentType[1]=typeIntMap[line.substr(virg1+1,endPar - (virg1+1))];
							currentProto.push_back(currentType);
						}
					}
				}
				protoMap[functionName]=currentProto;
			}
			else
				*tripouxLog << "Config API file problem : prototypes " << line << endl;
		}
	}
	APIfile.close();
}

template <class T> bool from_string(T& t, const std::string& s, std::ios_base& (*f)(std::ios_base&))
{
  std::istringstream iss(s);
  return !(iss >> f >> t).fail();
}

void initIDAFunctionFile(string fileName)
{

	string line;
	ifstream functionFile (fileName.c_str(), ifstream::in);
	
	while(functionFile.good())
	{
		getline(functionFile,line);
		if(line[0] == '_')
		{
			// Only interested in functions with name like "_*"

			// Get the name (without the first "_")
			string name = line.substr(1,line.find_first_of(" ")-1);

			// Get the address
			// jump over the name
			string addressFunctionStr = line.substr(line.find_first_of(" "));
			addressFunctionStr = addressFunctionStr.substr(addressFunctionStr.find_first_not_of(" "));

			// jump over the section
			addressFunctionStr = addressFunctionStr.substr(addressFunctionStr.find_first_of(" ")+1,8);
			
			int addressFunctionInt;
			if(from_string<int>(addressFunctionInt, std::string(addressFunctionStr), std::hex))
				staticFunctions[addressFunctionInt] = name;
			else
				*tripouxLog << "Fail during the parsing of the IDA functions file for \"" << name << "\"" << endl;
		}
	}
}

bool checkArguments(int argc, char* argv[])
{
	int i;

	for(i = 1; i < argc; i++)
	{
		/* Help */
		if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
		{
			*tripouxLog << "Usage: pin -t Tripoux.dll [-p protoFile][-s startAddress][-f functionsFile] -- binaryToTrace.exe\n"
				"Options:\n"
				"-p protoFile : Give a formatted file containing the API prototypes (cf doc)\n"
				"-s startAddress : Give the address where to start the tracing (IN HEXADECIMAL!)\n"
				"-f functionsFile : Give a formatted file containing the static API functions (output from IDA Pro)\n"
				"-h or --help : display the help"
			  << endl;
		  exit(0);
		}

		/* Start point */
		if(strcmp(argv[i], "-s") == 0)
		{	
			if(i+1<argc) 
			{
				if(!from_string<int>(startAddress, std::string(argv[i+1]), std::hex))
				{
					*tripouxLog << "Fail to get the start address. Check -h." << endl;
					return false;
				}
				else
					start = 0;
			}
			else
			{
				*tripouxLog << "Missing parameter : hexadecimal address behind -s" << endl;
				return false;
			}
		}

		/* Prototypes file */
		if(strcmp(argv[i], "-p") == 0)
		{	
			if(i+1<argc) 
			{
				initTypes((string)argv[i+1]); // exit if there is a failure
				initPrototypes((string)argv[i+1]);
			}
			else
			{
				*tripouxLog << "Missing parameter : filename behind -p" << endl;
				return false;
			}

		}

		/* IDA Pro functions file */
		if(strcmp(argv[i], "-f") == 0)
		{
			if(i+1<argc) 
			{
				initIDAFunctionFile(argv[i+1]);
			}
			else
			{
				*tripouxLog << "Missing parameter : filename behind -f" << endl;
				return false;
			}
		}	
	}

	return true;
}



/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{

	puts("Tripoux Tracer - version 0.1 - by j04n");
	
	// Setup output files
    dynamicTr = new std::ofstream("dynamicTrace.out");
	staticInstructions = new std::ofstream("staticInstructions.out");
	memoryFingerprint = new std::ofstream("memFingerprint.out",ofstream::binary);
	tripouxLog = new std::ofstream("tripoux.log"); // Errors and bullshit file
	
	checkArguments(argc, argv);
	
	// Pin setup
	PIN_Init(argc,argv);
	PIN_InitSymbols();
	PIN_AddFiniFunction(Fini, 0);

	IMG_AddInstrumentFunction(imgInstrumentation,0);
	INS_AddInstrumentFunction(instrumentationFunction, 0);

	PIN_StartProgram();    // Never returns

    return 0;
}



/* ===================================================================== */
/* Debug functions                                                       */
/* ===================================================================== */

VOID printInstructionType(short instType)
{
	if(instType != 0x0)
	{
		*dynamicTr << "-> Instruction type : "; 
		
		if(instType & 0x8000)
		{
			*dynamicTr << "Branch ";
		
			if(instType & 0x4000)
				*dynamicTr << "Conditionnal ";
			else
				*dynamicTr << "Non-Conditionnal ";
		
			if(instType & 0x2000)
				*dynamicTr << "Direct ";
			else
				*dynamicTr << "Indirect ";

			// Call and return are considered as branch !
			if(instType & 0x1000)
				*dynamicTr << "Call ";
			else if(instType & 0x0800)
				*dynamicTr << "Return ";
		}

		if(instType & 0x0080)
			*dynamicTr << "Push ";	
		else if(instType & 0x0040)
			*dynamicTr << "Pop ";

		// Push-Pop-Call-Ret are the instructions "stack related", this is probably not enough! (pushadd ?)
		if(instType & 0x0020)
			*dynamicTr << "Stack-related ";

		*dynamicTr << endl;
	}
}

void printFlags(int readFlags, int writtenFlags)
{

	int flags[] = {readFlags, writtenFlags};
	int i;

	for(i=0;i<2;i++)
	{
		if(flags[i] != 0x0)
		{
			if(i==0)
				*dynamicTr << "-> Read Flags :";
			else
				*dynamicTr << "-> Written Flags :";

			if(flags[i] & 0x0001)
				*dynamicTr << " CF ";
			if(flags[i] & 0x0004)
				*dynamicTr << " PF ";
			if(flags[i] & 0x0010)
				*dynamicTr << " AF ";
			if(flags[i] & 0x0040)
				*dynamicTr << " ZF ";
			if(flags[i] & 0x0080)
				*dynamicTr << " SF ";
			if(flags[i] & 0x0100)
				*dynamicTr << " TF ";
			if(flags[i] & 0x0200)
				*dynamicTr << " IF ";
			if(flags[i] & 0x0400)
				*dynamicTr << " DF ";
			if(flags[i] & 0x0800)
				*dynamicTr << " OF ";

			*dynamicTr << endl;
		}
	}

}

VOID printStaticX86Instruction(staticX86Instruction myInstruction)
{
	*dynamicTr << "-> Instruction length : " << (int)myInstruction.instructionLength << endl;
	//*dynamicTr << "-> Intel disass : " << myInstruction.disassIntelInstruction << endl; // No longer implemented
	printInstructionType(myInstruction.instructionType);
	printFlags(myInstruction.readFlags,myInstruction.writtenFlags);
}


/* ===================================================================== */
/* eof */