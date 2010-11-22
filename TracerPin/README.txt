Tripoux project - Joan Calvet - j04n.calvet@gmail.com
Version : v0.1

This is the Pin tracer of the project (only suitable for x86-32bits processor and Windows binaries)

Usage: pin -t TripouxTracer_32b.dll [-p protoFile][-s startAddress][-f functionsFile] -- binaryToTrace.exe

Options:
				-p protoFile : Give a formatted file containing the API prototypes (e.g. "protoAPI_win32_libc.txt" which is furnished)
				-s startAddress : Give the address where to start the tracing, in hexadecimal, e.g. "4010FF"
				-f functionsFile : Give a formatted file containing the static API functions. This file is the output of IDA Pro functions window (right-click->"Copy")
				-h or --help : display the help
