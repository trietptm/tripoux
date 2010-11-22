Tripoux project - Joan Calvet - j04n.calvet@gmail.com
Version : v0.1

This is the core engine of the project that translate the trace coming out from the Pin tracer into something usable.

* It defines some high-level abstractions on the code: 
1. Waves: a subset of the trace where there is no self-modifying code (aka layer of dynamic code)
2. Loops

* It detects some events : 
1. Exceptions (actually done by the tracer)
2. Api Calls (actually done by the tracer)
3. System Access : read or write into the PEB/TEB/PE headers of the loaded modules.
4. "Fake" Conditionnal or Indirect Branch (that is conditionnal or indirect branch that are always seen jumping at one specific place)

Usage: translatorPin.exe -t dynamicTraceFile -s staticInstructionsFile -m memFingerprint
						(These 3 files come from the Pin tracer of the Tripoux project.)
						
Optionnal arguments to limit the analysis : --no-loops, --no-waves, --no-apicalls, --no-exceptions, --no-systemaccess, --no-fakebr
