# Prime

Prime is a composition mechanism for modular P4 programs. 

The system provides programming operators to compose PDP programs and specify the steering through them.

The Prime platform - composition engine & configuration interface. 

Top level structure: 
   * bmv2: Slightly modified version of mininet and extra examples used by Prime
   * bmv2.sh: a wrapper that starts mininet and use w/composed modules
   * prime: Prime system proper
   * prime.py: a wrapper that starts Prime and optinally deploy the program on the available P4 target
