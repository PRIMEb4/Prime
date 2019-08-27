import sys


sys.path.insert(0, "../ply-3.11/")
sys.path.insert(0, "interpreter/")

from interpreter import commandline


cmd = commandline()

x = cmd.carry_composition('firewall', '')

x = cmd.carry_composition('l3', 'BOLACHA_')

cmd.write_composition_(x)