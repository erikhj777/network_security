#!/usr/bin/env python3
import ifcfg
from pprint import pprint

print(dir(ifcfg))#return all attributes & methods of ifcfg module
#returns dict of each active interface : information
pprint(ifcfg.interfaces())

default = ifcfg.default_interface()
ip_address = default['inet']
print(ip_address)
