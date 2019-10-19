from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
import csv

log = core.getLogger()
policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ[ 'HOME' ]
file = csv.DictReader(open(policyFile))

class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        self.list = []
        log.debug("Enabling Firewall Module")
        for entry in file:
            first = entry["mac_0"]
            second = entry["mac_1"]
            self.list.append((EthAddr(first), EthAddr(second)))

    def _handle_ConnectionUp (self, event):
        for (first,second) in self.list:
            match = of.ofp_match()
            match.dl_src = source
            match.dl_dst = dest
            msg = of.ofp_flow_mod()
            msg.match = match
            event.connection.send(msg)
        
        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

def launch ():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)
