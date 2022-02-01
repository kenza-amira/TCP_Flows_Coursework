from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from ipaddress import ip_address, IPv6Address
from socket import IPPROTO_TCP
import sys
import matplotlib.pyplot as plt

class Flow(object):
    def __init__(self, data):
        self.pkts = 0
        self.flows = 0
        self.ft = {}
        for pkt, metadata in RawPcapReader(data):
            self.pkts += 1
            ether = Ether(pkt)
            if ether.type == 0x86dd:
                ip = ether[IPv6]                
                if ip.nh != 6:
                    continue
                ip_src = int(IPv6Address(ip.src))
                ip_dst = int(IPv6Address(ip.dst))
                flow = ip.plen
            elif ether.type == 0x0800:
                ip = ether[IP]
                if ip.proto != 6:
                    continue
                ip_src = int(ip_address(ip.src))
                ip_dst = int(ip_address(ip.dst))
                flow = ip.len - ip.ihl * 4
            try:
                tcp = ip[TCP]
            except IndexError:
                continue

            self.flows += 1
            flow -= tcp.dataofs * 4

            sport = tcp.sport
            dport = tcp.dport

            onward = (ip_src, ip_dst, sport, dport)
            returning = (ip_dst, ip_src, dport, sport)

            if onward in self.ft:
                self.ft[onward] += flow
            elif returning in self.ft:
                self.ft[returning] += flow
            else:
                self.ft[onward] = flow

    def Plot(self):
        topn = 100
        data = [i/1000 for i in list(self.ft.values())]
        data.sort()
        data = data[-topn:]
        fig = plt.figure()
        ax = fig.add_subplot(1,1,1)
        ax.hist(data, bins=50, log=True)
        ax.set_ylabel('# of flows')
        ax.set_xlabel('Data sent [KB]')
        ax.set_title('Top {} TCP flow size distribution.'.format(topn))
        plt.savefig(sys.argv[1] + '.flow.pdf', bbox_inches='tight')
        plt.close()
    def _Dump(self):
        with open(sys.argv[1] + '.flow.data', 'w') as f:
            f.write('{}'.format(self.ft))

if __name__ == '__main__':
    d = Flow(sys.argv[1])
    d.Plot()
    d._Dump()
