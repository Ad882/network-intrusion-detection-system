from mininet.topo import Topo

# Simple topology: 2 hosts, 1 switch
# h1 <-> s1 <-> h2
class SimpleTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        leftHost = self.addHost('h1')
        rightHost = self.addHost('h2')
        switch = self.addSwitch('s1')

        self.addLink(leftHost, switch)
        self.addLink(switch, rightHost)


# More complex topology: 6 hosts, 1 switch
#    h1    h4
#     \    /  
# h2 -  s1  -  h5
#     /    \
#    h3    h6
class DDoSTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        ddos_hosts = [self.addHost(f'h{i}') for i in range(1, 6)]
        target_host = self.addHost('h6')
        switch = self.addSwitch('s1')

        for host in ddos_hosts:
            self.addLink(host, switch)
        self.addLink(target_host, switch)



topos = {
    'simple': (lambda: SimpleTopo()),
    'ddos': (lambda: DDoSTopo())
}