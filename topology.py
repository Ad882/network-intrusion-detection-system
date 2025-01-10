from mininet.topo import Topo

class SimpleTopo(Topo):

    def __init__(self):
        Topo.__init__(self)

        leftHost = self.addHost('h1')
        rightHost = self.addHost('h2')
        switch = self.addSwitch('s1')

        self.addLink(leftHost, switch)
        self.addLink(switch, rightHost)


class DDoSTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        # Création des hôtes et du switch
        ddos_hosts = [self.addHost(f'h{i}') for i in range(1, 6)]
        target_host = self.addHost('h6')
        switch = self.addSwitch('s1')

        # Connecter les hôtes au switch
        for host in ddos_hosts:
            self.addLink(host, switch)
        self.addLink(target_host, switch)



topos = {
    'simple': (lambda: SimpleTopo()),
    'ddos': (lambda: DDoSTopo())
}