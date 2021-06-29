#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import RemoteController

class final_topo(Topo):
  def build(self):
    # Examples!
    # Create a host with a default route of the ethernet interface. You'll need to set the
    # default gateway like this for every host you make on this assignment to make sure all 
    # packets are sent out that port. Make sure to change the h# in the defaultRoute area
    # and the MAC address when you add more hosts!

    # Floor 1
    h10 = self.addHost('h10',mac='00:00:00:00:00:01',ip='10.1.1.10/24', defaultRoute="h10-eth0")
    h20 = self.addHost('h20',mac='00:00:00:00:00:02',ip='10.1.2.20/24', defaultRoute="h20-eth0")
    h30 = self.addHost('h30',mac='00:00:00:00:00:03',ip='10.1.3.30/24', defaultRoute="h30-eth0")
    h40 = self.addHost('h40',mac='00:00:00:00:00:04',ip='10.1.4.40/24', defaultRoute="h40-eth0")

    # Floor 2
    h50 = self.addHost('h50',mac='00:00:00:00:00:05',ip='10.2.5.50/24', defaultRoute="h50-eth0")
    h60 = self.addHost('h60',mac='00:00:00:00:00:06',ip='10.2.6.60/24', defaultRoute="h60-eth0")
    h70 = self.addHost('h70',mac='00:00:00:00:00:07',ip='10.2.7.70/24', defaultRoute="h70-eth0")
    h80 = self.addHost('h80',mac='00:00:00:00:00:08',ip='10.2.8.80/24', defaultRoute="h80-eth0")

    h_server = self.addHost('h_server',mac='00:00:00:00:00:09',ip='10.3.9.90/24', defaultRoute="h_server-eth0")
    h_trust = self.addHost('h_trust',mac='00:00:00:00:01:00',ip='108.24.32.112/24', defaultRoute="h_trust-eth0")
    h_untrust = self.addHost('h_untrust',mac='00:00:00:00:02:00',ip='106.44.83.103/24', defaultRoute="h_untrust-eth0")
    

    # Create a switch. No changes here from Lab 1.
    s1 = self.addSwitch('s1')  # Floor 1 Switch 1
    s2 = self.addSwitch('s2')  # Floor 1 Switch 2
    
    s3 = self.addSwitch('s3')  # Floor 2 Switch 1
    s4 = self.addSwitch('s4')  # Floor 2 Switch 2



    s5 = self.addSwitch('s5')  # Core Switch
    s6 = self.addSwitch('s6')  # Data Center Switch

    # Connect Port 8 on the Switch to Port 0 on Host 1 and Port 9 on the Switch to Port 0 on 
    # Host 2. This is representing the physical port on the switch or host that you are 
    # connecting to.
    #
    # IMPORTANT NOTES: 
    # - On a single device, you can only use each port once! So, on s1, only 1 device can be
    #   plugged in to port 1, only one device can be plugged in to port 2, etc.
    # - On the "host" side of connections, you must make sure to always match the port you 
    #   set as the default route when you created the device above. Usually, this means you 
    #   should plug in to port 0 (since you set the default route to h#-eth0).
    #
    # self.addLink(s1,h1, port1=8, port2=0)
    # self.addLink(s1,h2, port1=9, port2=0)

    # Floor 1 Switch 1
    self.addLink(s1,h10, port1=8, port2=0)
    self.addLink(s1,h20, port1=9, port2=0)

    # Floor 1 Switch 2
    self.addLink(s2,h30, port1=8, port2=0)
    self.addLink(s2,h40, port1=9, port2=0)

    # Floor 2 Switch 1
    self.addLink(s3,h50, port1=8, port2=0)
    self.addLink(s3,h60, port1=9, port2=0)

    # Floor 2 Switch 2
    self.addLink(s4,h70, port1=8, port2=0)
    self.addLink(s4,h80, port1=9, port2=0)

    # Server and Data Center Switch
    self.addLink(s6, h_server, port1=8, port2=0)

    
    # Trusted and Core Switch
    self.addLink(s5, h_trust, port1=5, port2=0)

    # Untrusted and Core Switch
    self.addLink(s5, h_untrust, port1=6, port2=0)


    # Floor switches and Core Switch
    self.addLink(s5,s1, port1=1, port2=1)
    self.addLink(s5,s2, port1=2, port2=1)
    self.addLink(s5,s3, port1=3, port2=1)
    self.addLink(s5,s4, port1=4, port2=1)

    # Core Switch and Data Center Switch 
    self.addLink(s5, s6, port1=7, port2=1)

def configure():
  topo = final_topo()
  net = Mininet(topo=topo, controller=RemoteController)
  net.start()

  CLI(net)
  
  net.stop()


if __name__ == '__main__':
  configure()
