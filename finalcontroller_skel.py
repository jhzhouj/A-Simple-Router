# Final Skeleton
#
# Hints/Reminders from Lab 3:
#
# To check the source and destination of an IP packet, you can use
# the header information... For example:
#
# ip_header = packet.find('ipv4')
#
# if ip_header.srcip == "1.1.1.1":
#   print "Packet is from 1.1.1.1"
#
# Important Note: the "is" comparison DOES NOT work for IP address
# comparisons in this way. You must use ==.
# 
# To send an OpenFlow Message telling a switch to send packets out a
# port, do the following, replacing <PORT> with the port number the 
# switch should send the packets out:
#
#    msg = of.ofp_flow_mod()
#    msg.match = of.ofp_match.from_packet(packet)
#    msg.idle_timeout = 30
#    msg.hard_timeout = 30
#
#    msg.actions.append(of.ofp_action_output(port = <PORT>))
#    msg.data = packet_in
#    self.connection.send(msg)
#
# To drop packets, simply omit the action.
#

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Final (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

  def do_final (self, packet, packet_in, port_on_switch, switch_id):
    # This is where you'll put your code. The following modifications have 
    # been made from Lab 3:
    #   - port_on_switch: represents the port that the packet was received on.
    #   - switch_id represents the id of the switch that received the packet.
    #      (for example, s1 would have switch_id == 1, s2 would have switch_id == 2, etc...)
    # You should use these to determine where a packet came from. To figure out where a packet 
    # is going, you can use the IP header information.
    
    msg = of.ofp_flow_mod()

    msg.match = of.ofp_match.from_packet(packet)

    msg.idle_timeout = 30  
    msg.hard_timeout = 30 

    host10_IP = '10.1.1.10' # Host10 IP address
    host20_IP = '10.1.2.20' # Host20 IP address 
    host30_IP = '10.1.3.30' # Host30 IP address
    host40_IP = '10.1.4.40' # Host40 IP address
    host50_IP = '10.2.5.50' # Host50 IP address
    host60_IP = '10.2.6.60' # Host60 IP address
    host70_IP = '10.2.7.70' # Host70 IP address
    host80_IP = '10.2.8.80' # Host80 IP address
    server_IP = '10.3.9.90' # Server IP address
    trustedHost_IP = '108.24.32.112' # Trusted Host IP address
    untrustedHost_IP = '106.44.83.103' # Untrustest Host IP address

    floor1Switch1 = 1 # Floor 1 Switch 1
    floor1Switch2 = 2 # Floor 1 Switch 2
    floor2Switch1 = 3 # Floor 2 Switch 1
    floor2Switch2 = 4 # Floor 2 Switch 2
    coreSwitch = 5 # Core Switch
    dataCenterSwitch = 6 # Data Center Switch
    

    icmp = packet.find('icmp')
    ip = packet.find('ipv4')

    # if not an ip packet, flood
    if ip is None:  
      msg.data = packet_in
      msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
      self.connection.send(msg)
    else:
      if switch_id == floor1Switch1:   # floor 1 switch 1
        if icmp is not None and (ip.dstip == host50_IP or ip.dstip == host60_IP or ip.dstip == host70_IP or ip.dstip == host80_IP):  
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
            self.connection.send(msg)
          
        else:
          if ip.dstip == host10_IP:
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port=8))
            self.connection.send(msg)
          elif ip.dstip == host20_IP:
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port=9))
            self.connection.send(msg)
          else:    
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port=1))
            self.connection.send(msg)


      elif switch_id == floor1Switch2:   # floor 1 switch 2
        if icmp is not None and (ip.dstip == host50_IP or ip.dstip == host60_IP or ip.dstip == host70_IP or ip.dstip == host80_IP):
          msg.data = packet_in
          msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
          self.connection.send(msg)  

        else:
          if ip.dstip == host30_IP:
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port=8))
            self.connection.send(msg)
          elif ip.dstip == host40_IP:
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port=9))
            self.connection.send(msg)
          else:    
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port=1))
            self.connection.send(msg)


      elif switch_id == floor2Switch1:     # floor 2 switch 1
        if icmp is not None and (ip.dstip == host10_IP or ip.dstip == host20_IP or ip.dstip == host30_IP or ip.dstip == host40_IP):
          msg.data = packet_in
          msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
          self.connection.send(msg)  

        else:
          if ip.dstip == host50_IP:
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port=8))
            self.connection.send(msg)
          elif ip.dstip == host60_IP:
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port=9))
            self.connection.send(msg)
          else:    
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port=1))
            self.connection.send(msg)


      elif switch_id == floor2Switch2:     # floor 2 switch 2
        if icmp is not None and (ip.dstip == host10_IP or ip.dstip == host20_IP or ip.dstip == host30_IP or ip.dstip == host40_IP):
          msg.data = packet_in
          msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
          self.connection.send(msg)  

        else:
          if ip.dstip == host70_IP:
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port=8))
            self.connection.send(msg)
          elif ip.dstip == host80_IP:
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port=9))
            self.connection.send(msg)
          else:    
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port=1))
            self.connection.send(msg)

      elif switch_id == coreSwitch:     # coreSwitch
        if ip.srcip == untrustedHost_IP:   # untrustedHost
          
          if icmp is not None:    # now it's icmp
            if ip.dstip == trustedHost_IP:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port=5))
              self.connection.send(msg)
            else:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
              self.connection.send(msg)

          else:   # now it's IP traffic
            if ip.dstip == trustedHost_IP:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port=5))
              self.connection.send(msg)

            elif ip.dstip == untrustedHost_IP:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port=6))
              self.connection.send(msg)

            elif ip.dstip == host10_IP or ip.dstip == host20_IP:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port=1))
              self.connection.send(msg)

            elif ip.dstip == host30_IP or ip.dstip == host40_IP:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port=2))
              self.connection.send(msg)

            elif ip.dstip == host50_IP or ip.dstip == host60_IP:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port=3))
              self.connection.send(msg)

            elif ip.dstip == host70_IP or ip.dstip == host80_IP:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port=4))
              self.connection.send(msg)

            elif ip.dstip == server_IP:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
              self.connection.send(msg)


        elif ip.srcip == trustedHost_IP:  #  trustedHost
          if icmp is not None:    # now it's icmp
            if ip.dstip == untrustedHost_IP:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port=6))
              self.connection.send(msg)
            
            elif ip.dstip == host50_IP or ip.dstip == host60_IP:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port=3))
              self.connection.send(msg)

            elif ip.dstip == host70_IP or ip.dstip == host80_IP:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port=4))
              self.connection.send(msg)

            else:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
              self.connection.send(msg)

          else: # now it's IP traffic
            if ip.dstip == trustedHost_IP:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port=5))
              self.connection.send(msg)

            elif ip.dstip == untrustedHost_IP:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port=6))
              self.connection.send(msg)

            elif ip.dstip == host10_IP or ip.dstip == host20_IP:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port=1))
              self.connection.send(msg)

            elif ip.dstip == host30_IP or ip.dstip == host40_IP:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port=2))
              self.connection.send(msg)

            elif ip.dstip == host50_IP or ip.dstip == host60_IP:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port=3))
              self.connection.send(msg)

            elif ip.dstip == host70_IP or ip.dstip == host80_IP:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port=4))
              self.connection.send(msg)

            elif ip.dstip == server_IP:
              msg.data = packet_in
              msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
              self.connection.send(msg)

        # now the source is neither trustedHost nor untrustedHost
        elif ip.dstip == trustedHost_IP:
          msg.data = packet_in
          msg.actions.append(of.ofp_action_output(port=5))
          self.connection.send(msg)

        elif ip.dstip == untrustedHost_IP:
          msg.data = packet_in
          msg.actions.append(of.ofp_action_output(port=6))
          self.connection.send(msg)

        elif ip.dstip == host10_IP or ip.dstip == host20_IP:
          msg.data = packet_in
          msg.actions.append(of.ofp_action_output(port=1))
          self.connection.send(msg)

        elif ip.dstip == host30_IP or ip.dstip == host40_IP:
          msg.data = packet_in
          msg.actions.append(of.ofp_action_output(port=2))
          self.connection.send(msg)

        elif ip.dstip == host50_IP or ip.dstip == host60_IP:
          msg.data = packet_in
          msg.actions.append(of.ofp_action_output(port=3))
          self.connection.send(msg)

        elif ip.dstip == host70_IP or ip.dstip == host80_IP:
          msg.data = packet_in
          msg.actions.append(of.ofp_action_output(port=4))
          self.connection.send(msg)

        elif ip.dstip == server_IP:
          if ip.srcip == trustedHost_IP or ip.srcip == untrustedHost_IP:
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
            self.connection.send(msg)

          else:
            msg.data = packet_in
            msg.actions.append(of.ofp_action_output(port=7))
            self.connection.send(msg)

        else:
          msg.data = packet_in
          msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
          self.connection.send(msg)

      elif switch_id == dataCenterSwitch:  #  dataCenterSwitch
        if ip.dstip == server_IP:   #  go to server
          msg.data = packet_in
          msg.actions.append(of.ofp_action_output(port=8))
          self.connection.send(msg)

        else:   # go to core switch
          msg.data = packet_in
          msg.actions.append(of.ofp_action_output(port=1))
          self.connection.send(msg)



  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_final(packet, packet_in, event.port, event.dpid)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Final(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
