#reference from apache l3_learning
#Authors - Aaasheesh, Arjun, Sashwath and Jay
#Improvements on top of the existing L3 Apache learning switch

from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer

import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time

# Timeout for flows
FLOW_IDLE_TIMEOUT = 100

# Timeout for ARP entries
ARP_TIMEOUT = 100

# Maximum number of packet to buffer on a switch for an unknown IP
MAX_BUFFERED_PER_IP = 5

# Maximum time to hang on to a buffer for an unknown IP in seconds
MAX_BUFFER_TIME = 5

# Cache UP timer
CACHE_UP_TIMER = 180

#HackAlert
cache = ['192.168.1.4', '192.168.1.5']
cache1Down = False
cache1checker = False
cache1checkerCount = 10;
cache2Down = False
cache2checker = False
cache2checkerCount = 10;
cacheCnt = 0
dstCacheDict = {}
nwHosts = set()

for i in xrange(1,6):
  nwHosts.add(IPAddr('192.168.1.'+str(i)))
nwHosts.add(IPAddr('0.0.0.0'))
nwHosts.add(IPAddr('255.255.255.255'))

class Entry (object):
  """
  Not strictly an ARP entry.
  We use the port to determine which port to forward traffic out of.
  We use the MAC to answer ARP replies.
  We use the timeout so that if an entry is older than ARP_TIMEOUT, we
   flood the ARP request rather than try to answer it ourselves.
  """
  def __init__ (self, port, mac):
    self.timeout = time.time() + ARP_TIMEOUT
    self.port = port
    self.mac = mac

  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)
  def __ne__ (self, other):
    return not self.__eq__(other)

  def isExpired (self):
    if self.port == of.OFPP_NONE: return False
    return time.time() > self.timeout


def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))


class l3_switch (EventMixin):
  def __init__ (self, fakeways = [], arp_for_unknowns = False, wide = False):
    # These are "fake gateways" -- we'll answer ARPs for them with MAC
    # of the switch they're connected to.
    self.fakeways = set(fakeways)

    # If True, we create "wide" matches.  Otherwise, we create "narrow"
    # (exact) matches.
    self.wide = wide

    # If this is true and we see a packet for an unknown
    # host, we'll ARP for it.
    self.arp_for_unknowns = arp_for_unknowns

    # (dpid,IP) -> expire_time
    # We use this to keep from spamming ARPs
    self.outstanding_arps = {}

    # (dpid,IP) -> [(expire_time,buffer_id,in_port), ...]
    # These are buffers we've gotten at this datapath for this IP which
    # we can't deliver because we don't know where they go.
    self.lost_buffers = {}

    # For each switch, we map IP addresses to Entries
    self.arpTable = {}

    # This timer handles expiring stuff
    self._expire_timer = Timer(5, self._handle_expiration, recurring=True)

    core.listen_to_dependencies(self)

  def _handle_expiration (self):
    # Called by a timer so that we can remove old items.
    empty = []
    for k,v in self.lost_buffers.iteritems():
      dpid,ip = k

      for item in list(v):
        expires_at,buffer_id,in_port = item
        if expires_at < time.time():
          # This packet is old.  Tell this switch to drop it.
          v.remove(item)
          po = of.ofp_packet_out(buffer_id = buffer_id, in_port = in_port)
          core.openflow.sendToDPID(dpid, po)
      if len(v) == 0: empty.append(k)

    # Remove empty buffer bins
    for k in empty:
      del self.lost_buffers[k]

  def _send_lost_buffers (self, dpid, ipaddr, macaddr, port):
    """
    We may have "lost" buffers -- packets we got but didn't know
    where to send at the time.  We may know now.  Try and see.
    """
    if (dpid,ipaddr) in self.lost_buffers:
      # Yup!
      bucket = self.lost_buffers[(dpid,ipaddr)]
      del self.lost_buffers[(dpid,ipaddr)]
      log.debug("Sending %i buffered packets to %s from %s"
                % (len(bucket),ipaddr,dpid_to_str(dpid)))
      for _,buffer_id,in_port in bucket:
        po = of.ofp_packet_out(buffer_id=buffer_id,in_port=in_port)
        po.actions.append(of.ofp_action_dl_addr.set_dst(macaddr))
        po.actions.append(of.ofp_action_output(port = port))
        core.openflow.sendToDPID(dpid, po)

  def _handle_openflow_PacketIn (self, event):
    global cache, cacheCnt, dstCacheDict, nwHosts, cache1checker, cache2checker, cache1Down, cache2Down, cache1checkerCount, cache2checkerCount
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return

    if dpid not in self.arpTable:
      # New switch -- create an empty table
      self.arpTable[dpid] = {}
      for fake in self.fakeways:
        self.arpTable[dpid][IPAddr(fake)] = Entry(of.OFPP_NONE,
         dpid_to_mac(dpid))

    if packet.type == ethernet.LLDP_TYPE:
      # Ignore LLDP packets
      return

    if isinstance(packet.next, ipv4):
      log.debug("%i %i IP %s => %s", dpid,inport,
                packet.next.srcip,packet.next.dstip)

      # Send any waiting packets...
      self._send_lost_buffers(dpid, packet.next.srcip, packet.src, inport)

      # Learn or update port/MAC info
      if packet.next.srcip in self.arpTable[dpid]:
        if self.arpTable[dpid][packet.next.srcip] != (inport, packet.src):
          log.debug("%i %i RE-learned %s", dpid,inport,packet.next.srcip)
          if self.wide:
            # Make sure we don't have any entries with the old info...
            msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
            msg.match.nw_dst = packet.next.srcip
            msg.match.dl_type = ethernet.IP_TYPE
            event.connection.send(msg)
      else:
        log.debug("%i %i learned %s", dpid,inport,packet.next.srcip)
      self.arpTable[dpid][packet.next.srcip] = Entry(inport, packet.src)

      # Try to forward
      dstaddr = packet.next.dstip

      #print nwHosts

      #print dstCacheDict

      #print dstaddr
      #print type(dstaddr)

      #for p in nwHosts: log.info("Hosts - %s",p) # print hosts

      #for p in dstCacheDict: log.info("Cache entries - %s",p) # print map keys


      #HackAlert
      if dstaddr not in nwHosts:
        if dstaddr not in dstCacheDict:
          dstCacheDict[dstaddr] = IPAddr(cache[cacheCnt])
          log.info("assigning new cache for a new dstaddr: cache assigned :%s for dest addr:%s", dstCacheDict[dstaddr], packet.next.dstip)
          cacheCnt=1-cacheCnt
        dstaddr = IPAddr(dstCacheDict[dstaddr])

      if packet.next.dstip not in nwHosts:
        if dstaddr == IPAddr('192.168.1.4') and cache1Down:
          dstCacheDict[packet.next.dstip] = IPAddr('192.168.1.5')
          dstaddr = IPAddr('192.168.1.5')
          log.info("**********************cache 1 is down**********************")
          msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
          msg.match.nw_dst = packet.next.dstip
          msg.match.dl_type = ethernet.IP_TYPE
          #event.connection.send(msg)
        if dstaddr == IPAddr('192.168.1.5') and cache2Down:  
          dstCacheDict[packet.next.dstip] = IPAddr('192.168.1.4')
          dstaddr = IPAddr('192.168.1.4')
          log.info("**********************cache 2 is down**********************")
          msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
          msg.match.nw_dst = packet.next.dstip
          msg.match.dl_type = ethernet.IP_TYPE
          #event.connection.send(msg)
        if cache1Down and cache2Down:
          log.info("**********************cache 1 & 2 are down => reroute to router **********************")
          dstaddr = IPAddr('192.168.1.2')
          msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
          msg.match.nw_dst = packet.next.dstip
          msg.match.dl_type = ethernet.IP_TYPE
          #event.connection.send(msg)
        log.info("changing actual destination IP : %s to cache ip : %s", packet.next.dstip, dstaddr)

      # if dstaddr in dstCacheDict:
      #   dstaddr = dstCacheDict[dstaddr]
      # elif dstaddr not in nwHosts:
      #   dstCacheDict[dstaddr] = cache[cacheCnt]
      #   cacheCnt=1-cacheCnt
      #   dstaddr = dstCacheDict[dstaddr]


      if dstaddr in self.arpTable[dpid]:
        # We have info about what port to send it out on...

        prt = self.arpTable[dpid][dstaddr].port
        mac = self.arpTable[dpid][dstaddr].mac
        if prt == inport:
          log.warning("%i %i not sending packet for %s back out of the "
                      "input port" % (dpid, inport, dstaddr))
        else:
          log.info("For packet in on switch %i via port %i installing flow for source %s => destination %s to go on out port %i in the switch %i"
                    % (dpid, inport, packet.next.srcip, packet.next.dstip, prt, dpid))

          actions = []
          actions.append(of.ofp_action_dl_addr.set_dst(mac))
          actions.append(of.ofp_action_nw_addr.set_dst(dstaddr))
          #actions.append(of.ofp_action_tp_port.set_dst(80))
          actions.append(of.ofp_action_output(port = prt))
          
          #if self.wide:
          match = of.ofp_match(dl_type = ethernet.IP_TYPE, in_port=inport, nw_src=packet.next.srcip, nw_dst = packet.next.dstip) #mention the actual destination IP
          #else:
          #  match = of.ofp_match.from_packet(packet, inport)

          msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=FLOW_IDLE_TIMEOUT,
                                hard_timeout=of.OFP_FLOW_PERMANENT,
                                buffer_id=event.ofp.buffer_id,
                                actions=actions,
                                match=match)
          event.connection.send(msg.pack())

          ##########################################################################################

          actions = []
          #actions.append(of.ofp_action_dl_addr.set_dst(mac))
          actions.append(of.ofp_action_nw_addr.set_src(packet.next.dstip))
          #actions.append(of.ofp_action_tp_port.set_dst(8080))
          actions.append(of.ofp_action_output(port = inport))
          
          #if self.wide:
          match = of.ofp_match(dl_type = ethernet.IP_TYPE, in_port=prt, nw_src=dstaddr, nw_dst = packet.next.srcip) #mention the actual destination IP
          #else:
          #  match = of.ofp_match.from_packet(packet, inport)

          msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=FLOW_IDLE_TIMEOUT,
                                hard_timeout=of.OFP_FLOW_PERMANENT,
                                buffer_id=of.NO_BUFFER,
                                actions=actions,
                                match=match)
          event.connection.send(msg.pack())

      elif self.arp_for_unknowns:
        # We don't know this destination.
        # First, we track this buffer so that we can try to resend it later
        # if we learn the destination, second we ARP for the destination,
        # which should ultimately result in it responding and us learning
        # where it is

        # Add to tracked buffers
        if (dpid,dstaddr) not in self.lost_buffers:
          self.lost_buffers[(dpid,dstaddr)] = []
        bucket = self.lost_buffers[(dpid,dstaddr)]
        entry = (time.time() + MAX_BUFFER_TIME,event.ofp.buffer_id,inport)
        bucket.append(entry)
        while len(bucket) > MAX_BUFFERED_PER_IP: del bucket[0]

        # Expire things from our outstanding ARP list...
        self.outstanding_arps = {k:v for k,v in
         self.outstanding_arps.iteritems() if v > time.time()}

        # Check if we've already ARPed recently
        if (dpid,dstaddr) in self.outstanding_arps:
          # Oop, we've already done this one recently.
          return

        # And ARP...
        self.outstanding_arps[(dpid,dstaddr)] = time.time() + 4

        r = arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.hwlen = 6
        r.protolen = r.protolen
        r.opcode = r.REQUEST
        r.hwdst = ETHER_BROADCAST
        r.protodst = dstaddr
        r.hwsrc = packet.src
        r.protosrc = packet.next.srcip
        e = ethernet(type=ethernet.ARP_TYPE, src=packet.src,
                     dst=ETHER_BROADCAST)
        e.set_payload(r)
        log.debug("%i %i ARPing for %s on behalf of %s" % (dpid, inport,
         r.protodst, r.protosrc))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.in_port = inport
        event.connection.send(msg)

    elif isinstance(packet.next, arp):
      a = packet.next
      log.debug("%i %i ARP %s %s => %s", dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), a.protosrc, a.protodst)

      dstaddr = a.protodst# dest IP
      spoofingmac = False

      #HackAlert
      if dstaddr not in nwHosts:
        if dstaddr not in dstCacheDict:
          dstCacheDict[dstaddr] = IPAddr(cache[cacheCnt])
          log.info("assigning cache for a new dstaddr in ARP: cache:%s, dstaddr:%s", dstCacheDict[dstaddr], a.protodst)
          cacheCnt=1-cacheCnt
        dstaddr = IPAddr(dstCacheDict[dstaddr])
      #check cache status
      if a.protodst not in nwHosts:
        if dstaddr == IPAddr('192.168.1.4') and cache1Down:
          dstCacheDict[a.protodst] = IPAddr('192.168.1.5')
          dstaddr = IPAddr('192.168.1.5')
          log.debug("********************** cache 1 is down **********************")
          msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
          msg.match.nw_dst = a.protodst
          msg.match.nw_src = a.protosrc
          msg.match.dl_type = ethernet.IP_TYPE
          #event.connection.send(msg)
        if dstaddr == IPAddr('192.168.1.5') and cache2Down:  
          dstCacheDict[a.protodst] = IPAddr('192.168.1.4')
          dstaddr = IPAddr('192.168.1.4')
          msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
          msg.match.nw_dst = a.protodst
          msg.match.nw_src = a.protosrc
          msg.match.dl_type = ethernet.IP_TYPE
          #event.connection.send(msg)
          log.debug("********************** cache 2 is down **********************")
        if cache1Down and cache2Down:
          log.debug("********************** cache 1 & 2 are down => reroute to router **********************")
          dstaddr = IPAddr('192.168.1.2') # redirect to router
          msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
          msg.match.nw_dst = a.protodst
          msg.match.nw_src = a.protosrc
          msg.match.dl_type = ethernet.IP_TYPE
          #event.connection.send(msg)
        log.info("changing destination IP to cache ip in ARP: cache:%s, dstaddr:%s", dstaddr, a.protodst)

      if dstaddr != a.protodst:
        spoofingmac = True

      if a.prototype == arp.PROTO_TYPE_IP:
        if a.hwtype == arp.HW_TYPE_ETHERNET:
          if a.protosrc != 0:

            if str(a.protosrc) == '192.168.1.4':
              cache1checker = False
              cache1Down = False
              cache1checkerCount = 10
                        
            if str(a.protosrc) == '192.168.1.5':
              cache2checker = False
              cache2Down = False
              cache2checkerCount = 10

            # Learn or update port/MAC info
            if a.protosrc in self.arpTable[dpid]:
              if self.arpTable[dpid][a.protosrc] != (inport, packet.src):
                log.debug("%i %i RE-learned %s", dpid,inport,a.protosrc)
                if self.wide:
                  # Make sure we don't have any entries with the old info...
                  msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
                  msg.match.dl_type = ethernet.IP_TYPE
                  msg.match.nw_dst = a.protosrc
                  event.connection.send(msg)
            else:
              log.debug("%i %i learned %s", dpid,inport,a.protosrc)
            self.arpTable[dpid][a.protosrc] = Entry(inport, packet.src)

            # Send any waiting packets...
            self._send_lost_buffers(dpid, a.protosrc, packet.src, inport)

            
            # start evaluating ARP requests
            if a.opcode == arp.REQUEST:
              # Maybe we can answer

              if dstaddr in self.arpTable[dpid]:
                # We have an answer...

                if not self.arpTable[dpid][dstaddr].isExpired():
                  # .. and it's relatively current, so we'll reply ourselves

                  if str(dstaddr) in cache and str(dstaddr) == '192.168.1.4':
                    cache1checker = False
                    cache1Down = False
                    cache1checkerCount = 10
                  
                  if str(dstaddr) in cache and str(dstaddr) == '192.168.1.5':
                    cache2checker = False
                    cache2Down = False
                    cache2checkerCount = 10

                  r = arp()
                  r.hwtype = a.hwtype
                  r.prototype = a.prototype
                  r.hwlen = a.hwlen
                  r.protolen = a.protolen
                  r.opcode = arp.REPLY
                  r.hwdst = a.hwsrc
                  r.protodst = a.protosrc
                  r.protosrc = a.protodst #The guy who is supposed to reply
                  r.hwsrc = self.arpTable[dpid][dstaddr].mac # mac of guy who is supposed to reply
                  e = ethernet(type=packet.type, src=dpid_to_mac(dpid),
                               dst=a.hwsrc)
                  e.set_payload(r)
                  
                  ######################################################################################################################
                  if spoofingmac:
                      log.info("Switch %i on port %i answering ARP for %s to %s with the mac of the cache %s switch %s" % (dpid, inport,a.protodst,a.protosrc, r.hwsrc, dpid_to_mac(dpid)))
                  else:
                      log.info("Switch %i on port %i answering ARP for %s to %s with the mac %s switch %s" % (dpid, inport,a.protodst,a.protosrc, r.hwsrc, dpid_to_mac(dpid)))
                  ######################################################################################################################         
                  
                  msg = of.ofp_packet_out()
                  msg.data = e.pack()
                  msg.actions.append(of.ofp_action_output(port =
                                                          of.OFPP_IN_PORT))
                  msg.in_port = inport
                  event.connection.send(msg)
                  return

                else:    

                  if str(dstaddr) in cache and str(dstaddr) == '192.168.1.4': #entry is expired  -set checker is true
                    if cache1checker:
                      cache1Down = True
                      log.debug("################# Cache1 is down #################")
                    else:
                      if cache1checkerCount == 0:
                        cache1checker = True
                      else:
                        cache1checkerCount=cache1checkerCount-1
                  
                  if str(dstaddr) in cache and str(dstaddr) == '192.168.1.5':
                    if cache2checker:
                      cache2Down = True
                      log.debug("################# Cache2 is down #################")
                    else:
                      if cache2checkerCount == 0:
                        cache2checker = True
                      else:
                        cache2checkerCount=cache2checkerCount-1
      # Didn't know how to answer or otherwise handle this ARP, so just flood it
      #log.debug("%i %i flooding ARP %s %s => %s" % (dpid, inport, {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode, 'op:%i' % (a.opcode,)), a.protosrc, a.protodst))

      if a.opcode == arp.REQUEST:
        r = arp()
        r.hwtype = a.hwtype
        r.prototype = a.prototype
        r.hwlen = a.hwlen
        r.protolen = a.protolen
        r.opcode = a.opcode
        r.hwdst = ETHER_BROADCAST
        r.protodst = dstaddr
        r.hwsrc = a.hwsrc
        r.protosrc = a.protosrc
        e = ethernet(type=packet.type, src=packet.src,
                     dst=ETHER_BROADCAST)
        e.set_payload(r)
        log.info("Switch %i %i Flooding ARP for %s on behalf of %s" % (dpid, inport, r.protodst, r.protosrc))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.in_port = inport
        event.connection.send(msg)

        if cache1Down and dstaddr != IPAddr('192.168.1.4'):
          r = arp()
          r.hwtype = a.hwtype
          r.prototype = a.prototype
          r.hwlen = a.hwlen
          r.protolen = a.protolen
          r.opcode = a.opcode
          r.hwdst = ETHER_BROADCAST
          r.protodst = IPAddr('192.168.1.4')
          r.hwsrc = a.hwsrc
          r.protosrc = a.protosrc
          e = ethernet(type=packet.type, src=packet.src,
                       dst=ETHER_BROADCAST)
          e.set_payload(r)
          log.debug("Checking if cache up Switch %i %i Flooding ARP for %s on behalf of %s" % (dpid, inport, r.protodst, r.protosrc))
          msg = of.ofp_packet_out()
          msg.data = e.pack()
          msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
          msg.in_port = inport
          event.connection.send(msg)

        if cache2Down and dstaddr != IPAddr('192.168.1.5'):
          r = arp()
          r.hwtype = a.hwtype
          r.prototype = a.prototype
          r.hwlen = a.hwlen
          r.protolen = a.protolen
          r.opcode = a.opcode
          r.hwdst = ETHER_BROADCAST
          r.protodst = IPAddr('192.168.1.5')
          r.hwsrc = a.hwsrc
          r.protosrc = a.protosrc
          e = ethernet(type=packet.type, src=packet.src,
                       dst=ETHER_BROADCAST)
          e.set_payload(r)
          log.debug("Checking if cache up Switch %i %i Flooding ARP for %s on behalf of %s" % (dpid, inport, r.protodst, r.protosrc))
          msg = of.ofp_packet_out()
          msg.data = e.pack()
          msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
          msg.in_port = inport
          event.connection.send(msg)

      else:
        msg = of.ofp_packet_out(in_port = inport, data = event.ofp,
            action = of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(msg)
      


def launch (fakeways="", arp_for_unknowns=None, wide=False):
  fakeways = fakeways.replace(","," ").split()
  fakeways = [IPAddr(x) for x in fakeways]
  if arp_for_unknowns is None:
    arp_for_unknowns = len(fakeways) > 0
  else:
    arp_for_unknowns = str_to_bool(arp_for_unknowns)
  core.registerNew(l3_switch, fakeways, arp_for_unknowns, wide)