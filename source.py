
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""



from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.controller import mac_to_port
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp



#Controller Application Registration and Initialization

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}


#Helper Method for Adding Flow Entries
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        match=match

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=priority,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

        datapath.send_msg(mod)



#Packet-In Event Handler
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.in_port

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src


#Learning the MAC Address and Associated Port

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in DPID=%s S_MAC=%s D_MAC=%s IN_PORT=%s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port


#MAC-to-Port Lookup and Packet Destination

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto

                 # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_src=srcip, nw_dst=dstip, nw_proto=protocol)
                    self.logger.info("packet in dpid=%s in_port=%s src_mac=%s dst_mac=%s  src_ip=%s  dst_ip=%s protocol=%s", dpid, in_port, src, dst, srcip, dstip, protocol)

                #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_src=srcip, nw_dst=dstip, nw_proto=protocol, tp_src=t.src_port, tp_dst=t.dst_port,)
                    self.logger.info("packet in dpid=%s in_port=%s src_mac=%s dst_mac=%s  src_ip=%s  dst_ip=%s protocol=%s t_s_port=%s t_d_port=%s", dpid, in_port, src, dst, srcip, dstip, protocol,t.src_port,t.dst_port)

                #  If UDP Protocol
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_src=srcip, nw_dst=dstip, nw_proto=protocol, tp_src=u.src_port, tp_dst=u.dst_port,) 
                    self.logger.info("packet in dpid=%s in_port=%s src_mac=%s dst_mac=%s  src_ip=%s  dst_ip=%s protocol=%s u_s_port=%s u_d_port=%s", dpid, in_port, src, dst, srcip, dstip, protocol,u.src_port,u.dst_port)           

                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)


#Forwarding the Packet Sent to the Controller
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
