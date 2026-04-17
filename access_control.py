from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

BLOCKED_IP = "10.0.0.3"

def _handle_ConnectionUp(event):
    log.info("Switch connected")

def _handle_PacketIn(event):
    packet = event.parsed

    ip_packet = packet.find('ipv4')

    if ip_packet:
        src_ip = str(ip_packet.srcip)
        dst_ip = str(ip_packet.dstip)

        if dst_ip == BLOCKED_IP:
            log.info(f"BLOCKED: {src_ip} -> {dst_ip}")
            return

        else:
            log.info(f"ALLOWED: {src_ip} -> {dst_ip}")

    msg = of.ofp_packet_out()
    msg.data = event.ofp
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    event.connection.send(msg)

def launch():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
