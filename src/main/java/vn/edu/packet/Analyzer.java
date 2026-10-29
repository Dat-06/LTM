package vn.edu.packet;
import org.pcap4j.packet.*;
import java.time.Instant;
import java.util.HexFormat;
public final class Analyzer {
 private Analyzer(){}
 public static PacketInfo parse(Packet p,long number,Instant time){
  String src="",dst="",protocol="OTHER",info="";int sp=-1,dp=-1;
  EthernetPacket eth=p.get(EthernetPacket.class);
  if(eth!=null){src=eth.getHeader().getSrcAddr().toString();dst=eth.getHeader().getDstAddr().toString();protocol="ETHERNET";}
  IpV4Packet ip=p.get(IpV4Packet.class);IpV6Packet ip6=p.get(IpV6Packet.class);
  if(ip!=null){src=ip.getHeader().getSrcAddr().getHostAddress();dst=ip.getHeader().getDstAddr().getHostAddress();protocol="IPv4";info="TTL="+ip.getHeader().getTtlAsInt();}
  else if(ip6!=null){src=ip6.getHeader().getSrcAddr().getHostAddress();dst=ip6.getHeader().getDstAddr().getHostAddress();protocol="IPv6";}
  TcpPacket tcp=p.get(TcpPacket.class);UdpPacket udp=p.get(UdpPacket.class);
  if(tcp!=null){var h=tcp.getHeader();protocol="TCP";sp=h.getSrcPort().valueAsInt();dp=h.getDstPort().valueAsInt();info="Seq="+h.getSequenceNumberAsLong()+" Ack="+h.getAcknowledgmentNumberAsLong()+" "+(h.getSyn()?"SYN ":"")+(h.getAck()?"ACK ":"")+(h.getFin()?"FIN ":"")+(h.getRst()?"RST ":"");}
  else if(udp!=null){protocol="UDP";sp=udp.getHeader().getSrcPort().valueAsInt();dp=udp.getHeader().getDstPort().valueAsInt();info="UDP length="+udp.getHeader().getLengthAsInt();}
  else if(p.contains(IcmpV4CommonPacket.class)){protocol="ICMP";info=p.get(IcmpV4CommonPacket.class).getHeader().toString();}
  else if(p.contains(IcmpV6CommonPacket.class)){protocol="ICMPv6";}
  else if(p.contains(ArpPacket.class)){protocol="ARP";var h=p.get(ArpPacket.class).getHeader();src=h.getSrcProtocolAddr().getHostAddress();dst=h.getDstProtocolAddr().getHostAddress();info=h.getOperation().toString();}
  byte[] raw=p.getRawData();StringBuilder hex=new StringBuilder();
  for(int i=0;i<raw.length;i+=16){hex.append(String.format("%04X  ",i));int end=Math.min(i+16,raw.length);hex.append(HexFormat.ofDelimiter(" ").withUpperCase().formatHex(raw,i,end)).append('\n');}
  return new PacketInfo(number,time.toString(),src,dst,protocol,sp,dp,raw.length,info,p.toString(),hex.toString(),false);
 }
}
