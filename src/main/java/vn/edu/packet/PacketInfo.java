package vn.edu.packet;
public record PacketInfo(long number,String time,String source,String destination,
 String protocol,int sourcePort,int destinationPort,int length,String info,String detail,String hex,boolean demo) {}
