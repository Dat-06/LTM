package vn.edu.packet;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import java.io.*;
import java.net.*;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;
class ProjectTest {
 @Test void framesCanBeConcatenated()throws Exception{var bytes=new ByteArrayOutputStream();var out=new DataOutputStream(bytes);Wire.write(out,Wire.message("STATUS","Tiếng Việt"));Wire.write(out,Wire.message("STOP",""));var in=new DataInputStream(new ByteArrayInputStream(bytes.toByteArray()));assertEquals("Tiếng Việt",Wire.read(in).get("text").getAsString());assertEquals("STOP",Wire.read(in).get("type").getAsString());}
 @Test void rejectsOversizedAndTruncatedFrames()throws Exception{var b=new ByteArrayOutputStream();var o=new DataOutputStream(b);o.writeInt(Wire.MAX_FRAME+1);assertThrows(IOException.class,()->Wire.read(new DataInputStream(new ByteArrayInputStream(b.toByteArray()))));b.reset();o.writeInt(100);o.writeByte(1);assertThrows(EOFException.class,()->Wire.read(new DataInputStream(new ByteArrayInputStream(b.toByteArray()))));}
 @Test void parsesIpv4Udp()throws Exception{
  var src=(Inet4Address)InetAddress.getByName("192.0.2.1");var dst=(Inet4Address)InetAddress.getByName("198.51.100.1");
  var udp=new UdpPacket.Builder().srcPort(UdpPort.getInstance((short)12345)).dstPort(UdpPort.DOMAIN).srcAddr(src).dstAddr(dst).correctChecksumAtBuild(true).correctLengthAtBuild(true).payloadBuilder(new UnknownPacket.Builder().rawData(new byte[]{1,2,3}));
  var ip=new IpV4Packet.Builder().version(IpVersion.IPV4).tos(IpV4Rfc791Tos.newInstance((byte)0)).ttl((byte)64).protocol(IpNumber.UDP).srcAddr(src).dstAddr(dst).payloadBuilder(udp).correctChecksumAtBuild(true).correctLengthAtBuild(true).build();
  PacketInfo p=Analyzer.parse(ip,1,Instant.EPOCH);assertEquals("UDP",p.protocol());assertEquals(12345,p.sourcePort());assertEquals(53,p.destinationPort());assertEquals("192.0.2.1",p.source());assertEquals(ip.length(),p.length());assertFalse(p.hex().isBlank());
 }
 @Test void parsesTcpFlagsAndPorts()throws Exception{
  var src=(Inet4Address)InetAddress.getByName("192.0.2.3");var dst=(Inet4Address)InetAddress.getByName("198.51.100.4");
  var tcp=new TcpPacket.Builder().srcPort(TcpPort.getInstance((short)50000)).dstPort(TcpPort.HTTPS).srcAddr(src).dstAddr(dst).sequenceNumber(123).acknowledgmentNumber(0).syn(true).window((short)65535).correctChecksumAtBuild(true).correctLengthAtBuild(true).paddingAtBuild(true);
  var ip=new IpV4Packet.Builder().version(IpVersion.IPV4).tos(IpV4Rfc791Tos.newInstance((byte)0)).ttl((byte)64).protocol(IpNumber.TCP).srcAddr(src).dstAddr(dst).payloadBuilder(tcp).correctChecksumAtBuild(true).correctLengthAtBuild(true).build();
  var parsed=Analyzer.parse(ip,2,Instant.EPOCH);assertEquals("TCP",parsed.protocol());assertEquals(50000,parsed.sourcePort());assertEquals(443,parsed.destinationPort());assertTrue(parsed.info().contains("SYN"));assertTrue(parsed.info().contains("123"));
 }
 @Test void demoCommandsUseRealTcp()throws Exception{try(ServerSocket listener=new ServerSocket(0,1,InetAddress.getLoopbackAddress());Socket client=new Socket("127.0.0.1",listener.getLocalPort());Socket accepted=listener.accept()){
  client.setSoTimeout(3000);Thread t=new Thread(()->new ServerMain.Session(accepted,true).run());t.setDaemon(true);t.start();var in=new DataInputStream(client.getInputStream());var out=new DataOutputStream(client.getOutputStream());assertEquals("STATUS",Wire.read(in).get("type").getAsString());Wire.write(out,Wire.message("LIST",""));assertEquals("demo0",Wire.read(in).getAsJsonArray("devices").get(0).getAsJsonObject().get("name").getAsString());var start=Wire.message("START","");start.addProperty("device","demo0");Wire.write(out,start);boolean got=false;for(int i=0;i<5;i++){var m=Wire.read(in);if(m.get("type").getAsString().equals("PACKET")){assertTrue(m.getAsJsonObject("packet").get("demo").getAsBoolean());got=true;break;}}assertTrue(got);Wire.write(out,Wire.message("STOP",""));boolean stopped=false;for(int i=0;i<10;i++){var m=Wire.read(in);if(m.has("text")&&m.get("text").getAsString().startsWith("STOPPED")){stopped=true;break;}}assertTrue(stopped);
 }}
}
