package vn.edu.packet;
import com.google.gson.*;
import org.pcap4j.core.*;
import java.io.*;
import java.net.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
/** One independent capture session per TCP client. Default bind is loopback. */
public final class ServerMain {
 public static void main(String[] args)throws Exception {
  String bind=args.length>0?args[0]:"127.0.0.1";int port=args.length>1?Integer.parseInt(args[1]):9000;
  boolean demo=Arrays.asList(args).contains("--demo");
  try(ServerSocket server=new ServerSocket()){server.bind(new InetSocketAddress(bind,port));
   System.out.println("Packet Server "+bind+":"+port+" | "+(demo?"DEMO - synthetic data":"LIVE capture"));
   var clients=new Semaphore(4);
   while(true){Socket s=server.accept();if(!clients.tryAcquire()){s.close();continue;}
    Thread t=new Thread(()->{try{new Session(s,demo).run();}finally{clients.release();}},"client-session");t.start();}
  }
 }
 static final class Session {
  final Socket socket;final boolean demo;final AtomicBoolean capturing=new AtomicBoolean();
  final ArrayBlockingQueue<JsonObject> outbound=new ArrayBlockingQueue<>(512);
  volatile boolean closed;Thread captureThread;long sequence;long dropped;
  Session(Socket s,boolean d){socket=s;demo=d;}
  void send(JsonObject o){if(!outbound.offer(o)){dropped++;}}
  void status(String text){send(Wire.message("STATUS",text));}
  void run(){
   try(socket){socket.setTcpNoDelay(true);
    Thread writer=new Thread(()->{try{var out=new DataOutputStream(socket.getOutputStream());while(!closed){JsonObject o=outbound.take();Wire.write(out,o);}}catch(Exception e){close();}},"tcp-writer");writer.setDaemon(true);writer.start();
    var in=new DataInputStream(socket.getInputStream());status(demo?"Connected: DEMO (synthetic packets)":"Connected: LIVE");
    try{while(!closed){JsonObject cmd=Wire.read(in);try{switch(Wire.str(cmd,"type","")){
     case "LIST"->list();
     case "START"->start(Wire.str(cmd,"device",""),Wire.str(cmd,"filter",""));
     case "STOP"->stop();
     default->send(Wire.message("ERROR","Unknown command"));
    }}catch(Exception|LinkageError e){send(Wire.message("ERROR",e.toString()+" | Check Npcap/libpcap and permissions."));}}}
    finally{close();writer.interrupt();}
   }catch(IOException e){close();System.out.println("Client disconnected: "+e.getMessage());}
  }
  void list()throws PcapNativeException {
   JsonArray a=new JsonArray();
   if(demo){JsonObject d=new JsonObject();d.addProperty("name","demo0");d.addProperty("label","DEMO - synthetic network");a.add(d);}
   else{List<PcapNetworkInterface> devices=Pcaps.findAllDevs();if(devices!=null)for(var n:devices){JsonObject d=new JsonObject();d.addProperty("name",n.getName());d.addProperty("label",n.getName()+" | "+n.getDescription()+" | "+n.getAddresses());a.add(d);}}
   JsonObject m=new JsonObject();m.addProperty("type","DEVICES");m.add("devices",a);send(m);
  }
  synchronized void start(String device,String filter)throws Exception {
   if(capturing.get()||(captureThread!=null&&captureThread.isAlive()))throw new IOException("Capture already running/stopping");
   if(device.isBlank())throw new IOException("Choose an interface first");
   if(demo&&!filter.isBlank())throw new IOException("DEMO does not execute BPF. Clear BPF or use LIVE.");
   capturing.set(true);
   captureThread=new Thread(()->{
    try{
     if(demo){status("STARTED DEMO");while(capturing.get()&&!closed){long n=++sequence;String proto=n%3==0?"ICMP":n%3==1?"TCP":"UDP";PacketInfo p=new PacketInfo(n,Instant.now().toString(),"192.0.2.10","198.51.100.20",proto,proto.equals("ICMP")?-1:50000,proto.equals("TCP")?443:proto.equals("UDP")?53:-1,64,"DEMO synthetic "+proto,"Synthetic sample. No real traffic captured.","44 45 4D 4F",true);packet(p);Thread.sleep(150);}}
     else{
      PcapNetworkInterface nif=Pcaps.getDevByName(device);if(nif==null)throw new IOException("Interface not found");
      try(PcapHandle h=nif.openLive(65536,PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS,100)){
       if(!filter.isBlank())h.setFilter(filter,BpfProgram.BpfCompileMode.OPTIMIZE);
       status("STARTED LIVE");
       while(capturing.get()&&!closed){try{var p=h.getNextPacketEx();if(capturing.get())packet(Analyzer.parse(p,++sequence,h.getTimestamp().toInstant()));}catch(java.util.concurrent.TimeoutException ignored){}}
      }
     }
    }catch(InterruptedException e){Thread.currentThread().interrupt();}
    catch(Exception|LinkageError e){send(Wire.message("ERROR",e.toString()+" | Install Npcap/libpcap; check capture permissions and BPF."));}
    finally{capturing.set(false);status("STOPPED | queue dropped="+dropped);}
   },"capture-worker");captureThread.setDaemon(true);captureThread.start();
  }
  void packet(PacketInfo p){JsonObject m=new JsonObject();m.addProperty("type","PACKET");m.add("packet",new Gson().toJsonTree(p));send(m);}
  synchronized void stop(){capturing.set(false);if(demo&&captureThread!=null)captureThread.interrupt();status("Stop requested");}
  void close(){closed=true;capturing.set(false);if(demo&&captureThread!=null)captureThread.interrupt();try{socket.close();}catch(IOException ignored){}}
 }
}
