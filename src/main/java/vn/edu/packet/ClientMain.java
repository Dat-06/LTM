package vn.edu.packet;
import com.google.gson.*;
import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
public final class ClientMain extends JFrame {
 final JTextField host=new JTextField("127.0.0.1",10),port=new JTextField("9000",5),bpf=new JTextField(22),search=new JTextField(15);
 final JComboBox<Device> devices=new JComboBox<>();
 final JComboBox<String> protocol=new JComboBox<>(new String[]{"ALL","TCP","UDP","ICMP","ICMPv6","ARP","IPv4","IPv6","OTHER"});
 final JButton connect=new JButton("Kết nối"),disconnect=new JButton("Ngắt kết nối"),list=new JButton("Tải card mạng"),start=new JButton("Bắt đầu"),stop=new JButton("Dừng");
 final JLabel state=new JLabel("Chưa kết nối"),stats=new JLabel("Chưa có gói tin");
 final DefaultTableModel model=new DefaultTableModel(new String[]{"STT","Thời gian","IP/MAC nguồn","IP/MAC đích","Giao thức","Cổng nguồn","Cổng đích","Byte","Thông tin"},0){public boolean isCellEditable(int r,int c){return false;}};
 final JTable table=new JTable(model);final JTextArea detail=new JTextArea();
 final List<PacketInfo> packets=new ArrayList<>();final Map<String,Long> counts=new TreeMap<>();
 final ArrayBlockingQueue<PacketInfo> pending=new ArrayBlockingQueue<>(2000);
 final ExecutorService io=Executors.newSingleThreadExecutor(r->{Thread t=new Thread(r,"client-io");t.setDaemon(true);return t;});
 final ExecutorService writes=Executors.newSingleThreadExecutor(r->{Thread t=new Thread(r,"client-writer");t.setDaemon(true);return t;});
 final javax.swing.Timer timer=new javax.swing.Timer(150,e->drain());
 volatile Socket socket;volatile DataOutputStream out;volatile boolean connecting;long totalBytes,totalPackets;final java.util.concurrent.atomic.AtomicLong uiDropped=new java.util.concurrent.atomic.AtomicLong();volatile long generation;
 record Device(String name,String label){public String toString(){return label;}}
 public static void main(String[] a){SwingUtilities.invokeLater(()->{try{UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());}catch(Exception ignored){}new ClientMain().setVisible(true);});}
 ClientMain(){
  super("Đề tài 85 | Phân tích gói tin TCP/IP");setSize(1300,800);setMinimumSize(new Dimension(950,600));setLocationRelativeTo(null);setDefaultCloseOperation(DISPOSE_ON_CLOSE);
  JPanel top=new JPanel();top.setLayout(new BoxLayout(top,BoxLayout.Y_AXIS));
  JPanel connection=new JPanel(new FlowLayout(FlowLayout.LEFT));connection.add(new JLabel("Server:"));connection.add(host);connection.add(new JLabel("Cổng:"));connection.add(port);connection.add(connect);connection.add(disconnect);connection.add(list);top.add(connection);
  JPanel capture=new JPanel(new FlowLayout(FlowLayout.LEFT));devices.setPreferredSize(new Dimension(550,27));capture.add(new JLabel("Card mạng:"));capture.add(devices);capture.add(start);capture.add(stop);top.add(capture);
  JPanel filter=new JPanel(new FlowLayout(FlowLayout.LEFT));filter.add(new JLabel("BPF (trước khi bắt):"));filter.add(bpf);filter.add(new JLabel("Lọc hiển thị:"));filter.add(protocol);filter.add(search);JButton apply=new JButton("Áp dụng"),clear=new JButton("Xóa bảng"),csv=new JButton("Xuất CSV");filter.add(apply);filter.add(clear);filter.add(csv);top.add(filter);
  table.setAutoCreateRowSorter(true);table.setRowHeight(24);detail.setEditable(false);detail.setFont(new Font(Font.MONOSPACED,Font.PLAIN,13));
  JSplitPane split=new JSplitPane(JSplitPane.VERTICAL_SPLIT,new JScrollPane(table),new JScrollPane(detail));split.setResizeWeight(.65);
  JPanel bottom=new JPanel(new GridLayout(2,1));bottom.add(state);bottom.add(stats);add(top,BorderLayout.NORTH);add(split);add(bottom,BorderLayout.SOUTH);
  setConnected(false);connect.addActionListener(e->connect());disconnect.addActionListener(e->disconnect());list.addActionListener(e->command("LIST"));
  start.addActionListener(e->{Device d=(Device)devices.getSelectedItem();if(d==null){error("Chọn card mạng trước.");return;}JsonObject m=Wire.message("START","");m.addProperty("device",d.name());m.addProperty("filter",bpf.getText().trim());send(m);});stop.addActionListener(e->command("STOP"));
  apply.addActionListener(e->filter());search.addActionListener(e->filter());protocol.addActionListener(e->filter());clear.addActionListener(e->{packets.clear();model.setRowCount(0);detail.setText("");counts.clear();totalBytes=totalPackets=0;uiDropped.set(0);pending.clear();updateStats();});csv.addActionListener(e->export());
  table.getSelectionModel().addListSelectionListener(e->{int r=table.getSelectedRow();if(r>=0){PacketInfo p=packets.get(table.convertRowIndexToModel(r));detail.setText((p.demo()?"*** DEMO - DỮ LIỆU MÔ PHỎNG ***\n":"")+p.detail()+"\n\nHEX\n"+p.hex());detail.setCaretPosition(0);}});
  timer.start();addWindowListener(new WindowAdapter(){public void windowClosed(WindowEvent e){disconnect();timer.stop();io.shutdownNow();writes.shutdownNow();}});
 }
 void setConnected(boolean c){connect.setEnabled(!c&&!connecting);disconnect.setEnabled(c);list.setEnabled(c);start.setEnabled(c);stop.setEnabled(c);host.setEnabled(!c);port.setEnabled(!c);}
 void connect(){
  final int p;try{p=Integer.parseInt(port.getText().trim());if(p<1||p>65535)throw new NumberFormatException();}catch(NumberFormatException e){error("Cổng phải từ 1 đến 65535.");return;}
  String address=host.getText().trim();connecting=true;setConnected(false);state.setText("Đang kết nối...");long id=++generation;
  io.execute(()->{Socket s=new Socket();try{s.connect(new InetSocketAddress(address,p),5000);s.setTcpNoDelay(true);var output=new DataOutputStream(s.getOutputStream());var input=new DataInputStream(s.getInputStream());
   SwingUtilities.invokeLater(()->{if(id!=generation){try{s.close();}catch(IOException ignored){}return;}socket=s;out=output;connecting=false;setConnected(true);command("LIST");});
   while(!s.isClosed()){JsonObject m=Wire.read(input);if(Wire.str(m,"type","").equals("PACKET")){PacketInfo packet=new Gson().fromJson(m.get("packet"),PacketInfo.class);if(id==generation&&!pending.offer(packet))uiDropped.incrementAndGet();}else SwingUtilities.invokeLater(()->{if(id==generation)handle(m);});}
  }catch(Exception e){SwingUtilities.invokeLater(()->{if(id==generation)state.setText("Mất kết nối: "+e.getMessage());});}
  finally{try{s.close();}catch(IOException ignored){}SwingUtilities.invokeLater(()->{if(id==generation){socket=null;out=null;connecting=false;setConnected(false);}});}});
 }
 void disconnect(){generation++;Socket s=socket;socket=null;out=null;connecting=false;if(s!=null)try{s.close();}catch(IOException ignored){}pending.clear();setConnected(false);state.setText("Đã ngắt kết nối");}
 void send(JsonObject m){DataOutputStream o=out;if(o==null)return;writes.execute(()->{try{Wire.write(o,m);}catch(IOException e){SwingUtilities.invokeLater(()->error("Không gửi được: "+e.getMessage()));}});}
 void command(String type){send(Wire.message(type,""));}
 void handle(JsonObject m){switch(Wire.str(m,"type","")){
  case "DEVICES"->{devices.removeAllItems();for(var x:m.getAsJsonArray("devices")){var d=x.getAsJsonObject();devices.addItem(new Device(d.get("name").getAsString(),d.get("label").getAsString()));}if(devices.getItemCount()==0)state.setText("Không tìm thấy card mạng");}
  case "PACKET"->{if(!pending.offer(new Gson().fromJson(m.get("packet"),PacketInfo.class)))uiDropped.incrementAndGet();}
  case "ERROR"->error(Wire.str(m,"text","Error"));
  case "STATUS"->state.setText(Wire.str(m,"text",""));
 }}
 void drain(){for(int i=0;i<300;i++){PacketInfo p=pending.poll();if(p==null)break;totalPackets++;totalBytes+=p.length();counts.merge(p.protocol(),1L,Long::sum);if(packets.size()==5000){packets.remove(0);model.removeRow(0);}packets.add(p);model.addRow(new Object[]{p.number(),p.time(),p.source(),p.destination(),p.protocol(),p.sourcePort()<0?"":p.sourcePort(),p.destinationPort()<0?"":p.destinationPort(),p.length(),p.info()});}updateStats();}
 void updateStats(){stats.setText("Đã nhận: "+totalPackets+" gói | "+totalBytes+" byte | Giữ tối đa 5000 gói | Bỏ ở UI: "+uiDropped.get()+" | "+counts);}
 @SuppressWarnings("unchecked") void filter(){String proto=(String)protocol.getSelectedItem(),q=search.getText().trim().toLowerCase(Locale.ROOT);((TableRowSorter<DefaultTableModel>)table.getRowSorter()).setRowFilter(new RowFilter<>(){public boolean include(Entry<? extends DefaultTableModel,? extends Integer> e){if(!"ALL".equals(proto)&&!proto.equals(e.getStringValue(4)))return false;for(int c:new int[]{2,3,5,6})if(e.getStringValue(c).toLowerCase(Locale.ROOT).contains(q))return true;return q.isEmpty();}});}
 void error(String text){state.setText(text);JOptionPane.showMessageDialog(this,text,"Thông báo",JOptionPane.WARNING_MESSAGE);}
 static String cell(String s){if(s.startsWith("=")||s.startsWith("+")||s.startsWith("-")||s.startsWith("@"))s="'"+s;return "\""+s.replace("\"","\"\"")+"\"";}
 void export(){JFileChooser chooser=new JFileChooser();chooser.setSelectedFile(new File("packets.csv"));if(chooser.showSaveDialog(this)!=JFileChooser.APPROVE_OPTION)return;Path path=chooser.getSelectedFile().toPath();if(Files.exists(path)&&JOptionPane.showConfirmDialog(this,"Ghi đè tệp đã tồn tại?","Xuất CSV",JOptionPane.YES_NO_OPTION)!=JOptionPane.YES_OPTION)return;
  StringBuilder data=new StringBuilder("\uFEFFnumber,time,source,destination,protocol,sourcePort,destinationPort,length,info,demo\n");for(int r=0;r<table.getRowCount();r++){PacketInfo p=packets.get(table.convertRowIndexToModel(r));data.append(p.number()).append(',').append(cell(p.time())).append(',').append(cell(p.source())).append(',').append(cell(p.destination())).append(',').append(cell(p.protocol())).append(',').append(p.sourcePort()).append(',').append(p.destinationPort()).append(',').append(p.length()).append(',').append(cell(p.info())).append(',').append(p.demo()).append('\n');}
  String snapshot=data.toString();CompletableFuture.runAsync(()->{try{Files.writeString(path,snapshot,StandardCharsets.UTF_8);SwingUtilities.invokeLater(()->state.setText("Đã xuất: "+path));}catch(IOException e){SwingUtilities.invokeLater(()->error(e.toString()));}});
 }
}
