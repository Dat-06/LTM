package vn.edu.packet;
import com.google.gson.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
/** TCP framing: 4-byte big endian length, followed by UTF-8 JSON. */
public final class Wire {
 public static final int MAX_FRAME=2_000_000;
 private Wire(){}
 public static void write(DataOutputStream out, JsonObject msg) throws IOException {
  byte[] b=msg.toString().getBytes(StandardCharsets.UTF_8);
  if(b.length>MAX_FRAME)throw new IOException("Frame too large");
  synchronized(out){out.writeInt(b.length);out.write(b);out.flush();}
 }
 public static JsonObject read(DataInputStream in)throws IOException {
  int n=in.readInt();if(n<2||n>MAX_FRAME)throw new IOException("Invalid frame length: "+n);
  byte[] b=new byte[n];in.readFully(b);
  try{return JsonParser.parseString(new String(b,StandardCharsets.UTF_8)).getAsJsonObject();}
  catch(RuntimeException e){throw new IOException("Invalid JSON object",e);}
 }
 public static JsonObject message(String type,String text){JsonObject o=new JsonObject();o.addProperty("type",type);o.addProperty("text",text);return o;}
 public static String str(JsonObject o,String key,String fallback){return o.has(key)?o.get(key).getAsString():fallback;}
}
