# Đề tài 85 — Bắt và phân tích gói tin mạng thời gian thực bằng Java

Ứng dụng desktop Java 17, Maven, Swing, TCP Socket, Pcap4J. Hai tiến trình độc lập: Server bắt gói tại card mạng của Server, Client gửi lệnh và nhận kết quả qua TCP. Không cần MySQL.

## 1. Mở dự án trong IntelliJ IDEA trên Windows

1. Giải nén `de_tai_85_java.zip` vào thư mục riêng, ví dụ `D:\DoAn\packet-analyzer`.
2. IntelliJ → Open → chọn thư mục chứa `pom.xml` → mở dưới dạng Maven project.
3. File → Project Structure → Project SDK: chọn JDK 17 hoặc mới hơn (khuyến nghị 17).
4. Chờ Maven tải các dependency. Cần Internet cho lần đầu.
5. Nếu không tự tải: mở cửa sổ Maven → Reload All Maven Projects.
6. Mở `src/main/java/vn/edu/packet/ServerMain.java` và `ClientMain.java`.

## 2. Chạy thử DEMO trước — không cần Npcap

DEMO chỉ tạo gói tin giả, vẫn truyền qua TCP thật, không phải kết quả bắt mạng.

1. IntelliJ → Run → Edit Configurations → Add New → Application.
2. Name: `Demo Server`; Main class: `vn.edu.packet.ServerMain`.
3. Program arguments: `127.0.0.1 9000 --demo`.
4. Chọn JDK 17 và classpath của project → Apply → Run.
5. Console phải hiện `Packet Server 127.0.0.1:9000 | DEMO - synthetic data`.
6. Chạy `ClientMain.main()` bằng nút tam giác bên cạnh hàm main.
7. Client: IP `127.0.0.1`, cổng `9000` → Kết nối.
8. Chọn `DEMO - synthetic network` → để trống BPF → Bắt đầu.
9. Bảng xuất hiện TCP, UDP, ICMP. Chọn dòng để xem chi tiết.
10. Thử lọc giao thức, tìm IP/cổng, Dừng, xuất CSV. DEMO không hỗ trợ BPF.

## 3. Bắt gói tin thật trên Windows

1. Tải Npcap từ https://npcap.com/#download . Không có driver Npcap đi kèm dự án.
2. Cài Npcap, chọn **Install Npcap in WinPcap API-compatible Mode** để phù hợp cách tìm thư viện của Pcap4J.
3. Nếu Npcap giới hạn quyền Administrator, chạy IntelliJ hoặc terminal Server bằng Run as administrator.
4. Dừng Demo Server để giải phóng cổng 9000.
5. Tạo cấu hình `Live Server`: Main class `vn.edu.packet.ServerMain`; arguments `127.0.0.1 9000` (không có `--demo`).
6. Run Server, sau đó Run Client.
7. Kết nối → Tải card mạng → chọn card Wi-Fi/Ethernet đang dùng. Dựa mô tả và địa chỉ IP trong danh sách; không chọn card VMware nếu muốn bắt lưu lượng Wi-Fi.
8. BPF để trống lần đầu → Bắt đầu.
9. Mở một trang web hoặc PowerShell chạy `ping -4 1.1.1.1` để tạo lưu lượng.
10. Chọn dòng TCP/UDP/ICMP để xem thông tin header và HEX.
11. Nhấn Dừng trước khi đổi card hoặc BPF, chờ trạng thái `STOPPED` rồi bắt lại.

Nếu lỗi `UnsatisfiedLinkError`, thiếu `wpcap` hoặc `Packet`: kiểm tra Npcap, Java 64-bit, rồi khởi động lại IntelliJ. Nếu không dùng chế độ tương thích, có thể thêm VM option cho Server: `-Djna.library.path="C:\Windows\System32\Npcap"`.

## 4. Build và chạy ngoài IDE

Cần JDK 17+ và Maven có trong PATH. Terminal tại thư mục chứa pom.xml:

```powershell
mvn clean package
```

Chỉ tiếp tục khi hiện `BUILD SUCCESS`. JAR đã chứa thư viện Java nằm tại `target/packet-analyzer-1.0.0.jar`; driver Npcap/libpcap vẫn phải cài riêng.

Terminal 1 (Demo):
```powershell
java -cp target/packet-analyzer-1.0.0.jar vn.edu.packet.ServerMain 127.0.0.1 9000 --demo
```

Terminal 2:
```powershell
java -cp target/packet-analyzer-1.0.0.jar vn.edu.packet.ClientMain
```

Live Server:
```powershell
java -cp target/packet-analyzer-1.0.0.jar vn.edu.packet.ServerMain 127.0.0.1 9000
```

Có các file `build.bat`, `run-demo-server.bat`, `run-server.bat`, `run-client.bat` để nhấp đúp sau khi cài JDK/Maven và build. `java -jar` không được dùng vì có hai main class.

## 5. Chạy trên hai máy trong LAN

1. Máy A cài Npcap, chạy Live Server với arguments `0.0.0.0 9000`.
2. Dùng `ipconfig` trên máy A để lấy IPv4 của card đang kết nối.
3. Nếu Firewall hỏi, cho Java truy cập mạng Private; chỉ mở TCP 9000 trên mạng lab cần thiết.
4. Máy B chạy Client, nhập IPv4 máy A, cổng 9000 → Kết nối.
5. Card mạng trong danh sách là card của máy A. Kết quả cũng là lưu lượng máy A quan sát được.
6. Trình diễn: máy B điều khiển bắt/dừng, máy A chạy ping và truy cập web, máy B xem kết quả.

Đây là bản đồ án chạy trong mạng lab tin cậy. Giao thức điều khiển chưa có tài khoản hoặc TLS. Mặc định chỉ lắng nghe localhost; không mở cổng này ra Internet. Chỉ bắt lưu lượng trên máy/mạng được phép. Chưa giải mã nội dung HTTPS.

## 6. Bộ lọc

BPF được gửi đến Server và áp dụng trước khi bắt thật:

| BPF | Ý nghĩa |
|---|---|
| `tcp` | TCP |
| `udp` | UDP |
| `icmp` | ICMP IPv4 |
| `port 53` | Cổng nguồn hoặc đích 53 |
| `host 1.1.1.1` | IP nguồn hoặc đích |
| `tcp port 443` | TCP cổng 443 |
| `not tcp port 9000` | Loại lưu lượng điều khiển của ứng dụng |

Gợi ý: dùng `not tcp port 9000` khi bắt card chứa kết nối Client–Server để tránh ứng dụng bắt chính dữ liệu nó đang truyền. Nếu Client/Server cùng máy và chọn card loopback, lưu lượng TCP điều khiển có thể chiếm phần lớn bảng.

Bộ lọc hiển thị trên Client chỉ lọc những dòng đang giữ; không thay đổi quá trình bắt. Ô tìm kiếm là chuỗi con của IP/MAC hoặc cổng, không phải biểu thức BPF. CSV xuất các dòng đang hiển thị theo thứ tự hiện tại.

## 7. Cấu trúc mã nguồn

```
packet-analyzer/
  pom.xml
  README.md
  docs/THIET_KE_VA_KICH_BAN.md
  src/main/java/vn/edu/packet/
    ServerMain.java   # TCP listener, session, worker bắt gói
    ClientMain.java   # Giao diện Swing, kết nối, lọc, CSV
    Wire.java         # JSON UTF-8, khung bản tin TCP
    PacketInfo.java   # DTO dữ liệu gói tin
    Analyzer.java     # Ethernet, IP, TCP, UDP, ICMP, ARP, HEX
  src/test/java/vn/edu/packet/ProjectTest.java
  run-*.bat / run-*.sh
```

## 8. Giới hạn và cách đọc thống kê

- Phân tích header và dữ liệu HEX; chưa tái lắp luồng TCP, giải mã TLS hay suy diễn đầy đủ giao thức ứng dụng.
- IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, ARP được nhận diện khi Pcap4J giải mã được. Gói khác giữ dạng OTHER/ETHERNET và chi tiết thô.
- Bắt ở chế độ NONPROMISCUOUS, snap length 65536. Không đảm bảo bắt toàn mạng LAN; mạng chuyển mạch không gửi tất cả lưu lượng tới card Server.
- Tối đa 4 Client, mỗi Client có phiên bắt riêng.
- Server có hàng đợi 512 bản tin. Khi Client chậm, bỏ bản tin mới, báo tổng số bỏ khi dừng; không phải bộ thu không mất gói.
- Client có hàng đợi 2000 gói và giữ tối đa 5000 dòng. Thống kê là tổng số gói Client đã xử lý kể từ khi xóa bảng, có thể lớn hơn số dòng đang giữ. Tổng byte là số byte đã bắt, không phải tốc độ mạng hoặc số byte chính xác trên đường truyền.
- CSV chỉ chứa các dòng đang giữ và qua bộ lọc, không phải toàn bộ lịch sử. Chưa hỗ trợ PCAP.
- Dừng có hiệu lực sau lần đọc libpcap hiện tại; một số driver có thể chờ thêm khi không có lưu lượng. Nếu chưa `STOPPED`, tạo một gói ping và chờ trước khi bắt lại.
- Không cần database. Gói tin chỉ giữ trong RAM trừ khi người dùng xuất CSV.

## 9. Xử lý lỗi thường gặp

- `Address already in use`: dừng Server cũ hoặc đổi cổng ở cả Server và Client.
- `Connection refused`: kiểm tra Server đang chạy, đúng IP/cổng.
- Kết nối timeout: kiểm tra cùng mạng, IP máy A, Firewall và bind address.
- Không có gói: kiểm tra đúng card, tạo lưu lượng, xóa BPF quá chặt, quyền bắt gói.
- BPF sai cú pháp: sửa và nhấn Bắt đầu lại.
- `mvn` không nhận diện: dùng cửa sổ Maven của IntelliJ hoặc cài Maven, mở lại terminal.
- `UnsupportedClassVersionError`: dùng JDK 17 trở lên.

## 10. Ubuntu

Cài JDK 17, Maven và libpcap theo kho của bản Ubuntu đang dùng. Build bằng `mvn clean package`. Chạy Client bằng user desktop bình thường. Server cần quyền đọc thiết bị bắt gói; có thể chạy riêng Server bằng `sudo java -cp target/packet-analyzer-1.0.0.jar vn.edu.packet.ServerMain 127.0.0.1 9000` trong máy lab. DEMO không cần quyền bắt gói.

## Tài liệu tham khảo

- Pcap4J: https://www.pcap4j.org/
- Mã nguồn Pcap4J: https://github.com/kaitoy/pcap4j
- Npcap: https://npcap.com/guide/npcap-users-guide.html
- Java networking: https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/net/Socket.html
