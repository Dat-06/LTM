# Thiết kế và kịch bản trình diễn đồ án 85

## Bài toán

Xây dựng hệ thống Client–Server bằng Java, trong đó Server thu thập gói tin tại máy chạy Server và gửi kết quả phân tích thời gian thực tới Client qua TCP. Người dùng điều khiển việc chọn thiết bị, bắt/dừng, lọc và quan sát lưu lượng.

## Phân biệt hai loại lưu lượng

1. Lưu lượng được quan sát: Ethernet/IP/TCP/UDP/ICMP... trên card của Server.
2. Lưu lượng ứng dụng tự tạo: kết nối TCP Client ↔ Server cổng 9000, truyền lệnh và JSON kết quả.

Pcap4J là thư viện hỗ trợ truy cập libpcap/Npcap. Phần lập trình mạng tự xây dựng nằm ở Socket, ServerSocket, giao thức bản tin, phân luồng, điều khiển phiên bắt và truyền kết quả.

## Giao thức ứng dụng

Mỗi bản tin có 4 byte số nguyên big endian biểu diễn độ dài N, theo sau bởi N byte JSON UTF-8. Giới hạn 2.000.000 byte/bản tin. Dùng readFully để nhận đủ nội dung, không giả định một lần TCP read tương ứng một bản tin. Không dùng Java ObjectInputStream.

| Hướng | type | Trường và ý nghĩa |
|---|---|---|
| Client → Server | LIST | Yêu cầu danh sách card |
| Client → Server | START | device: tên card; filter: BPF |
| Client → Server | STOP | Yêu cầu dừng |
| Server → Client | DEVICES | devices: danh sách name, label |
| Server → Client | PACKET | packet: đối tượng PacketInfo |
| Server → Client | STATUS | text: trạng thái |
| Server → Client | ERROR | text: lỗi |

Ví dụ nội dung JSON (không bao gồm 4 byte độ dài):

```json
{"type":"START","device":"demo0","filter":""}
```

## Xử lý đồng thời

- Server accept các kết nối và giới hạn 4 phiên.
- Mỗi phiên có luồng nhận lệnh, luồng bắt gói và luồng gửi kết quả.
- Hàng đợi có giới hạn tách tốc độ bắt khỏi tốc độ TCP gửi; quá tải có thể bỏ bản tin.
- PcapHandle do luồng bắt sở hữu và đóng trong try-with-resources.
- Client nhận TCP ngoài EDT, cập nhật giao diện định kỳ trên EDT.
- Các lệnh Client gửi tuần tự qua một executor để giữ thứ tự.
- Mất kết nối đóng socket và báo dừng bắt. Không còn giữ phiên cho Client đã rời đi.

## Quy trình phân tích

1. Lấy timestamp và mảng byte từ thư viện bắt gói.
2. Đọc Ethernet, xác định IP hoặc ARP.
3. Với IP, xác định TCP/UDP/ICMP và trích xuất IP, cổng, thông tin header.
4. Tạo PacketInfo chứa metadata, chi tiết do Pcap4J giải mã và HEX.
5. Serialize JSON, gửi qua TCP, Client đưa vào bảng.

Không đồng nhất cổng 443 với đã phân tích HTTPS; bản này chỉ nhận diện TCP và cổng. Dữ liệu HTTPS vẫn được mã hóa.

## Kịch bản chụp ảnh nộp bài

| Bước | Thao tác | Kết quả cần chụp |
|---|---|---|
| 1 | Mở dự án và pom.xml | Cấu trúc lớp, thư viện |
| 2 | Chạy Live Server | Console địa chỉ và cổng |
| 3 | Client kết nối | Trạng thái LIVE và danh sách card |
| 4 | Chọn card, BPF `not tcp port 9000`, Bắt đầu | Gói tin cập nhật |
| 5 | Chạy `ping -4 1.1.1.1` trên Server | Dòng ICMP, IP nguồn/đích |
| 6 | Mở web trên Server | TCP/UDP xuất hiện |
| 7 | Chọn dòng TCP | Cổng, flags, sequence và HEX |
| 8 | Lọc TCP hoặc tìm IP | Bảng chỉ còn dòng phù hợp |
| 9 | Dừng, xuất CSV | Trạng thái STOPPED và file CSV |
| 10 | Nếu có hai máy, Client máy B điều khiển Server máy A | IP LAN, kết quả truyền TCP |

Đánh dấu rõ DEMO nếu chưa cài Npcap; không dùng ảnh mô phỏng để khẳng định đã bắt lưu lượng thật.

## Câu hỏi bảo vệ

- Vì sao TCP cần chia khung? TCP là luồng byte, không giữ ranh giới bản tin.
- Vì sao dùng nhiều luồng? Bắt gói và truyền mạng có thể chặn; không được chặn giao diện.
- Server bắt gói ở đâu? Card mạng được chọn trên Server.
- Vì sao không thấy mọi máy Wi-Fi? Card và thiết bị chuyển mạch chỉ cung cấp lưu lượng có thể quan sát được.
- Vì sao có thể mất gói? Driver, tốc độ bắt, hàng đợi và băng thông gửi đều có giới hạn.
- Tại sao lọc cổng 9000? Tránh bắt lại chính dữ liệu TCP của ứng dụng.
- Tại sao không cần MySQL? Chức năng hiện tại là theo dõi tức thời, RAM và CSV đủ cho phạm vi này.

## Hướng mở rộng

Lưu/đọc PCAP; thống kê theo giây; biểu đồ; xác thực và TLS cho kênh điều khiển; quản lý quyền; tái lắp TCP; phân tích DNS; bộ đếm mất gói từ driver; gộp capture giữa nhiều Client.
