# Kết quả kiểm tra bản 1.0

Ngày 21/10/2026. Môi trường kiểm tra: OpenJDK 17 trên Linux.

- Maven package: thành công; tạo JAR chứa thư viện Java.
- JUnit: 5 tests, 0 failures, 0 errors, 0 skipped.
- Kiểm tra khung TCP nhiều bản tin và tiếng Việt UTF-8.
- Kiểm tra từ chối khung quá lớn, phát hiện dữ liệu bị cắt.
- Kiểm tra phân tích gói IPv4/UDP tự dựng: IP và cổng 53/12345.
- Kiểm tra phân tích TCP tự dựng: cổng 50000/443, SYN, sequence.
- Kiểm tra Client TCP điều khiển Server DEMO: LIST, START, PACKET, STOP.
- Chạy riêng tiến trình Server từ chính file JAR đã đóng gói; dùng client kiểm thử ngoài tiến trình xác nhận LIST/START/PACKET/STOP.

Chưa kiểm tra bắt mạng thật vì môi trường kiểm thử không có libpcap/Npcap; chưa kiểm tra trực quan Swing do không có display. Cần chạy trên máy Windows của người dùng để xác nhận driver, card mạng và giao diện. DEMO không chứng minh khả năng bắt mạng thật.

Các lỗi tải Maven trong môi trường xây dựng đã được xử lý bằng cấu hình môi trường và bộ nhớ đệm dependency; không có cấu hình proxy riêng được đóng gói vào dự án.
