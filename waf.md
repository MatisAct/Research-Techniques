A reverse proxy operates by:

Receiving a user connection request
Completing a TCP three-way handshake, terminating the initial connection
Connecting with the origin server and forwarding the original request

<img width="810" height="287" alt="image" src="https://github.com/user-attachments/assets/82df7b60-770b-452a-80d1-58f2ad771e1c" />




| Đặc điểm | **NGRP (New Gen Reverse Proxy)** | **ABR (Advanced Bridge Mode)** |
| --- | --- | --- |
| **Bản chất** | Reverse Proxy truyền thống | Transparent Reverse Proxy |
| **Cấu hình mạng** | Thay đổi DNS để trỏ về IP của Proxy | DNS giữ nguyên IP của Server |
| **Vùng xử lý** | User-space (Dùng OpenSSL) | User-space (Dùng OpenSSL) |
| **Ưu điểm** | Hỗ trợ mọi Cipher Suite hiện đại nhất | "Tàng hình" về mặt mạng, ít thay đổi DNS |
| **Triển khai** | Dễ dàng trên Cloud / Hybrid | Thường dùng cho On-premise (Inline) |

---
Imperva WAF – Ngoại lệ (Exceptions)
Imperva cho phép admin tạo Whitelist/Exception dựa trên: IP/CIDR, URL/Path, HTTP Parameter, User-Agent, Country.
Kỹ thuật 1 – IP Whitelist Spoofing (Bypass toàn bộ WAF chỉ bằng 1 header)
(Hình minh họa packet với X-Forwarded-For: 127.0.0.1 + mũi tên xuyên tường)
Điều kiện khai thác (rất phổ biến):

Admin whitelist 127.0.0.1 / 192.168.0.0/16 / 10.0.0.0/8
Imperva đang lấy IP từ X-Forwarded-For, X-Real-IP, X-Client-IP, True-Client-IP (mặc định Cloud thường bật).

Kỹ thuật 2 – URL/Path Exception + Path Traversal / Header Rewrite
(Minh họa: /public/images/../../admin → backend resolve thành /admin)
Các dạng ngoại lệ thường gặp cần khai thác:

/api/public/*
/static/*
/upload/images/*
/cdn/*

2 cách bypass tức thì:

Path Traversal trực tiếp:/public/images/../../../admin/config.php?cmd=id
→ WAF match prefix /public/images/ → bypass toàn bộ. Backend normalize → thực thi.
X-Original-URL / X-Rewrite-URL (Nginx/Apache backend):textGET /public/images/any.jpg HTTP/1.1
X-Original-URL: /admin/exec?cmd=whoami
X-Rewrite-URL: /admin/exec?cmd=whoami

Kỹ thuật 3 – Parameter Piggybacking (Ngoại lệ “Bypass All” trên 1 tham số)
(Hình: Parameter description được whitelist → nhồi full RCE payload)
Câu chuyện thật:
Dev yêu cầu: “Cho description chứa HTML không bị chặn XSS”.
Admin thay vì chỉ tắt rule XSS → chọn “Bypass all security checks for this parameter”.



