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

Kỹ thuật 4 – Truy cập thẳng Origin IP (Direct Origin IP Bypass) – “Cửa sau” mạnh nhất của Imperva Cloud & SecureSphere
(Hình minh họa: mũi tên từ attacker → thẳng Origin IP, vòng qua Imperva PoP + icon firewall vỡ)
Tại sao đây là bypass hoàn toàn (không phụ thuộc exception)?

Imperva Cloud chỉ inspect traffic đi qua domain (CNAME/Anycast PoP).
SecureSphere (On-Prem) cũng chỉ áp dụng rule khi traffic đi qua gateway.
Nếu origin server không whitelist Imperva IPs (Origin ACL), request thẳng IP + Host header đúng sẽ bỏ qua 100% signature + behavioral engine.
Kỹ thuật 5 – DNS Override / Hosts file + Internal IP (Split DNS Bypass)
(Minh họa: external DNS → Imperva | local /etc/hosts hoặc --resolve → Origin IP thẳng)
Nguyên lý siêu đơn giản nhưng cực kỳ hiệu quả:

DNS public → Imperva PoP (bắt buộc).
Nhưng attacker/red team thay đổi resolution local → domain resolve thẳng Origin IP hoặc IP nội bộ → bypass hoàn toàn WAF.
Kỹ thuật 8 – Character Set Confusion (Sự nhầm lẫn bảng mã – Encoding Bypass)
(Hình: UTF-8 vs UTF-7 vs ISO-8859-1 vs Overlong UTF-8 + chữ ký WAF bị “mù”)
Giả định sai lầm của Imperva:
Signature engine mặc định chỉ scan UTF-8/ASCII. Khi bạn thay đổi charset, toàn bộ regex bị vô hiệu hóa.
3 kỹ thuật áp dụng ngay:

UTF-7 XSS (bypass Anti-XSS rule):+ADw-script+AD4-alert(1)+ADw-/script+AD4-
(Imperva không decode UTF-7 → cho qua, backend browser decode thành <script>)
Overlong UTF-8 / Double Encoding (bypass SQLi signature):%C0%A7 thay vì ' (overlong)
Hoặc %2527 (double encode) → WAF chỉ decode 1 lần.
Charset BOM + Meta tag:
Thêm ï»¿ (UTF-8 BOM) hoặc Content-Type: text/html; charset=ISO-8859-1
→ Signature không match vì bảng mã khác.
Kỹ thuật 9 – HTTP Parameter Pollution (HPP) + Routing & Rewrite Rules Bypass
(Hình: ?id=1&id=2 + X-Original-URL chồng lên nhau)
Nguyên lý:
Imperva chỉ kiểm tra parameter đầu tiên hoặc cuối cùng (tùy config), backend (PHP/Node/.NET) lại xử lý khác → kẻ tấn công “nhiễm độc” nhiều giá trị.
