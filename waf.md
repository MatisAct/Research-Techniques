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
