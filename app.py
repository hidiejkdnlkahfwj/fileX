# Flask-based P2P Encrypted File Transfer with Full Web UI, QR, and Password
# Fixed for direct browser usage without JSON fetch

from flask import Flask, request, render_template_string, send_file, url_for, redirect
import os, secrets, base64, atexit
from cryptography.fernet import Fernet
import qrcode
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.urandom(24)

UPLOAD_DIR = 'uploaded_files'
os.makedirs(UPLOAD_DIR, exist_ok=True)
FILES = {}  # file_id -> {filename, password, original name}
KEY_FILE = 'secret.key'

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    return key

def load_key():
    if not os.path.exists(KEY_FILE):
        return generate_key()
    with open(KEY_FILE, 'rb') as f:
        return f.read()

encryption_key = load_key()
fernet = Fernet(encryption_key)

INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure File Sender</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-5">
  <h2>Upload File & Set Password</h2>
  <form method='POST' enctype='multipart/form-data'>
    <div class="mb-3">
      <label class="form-label">Select File</label>
      <input type="file" class="form-control" name="file" required>
    </div>
    <div class="mb-3">
      <label class="form-label">Password</label>
      <input type="password" class="form-control" name="password" required>
    </div>
    <button type="submit" class="btn btn-primary">Generate Link & QR</button>
  </form>

  {% if link %}
  <div class="mt-4">
    <h5>Link:</h5>
    <a href='{{link}}' target='_blank'>{{link}}</a>
    <h5 class="mt-3">QR Code:</h5>
    <img src='{{qr_data}}'>
  </div>
  {% endif %}
</div>
</body>
</html>
"""

PASSWORD_HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Enter Password</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-5">
  <h3>Enter Password to Download File</h3>
  {% if error %}<div class="alert alert-danger">{{error}}</div>{% endif %}
  <form method='POST'>
    <div class="mb-3">
      <input type='password' class="form-control" name='password' placeholder='Password' required>
    </div>
    <button type='submit' class="btn btn-success">Submit</button>
  </form>
</div>
</body>
</html>
"""

@app.route('/', methods=['GET','POST'])
def index():
    link = None
    qr_data = None
    if request.method=='POST':
        file = request.files.get('file')
        password = request.form.get('password')
        if file and password:
            file_data = file.read()
            encrypted = fernet.encrypt(file_data)
            file_id = secrets.token_urlsafe(8)
            filename = f'{file_id}_{file.filename}.enc'
            filepath = os.path.join(UPLOAD_DIR, filename)
            with open(filepath,'wb') as f:
                f.write(encrypted)
            FILES[file_id] = {'filename': filename, 'password': password, 'orig_name': file.filename}
            # Generate link and QR code
            link = url_for('download_file', file_id=file_id, _external=True)
            qr = qrcode.QRCode(box_size=6, border=2)
            qr.add_data(link)
            qr.make(fit=True)
            img = qr.make_image(fill_color='black', back_color='white')
            buf = BytesIO()
            img.save(buf, format='PNG')
            buf.seek(0)
            img_base64 = base64.b64encode(buf.read()).decode('utf-8')
            qr_data = f'data:image/png;base64,{img_base64}'
    from flask import render_template_string
    return render_template_string(INDEX_HTML, link=link, qr_data=qr_data)

@app.route('/download/<file_id>', methods=['GET','POST'])
def download_file(file_id):
    if file_id not in FILES:
        return 'Invalid link or file expired', 404
    error = None
    if request.method=='POST':
        password = request.form.get('password')
        if password == FILES[file_id]['password']:
            filepath = os.path.join(UPLOAD_DIR, FILES[file_id]['filename'])
            with open(filepath,'rb') as f:
                encrypted = f.read()
            decrypted = fernet.decrypt(encrypted)
            orig_name = FILES[file_id]['orig_name']
            os.remove(filepath)
            del FILES[file_id]
            from io import BytesIO
            return send_file(BytesIO(decrypted), as_attachment=True, download_name=orig_name)
        else:
            error='Wrong password'
    from flask import render_template_string
    return render_template_string(PASSWORD_HTML, error=error)

def cleanup_files():
    for file_id, info in FILES.items():
        try:
            os.remove(os.path.join(UPLOAD_DIR, info['filename']))
        except Exception:
            pass
    FILES.clear()

atexit.register(cleanup_files)

if __name__=='__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True)
