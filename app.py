# Flask-based P2P Encrypted Multi-File Transfer (ZIP + QR + Password)

from flask import Flask, request, render_template_string, send_file, url_for
import os, secrets, base64, atexit, zipfile
from cryptography.fernet import Fernet
import qrcode
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.urandom(24)

UPLOAD_DIR = 'uploaded_files'
os.makedirs(UPLOAD_DIR, exist_ok=True)

FILES = {}   # file_id -> {filename, password, orig_name}
KEY_FILE = 'secret.key'


# ----------------- Encryption Key -----------------
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

fernet = Fernet(load_key())


# ----------------- HTML -----------------
INDEX_HTML = """
<!doctype html>
<html>
<head>
<title>Secure File Sender</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-5">
<h2>Send Multiple Files (Encrypted ZIP)</h2>

<form method="POST" enctype="multipart/form-data">
  <div class="mb-3">
    <label class="form-label">Select Files</label>
    <input type="file" class="form-control" name="files" multiple required>
  </div>
  <div class="mb-3">
    <label class="form-label">Password</label>
    <input type="password" class="form-control" name="password" required>
  </div>
  <button class="btn btn-primary">Generate Link & QR</button>
</form>

{% if link %}
<hr>
<p><b>Download Link:</b></p>
<a href="{{link}}" target="_blank">{{link}}</a>
<h5 class="mt-3">QR Code</h5>
<img src="{{qr_data}}">
{% endif %}
</div>
</body>
</html>
"""

PASSWORD_HTML = """
<!doctype html>
<html>
<head>
<title>Download Files</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-5">
<h3>Enter Password</h3>
{% if error %}
<div class="alert alert-danger">{{error}}</div>
{% endif %}
<form method="POST">
<input type="password" name="password" class="form-control mb-3" required>
<button class="btn btn-success">Download ZIP</button>
</form>
</div>
</body>
</html>
"""


# ----------------- Routes -----------------
@app.route('/', methods=['GET', 'POST'])
def index():
    link = qr_data = None

    if request.method == 'POST':
        files = request.files.getlist('files')
        password = request.form.get('password')

        if files and password:
            # ZIP in memory
            zip_buffer = BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for f in files:
                    zipf.writestr(f.filename, f.read())

            zip_buffer.seek(0)

            # Encrypt ZIP
            encrypted = fernet.encrypt(zip_buffer.read())

            file_id = secrets.token_urlsafe(8)
            enc_name = f"{file_id}.zip.enc"
            path = os.path.join(UPLOAD_DIR, enc_name)

            with open(path, 'wb') as f:
                f.write(encrypted)

            FILES[file_id] = {
                'filename': enc_name,
                'password': password,
                'orig_name': 'files.zip'
            }

            link = url_for('download_file', file_id=file_id, _external=True)

            # QR Code
            qr = qrcode.make(link)
            buf = BytesIO()
            qr.save(buf, format="PNG")
            qr_data = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()

    return render_template_string(INDEX_HTML, link=link, qr_data=qr_data)


@app.route('/download/<file_id>', methods=['GET', 'POST'])
def download_file(file_id):
    if file_id not in FILES:
        return "Invalid or expired link", 404

    error = None

    if request.method == 'POST':
        if request.form.get('password') == FILES[file_id]['password']:
            path = os.path.join(UPLOAD_DIR, FILES[file_id]['filename'])

            with open(path, 'rb') as f:
                decrypted = fernet.decrypt(f.read())

            os.remove(path)
            del FILES[file_id]

            return send_file(
                BytesIO(decrypted),
                as_attachment=True,
                download_name="files.zip"
            )
        else:
            error = "Wrong password"

    return render_template_string(PASSWORD_HTML, error=error)


# ----------------- Cleanup -----------------
def cleanup():
    for v in FILES.values():
        try:
            os.remove(os.path.join(UPLOAD_DIR, v['filename']))
        except:
            pass

atexit.register(cleanup)


# ----------------- Run -----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
