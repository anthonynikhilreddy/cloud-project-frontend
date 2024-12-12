from flask import Flask, render_template, request, redirect, url_for, jsonify, session, send_file
import requests
import json
import base64
import io
from datetime import datetime
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure secret key


@app.route('/')
def hello_world():
    if 'token' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        print(email, password_hash)
        # Make a request to the /validate endpoint
        response = requests.post('https://2dr3wn94t1.execute-api.us-east-2.amazonaws.com/test_v1/validate_user', json={'email': email, 'password': password_hash})
        if response.status_code == 200:
            print(response.json())
            session['email'] = email
            session['password'] = hashlib.sha256(password.encode()).hexdigest()
            username = json.loads(response.json().get('body')).get('username')
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return 'Invalid credentials', 401
    return render_template('login.html')

@app.route('/home')
def home():
    username = session.get('username')
    auth_key = session.get('auth_key')
    expires_in = session.get('expires_in')
    remaining_hours = None
    if expires_in:
        expires_in_datetime = datetime.strptime(expires_in, '%Y-%m-%d %H:%M:%S.%f')
        remaining_time = expires_in_datetime - datetime.now()
        remaining_hours = remaining_time.total_seconds() // 3600
    return render_template('home.html', auth_key = auth_key, remaining_hours=remaining_hours, username=username)

@app.route('/generate_token', methods=['POST'])
def generate_token():
    email = session.get('email')
    password = session.get('password')
    if not email:
        return 'User not logged in', 401
    # Make a request to the auth_key generation endpoint
    response = requests.post('https://2dr3wn94t1.execute-api.us-east-2.amazonaws.com/test_v1/generate_token', json={'email': email, 'password': password})
    if response.status_code == 200:
        print(response.json())
        data = json.loads(response.json().get('body'))
        auth_key = data.get('auth_key')
        expires_in = data.get('expires_in')
        print(auth_key, expires_in)
        session['auth_key'] = auth_key
        session['expires_in'] = expires_in
        return redirect(url_for('home'))
    else:
        return 'Failed to generate token', 500
    

@app.route('/fetch_logs', methods=['POST'])
def fetch_logs():
    auth_key = session.get('auth_key')
    if not auth_key:
        return 'Token not available', 401
    
    selected_value = request.form.get('userSelect')
    if not selected_value:
        return 'No value selected', 400
    
    print(selected_value)
    
    # Make a request to the logs endpoint with the selected value in the body
    response = requests.post(
        'https://2dr3wn94t1.execute-api.us-east-2.amazonaws.com/test_v1/dashboard',
        headers={'authToken': auth_key},
        json={'action': selected_value}
    )

    if response.status_code == 200:
        # print
        return response.json()
    else:
        return 'Failed to fetch logs', 500

# @app.route('/migrate', methods=['POST'])
# def migrate():
#     token = session.get('token')
#     if not token:
#         return 'Token not available', 401
#     # Make a request to the migration endpoint
#     response = requests.post('https://6b6ucoyz90.execute-api.us-east-2.amazonaws.com/test/migrate', json={'token': token})
#     if response.status_code == 200:
#         data = response.json()
#         body = data.get('body')
#         is_base64_encoded = data.get('isBase64Encoded')
#         headers = data.get('headers')
#         if is_base64_encoded:
#             file_data = base64.b64decode(body)
#             file_name = headers.get('Content-Disposition').split('filename=')[1]
#             return send_file(io.BytesIO(file_data), as_attachment=True, download_name=file_name, mimetype=headers.get('Content-Type'))
#         else:
#             return 'Failed to decode file', 500
#     else:
        # return 'Failed to migrate', 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)