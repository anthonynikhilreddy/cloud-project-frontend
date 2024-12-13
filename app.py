from flask import Flask, render_template, request, redirect, url_for, session, send_file
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
    if 'auth_key' not in session:
        return redirect(url_for('login'))
    username = session.get('username')
    auth_key = session.get('auth_key')
    return render_template('home.html', auth_key=auth_key, username=username)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        print(email, password_hash)
        # Make a request to the /validate endpoint
        response = requests.post(
            'https://2dr3wn94t1.execute-api.us-east-2.amazonaws.com/test_v1/validate_user',
            json={'email': email, 'password': password_hash}
        )
        response_data = response.json()
        print(response_data)
        if response_data['statusCode'] == 200:
            session['email'] = email
            session['password'] = hashlib.sha256(password.encode()).hexdigest()
            print(response.json())
            username = response.json().get('body').get('username')
            print(username)
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')


@app.route('/home')
def home():
    username = session.get('username')
    auth_key = session.get('auth_key')
    expires_in = session.get('expires_in')
    if not username:
        return redirect(url_for('login'))
    remaining_hours = None
    if expires_in:
        expires_in_datetime = datetime.strptime(expires_in, '%Y-%m-%d %H:%M:%S.%f')
        remaining_time = expires_in_datetime - datetime.now()
        remaining_hours = remaining_time.total_seconds() // 3600
    return render_template('home.html', auth_key=auth_key, remaining_hours=remaining_hours, username=username)


@app.route('/generate_token', methods=['POST'])
def generate_token():
    email = session.get('email')
    password = session.get('password')
    if not email:
        return 'User not logged in', 401
    # Make a request to the auth_key generation endpoint
    response = requests.post(
        'https://2dr3wn94t1.execute-api.us-east-2.amazonaws.com/test_v1/generate_token',
        json={'email': email, 'password': password}
    )
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
        return render_template('home.html', error="Failed to generate token")

@app.route('/fetch_logs', methods=['POST'])
def fetch_logs():
    auth_key = session.get('auth_key')
    username = session.get('username')  # Retrieve username from the session
    expires_in = session.get('expires_in')

    if not auth_key:
        return 'Token not available', 401

    # Calculate remaining hours for the token
    remaining_hours = None
    if expires_in:
        expires_in_datetime = datetime.strptime(expires_in, '%Y-%m-%d %H:%M:%S.%f')
        remaining_time = expires_in_datetime - datetime.now()
        remaining_hours = max(0, remaining_time.total_seconds() // 3600)

    selected_value = request.form.get('userSelect')
    if not selected_value:
        return render_template(
            'home.html',
            error="No value selected",
            username=username,
            auth_key=auth_key,
            remaining_hours=remaining_hours
        )

    print("Selected Value:", selected_value)

    # Make a request to the logs endpoint with the selected value in the body
    response = requests.post(
        'https://2dr3wn94t1.execute-api.us-east-2.amazonaws.com/test_v1/dashboard',
        headers={'authToken': auth_key},
        json={'action': selected_value}
    )

    if response.status_code == 200:
        data = response.json()
        # Check if 'timestamp' is in the data and sort by 'timestamp'
        if(selected_value=='get_log_table')and 'logs' in data:
            logs = data['logs']
            if all('create_timestamp' in item for item in logs):
                logs = sorted(logs, key=lambda x: datetime.strptime(x['create_timestamp'], '%Y-%m-%d %H:%M:%S'), reverse=True)
                data['logs'] = logs
        if(selected_value=='get_query_logs')and 'logs' in data:
            logs = data['logs']
            if all('timestamp' in item for item in logs):
                logs = sorted(logs, key=lambda x: x['timestamp'], reverse=True)
                data['logs'] = logs
        return render_template(
            'home.html',
            selected_value=selected_value,
            data=data,
            username=username,
            auth_key=auth_key
        )
    else:
        return render_template(
            'home.html',
            selected_value=selected_value,
            error="Failed to fetch logs",
            username=username,
            auth_key=auth_key
        )

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)

