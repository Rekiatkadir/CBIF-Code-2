#!/usr/bin/env python3
import os
import json
import sqlite3
import pickle
import numpy as np
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from crypto_helper import convert_password_to_key, validate_password, context_encryption, context_dencryption

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB_FILE = 'bank_app.db'
MODEL_FILE = 'isolation_model.pkl'

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Create Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            salt BLOB NOT NULL,
            dob TEXT NOT NULL, -- Format YYYY-MM-DD
            account_number TEXT UNIQUE NOT NULL,
            balance REAL NOT NULL DEFAULT 5000.0
        )
    ''')
    
    # Create Transactions table with encrypted context columns
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            recipient_name TEXT NOT NULL,
            recipient_account TEXT NOT NULL,
            enc_amount TEXT NOT NULL,
            enc_time TEXT NOT NULL,
            enc_trial_count TEXT NOT NULL,
            enc_password_session TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL, -- Approved, Pending DOB, Denied
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Check if a default user exists, if not create one
    cursor.execute("SELECT * FROM users WHERE email = 'user@bank.com'")
    if not cursor.fetchone():
        # Default user with: password 'password123', dob '1995-08-15', balance 50000.0
        salt, key = convert_password_to_key('password123')
        cursor.execute('''
            INSERT INTO users (email, full_name, password_hash, salt, dob, account_number, balance)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            'user@bank.com',
            'Jane Doe',
            key.decode('utf-8'),
            salt,
            '1995-08-15',
            'NL89ABNA0123456789',
            50000.0
        ))
        
    conn.commit()
    conn.close()

# Ensure model and db are initialized on startup
init_db()

def load_prediction_model():
    if os.path.exists(MODEL_FILE):
        with open(MODEL_FILE, 'rb') as f:
            return pickle.load(f)
    return None

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()
        
        if user and validate_password(password, user['salt'], user['password_hash']):
            session['user_id'] = user['id']
            session['user_name'] = user['full_name']
            session['user_key'] = user['password_hash'] # Using our derived b64 password key as transaction key
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'error')
            
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    cursor.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC", (user_id,))
    encrypted_transactions = cursor.fetchall()
    
    # Decrypt transaction context on-the-fly for show in table
    user_key = session['user_key']
    transactions = []
    
    for tx in encrypted_transactions:
        try:
            enc_dict = {
                'amount': tx['enc_amount'],
                'time': tx['enc_time'],
                'trial_count': tx['enc_trial_count'],
                'password_session': tx['enc_password_session']
            }
            decrypted = context_dencryption(enc_dict, user_key)
            transactions.append({
                'id': tx['id'],
                'recipient_name': tx['recipient_name'],
                'recipient_account': tx['recipient_account'],
                'amount': decrypted['amount'],
                'timestamp': tx['timestamp'],
                'status': tx['status']
            })
        except Exception as e:
            print(f"Error decrypting transaction {tx['id']}: {e}")
            transactions.append({
                'id': tx['id'],
                'recipient_name': tx['recipient_name'],
                'recipient_account': tx['recipient_account'],
                'amount': 'Error (Decryption Failed)',
                'timestamp': tx['timestamp'],
                'status': 'Error'
            })
            
    conn.close()
    return render_template('dashboard.html', user=user, transactions=transactions)

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        recipient_name = request.form.get('recipient_name')
        recipient_account = request.form.get('recipient_account')
        amount = float(request.form.get('amount'))
        attempts = int(request.form.get('attempts', 1))
        seconds = int(request.form.get('seconds', 10))
        
        user_id = session['user_id']
        user_key = session['user_key']
        now = datetime.now()
        current_time_str = now.strftime("%H:%M:%S")
        timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S")
        
        # Determine time in seconds for model prediction
        parts = current_time_str.split(':')
        time_seconds = int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
        
        # Align inputs for Anomaly Detection (amount, time_seconds, attempts, seconds)
        model = load_prediction_model()
        is_anomaly = False
        
        if model:
            features = np.array([[amount, time_seconds, attempts, seconds]])
            prediction = model.predict(features)[0]
            if prediction == -1:
                is_anomaly = True
        else:
            # Simple rule-based heuristic fallback if model is not loaded yet
            if amount > 10000 or attempts > 3 or seconds < 5:
                is_anomaly = True
                
        # Context-based Encryption using the Derived Password Key
        enc_context = context_encryption(amount, current_time_str, attempts, seconds, user_key)
        
        # Save transaction in Pending or Approved State
        status = 'Pending DOB' if is_anomaly else 'Approved'
        
        conn = get_db()
        cursor = conn.cursor()
        
        if not is_anomaly:
            # Dedust the user's balance
            cursor.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
            current_balance = cursor.fetchone()['balance']
            if current_balance < amount:
                flash('Insufficient funds for this transfer.', 'error')
                conn.close()
                return redirect(url_for('transfer'))
                
            cursor.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, user_id))
            
        cursor.execute('''
            INSERT INTO transactions (user_id, recipient_name, recipient_account, 
                                      enc_amount, enc_time, enc_trial_count, enc_password_session, 
                                      timestamp, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, recipient_name, recipient_account, 
              enc_context['amount'], enc_context['time'], enc_context['trial_count'], enc_context['password_session'],
              timestamp_str, status))
              
        tx_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        if is_anomaly:
            # Route to Date of Birth verifier
            session['pending_tx_id'] = tx_id
            return redirect(url_for('verify_dob'))
        else:
            flash(f"Transfer of ${amount:.2f} to {recipient_name} was approved instantly!", "success")
            return redirect(url_for('result', tx_id=tx_id))
            
    return render_template('transfer.html')

@app.route('/verify_dob', methods=['GET', 'POST'])
def verify_dob():
    if 'user_id' not in session or 'pending_tx_id' not in session:
        return redirect(url_for('dashboard'))
        
    tx_id = session['pending_tx_id']
    user_id = session['user_id']
    
    if request.method == 'POST':
        dob_input = request.form.get('dob')
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT dob FROM users WHERE id = ?", (user_id,))
        actual_dob = cursor.fetchone()['dob']
        
        if dob_input == actual_dob:
            # Correct DOB -> Approve transaction & Deduct Funds
            cursor.execute("SELECT enc_amount FROM transactions WHERE id = ?", (tx_id,))
            tx = cursor.fetchone()
            
            # Decrypt amount
            user_key = session['user_key']
            enc_dict = {'amount': tx['enc_amount'], 'time': '', 'trial_count': '', 'password_session': ''}
            try:
                decrypted = context_dencryption(enc_dict, user_key)
                amount = float(decrypted['amount'])
            except Exception:
                amount = 0.0 # Fallback
                
            cursor.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
            current_balance = cursor.fetchone()['balance']
            
            if current_balance >= amount:
                cursor.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, user_id))
                cursor.execute("UPDATE transactions SET status = 'Approved' WHERE id = ?", (tx_id,))
                conn.commit()
                flash('DOB Verified successfully! Transaction approved.', 'success')
                session.pop('pending_tx_id', None)
                conn.close()
                return redirect(url_for('result', tx_id=tx_id))
            else:
                flash('Insufficient funds to complete transaction after approval.', 'error')
                cursor.execute("UPDATE transactions SET status = 'Denied' WHERE id = ?", (tx_id,))
                conn.commit()
                session.pop('pending_tx_id', None)
                conn.close()
                return redirect(url_for('dashboard'))
        else:
            # Incorrect DOB -> Deny access
            cursor.execute("UPDATE transactions SET status = 'Denied' WHERE id = ?", (tx_id,))
            conn.commit()
            conn.close()
            flash('Incorrect Date of Birth entered. Access denied and transaction blocked.', 'error')
            session.pop('pending_tx_id', None)
            return redirect(url_for('dashboard'))
            
    return render_template('verify_dob.html')

@app.route('/result/<int:tx_id>')
def result(tx_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM transactions WHERE id = ?", (tx_id,))
    tx = cursor.fetchone()
    conn.close()
    
    if not tx or tx['user_id'] != session['user_id']:
        return redirect(url_for('dashboard'))
        
    return render_template('result.html', tx=tx)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
