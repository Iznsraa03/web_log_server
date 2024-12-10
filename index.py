from flask import Flask, render_template, jsonify
import re
import pandas as pd
import mysql.connector
from datetime import datetime

app = Flask(__name__)

# untuk mambaca file log
def read_log(file_path):
    try:
        with open(file_path, 'r') as file:
            logs = file.readlines()
        return logs
    except FileNotFoundError:
        return []

# untuk memparsing log
def parse_logs(logs):
    log_pattern = (
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)'
        r' - - \[(?P<time>[^\]]+)\]'
        r' "(?P<method>\w+) (?P<url>[^\s]+).*"'
        r' (?P<status>\d+)'
        r' (?P<size>\d+|-)'
    )
    parsed_logs = []
    for log in logs:
        match = re.match(log_pattern, log)
        if match:
            parsed_logs.append(match.groupdict())
    return pd.DataFrame(parsed_logs)

# menyimpan log ke MySQL
def save_log_to_mysql(log_df):
    try:
        conn = mysql.connector.connect(
            host="localhost",       
            user="root",            
            password="",             
            database="logs_db"       
        )
        cursor = conn.cursor()

        for _, row in log_df.iterrows():
            log_time = datetime.strptime(row['time'], "%d/%b/%Y:%H:%M:%S %z").strftime('%Y-%m-%d %H:%M:%S')

            cursor.execute('''INSERT INTO logs (ip, time, method, url, status, size)
                            VALUES (%s, %s, %s, %s, %s, %s)''',
                            (row['ip'], log_time, row['method'], row['url'], row['status'], row['size']))

        conn.commit()
        conn.close()
        return True
    except mysql.connector.Error as err:
        print(f"Error saat menyimpan ke MySQL: {err}")
        return False

def detect_attacks(log_df):
    sql_injection_logs = log_df[log_df['url'].str.contains(r"(SELECT|UNION|')", na=False, case=False)]
    brute_force_logs = log_df[(log_df['method'] == 'POST') & (log_df['status'] == '401')]
    lfi_logs = log_df[log_df['url'].str.contains(r"(\.\./|etc/passwd)", na=False)]

    print(f"\n[TERDETEKSI] SQL Injection: {len(sql_injection_logs)} kemungkinan serangan")
    print(sql_injection_logs[['ip', 'url', 'time']].head())

    print(f"\n[TERDETEKSI] Brute Force: {len(brute_force_logs)} kemungkinan serangan")
    print(brute_force_logs[['ip', 'url', 'time']].head())

    print(f"\n[TERDETEKSI] Local File Inclusion (LFI): {len(lfi_logs)} kemungkinan serangan")
    print(lfi_logs[['ip', 'url', 'time']].head())

    return {
        "sql_injection": len(sql_injection_logs),
        "brute_force": len(brute_force_logs),
        "lfi": len(lfi_logs)
    }

# Route ke halaman utama
@app.route("/")
def index():
    return render_template("index.html")

# Route untuk mendapatkan data log
@app.route("/data")
def get_data():
    log_file_path = '/Users/iznsraaa./log_apache/access_log copy'  # Ganti dengan path log yang benar
    logs = read_log(log_file_path)
    if not logs:
        return jsonify({"error": "Log file not found"})

    log_df = parse_logs(logs)
    if log_df.empty:
        return jsonify({"error": "No valid log data found"})

    attack_data = detect_attacks(log_df)
    top_ips = log_df['ip'].value_counts().head(10).to_dict()

    # Menyimpan data log ke MySQL
    if save_log_to_mysql(log_df):
        return jsonify({
            "attacks": attack_data,
            "top_ips": top_ips,
            "message": "Logs successfully saved to MySQL"
        })
    else:
        return jsonify({"error": "Failed to save logs to MySQL"})

if __name__ == "__main__":
    app.run(debug=True)