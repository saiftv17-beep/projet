import subprocess
import json
import threading

process = None

def set_uid(uid):
    with open("config.json", "r", encoding="utf-8") as f:
        config = json.load(f)

    config["uid"] = uid

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4)

def start_bot(uid, hours):
    global process

    if process:
        return  # يمنع تشغيل مرتين

    set_uid(uid)

    process = subprocess.Popen(["python", "main.py"])

    # إيقاف تلقائي بعد الساعات
    threading.Timer(hours * 3600, stop_bot).start()

def stop_bot():
    global process
    if process:
        process.terminate()
        process = None