import os
import sqlite3
import logging
import time
import threading
from datetime import datetime, timedelta
from eth_keys import keys
import hashlib
import base58
import requests
import config  # 导入配置文件
from apscheduler.schedulers.background import BackgroundScheduler
import random

# 从 config.py 中读取配置
TELEGRAM_TOKEN = config.TELEGRAM_TOKEN
TELEGRAM_CHAT_ID = config.TELEGRAM_CHAT_ID
TRON_API_KEY = config.TRON_API_KEY


# 配置日志，按天生成新的日志文件，并使用UTF-8编码
def setup_logging():
    log_filename = f'wallet_generator_{datetime.now().strftime("%Y-%m-%d")}.log'

    # 创建日志处理器并设置编码
    file_handler = logging.FileHandler(log_filename, mode='a', encoding='utf-8')
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)

    # 设置根日志记录器
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)

    # 如果需要，你可以添加控制台输出
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    logging.info("日志已配置，程序启动")


# 发送 Telegram 消息，加入异常处理
def send_telegram_message(message):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        logging.warning("Telegram 配置未设置，跳过发送消息")
        return  # 如果未设置 Telegram 配置，直接返回

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}

    try:
        response = requests.post(url, data=data)
        if response.status_code != 200:
            raise Exception(f"Telegram 通知发送失败: {response.text}")
    except Exception as e:
        logging.error(f"发送 Telegram 消息时出错: {e}")


# 发送文件到 Telegram，并加入失败重试机制
def send_log_file(log_filename):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        logging.warning("Telegram 配置未设置，跳过发送消息")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument"

    # 循环尝试发送文件，直到成功为止
    while True:
        try:
            with open(log_filename, 'rb') as log_file:
                files = {'document': log_file}
                data = {'chat_id': TELEGRAM_CHAT_ID}

                # 尝试发送文件
                response = requests.post(url, data=data, files=files)

                # 如果发送成功，退出循环
                if response.status_code == 200:
                    logging.info(f"已成功发送日志文件: {log_filename}")
                    return
                else:
                    raise Exception(f"Telegram 文件发送失败: {response.text}")

        except Exception as e:
            # 如果发送失败，记录错误并等待随机时间后重试
            logging.error(f"发送日志文件时出错: {e}")
            wait_time = random.randint(10, 60)  # 随机等待 10 到 60 秒
            logging.info(f"等待 {wait_time} 秒后重试...")
            time.sleep(wait_time)


# 删除文件
def delete_log_file(log_filename):
    try:
        os.remove(log_filename)
        logging.info(f"已删除日志文件: {log_filename}")
    except Exception as e:
        logging.error(f"删除日志文件时出错: {e}")


# 每天12点随机时间发送前一天的日志
def send_yesterday_log():
    yesterday = datetime.now() - timedelta(days=1)
    log_filename = f'wallet_generator_{yesterday.strftime("%Y-%m-%d")}.log'

    if os.path.exists(log_filename):
        send_log_file(log_filename)
        delete_log_file(log_filename)
    else:
        logging.warning(f"日志文件 {log_filename} 不存在，跳过发送。")


# 创建数据库连接和表
def create_database():
    conn = sqlite3.connect('wallets.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS wallets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        private_key TEXT,
                        wallet_address TEXT,
                        trx_balance REAL,
                        usdt_balance REAL
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS non_zero_balances (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        private_key TEXT,
                        wallet_address TEXT,
                        trx_balance REAL,
                        usdt_balance REAL
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS transactions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        wallet_address TEXT,
                        transaction_id TEXT,
                        amount REAL,
                        timestamp TEXT
                    )''')
    conn.commit()
    conn.close()


# 保存生成的私钥和地址到数据库
def save_wallet_to_database(private_key, wallet_address):
    conn = sqlite3.connect('wallets.db')
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO wallets (private_key, wallet_address, trx_balance, usdt_balance)
                      VALUES (?, ?, 0, 0)''', (private_key, wallet_address))
    conn.commit()
    conn.close()


# 检查地址是否已存在于数据库中
def address_exists(wallet_address):
    conn = sqlite3.connect('wallets.db')
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM wallets WHERE wallet_address = ?', (wallet_address,))
    exists = cursor.fetchone()[0] > 0
    conn.close()
    return exists


# 生成唯一的私钥和地址，并保存到数据库
def generate_unique_private_key_and_address():
    while True:
        private_key_bytes = os.urandom(32)
        private_key_hex = private_key_bytes.hex()
        wallet_address = private_key_to_tron_address(private_key_bytes)
        if not address_exists(wallet_address):
            save_wallet_to_database(private_key_hex, wallet_address)
            return private_key_hex, wallet_address
        else:
            logging.info("检测到重复地址，重新生成...")


# 将私钥转换为 Tron 地址
def private_key_to_tron_address(private_key_bytes):
    private_key = keys.PrivateKey(private_key_bytes)
    public_key = private_key.public_key
    public_key_hash = public_key.to_canonical_address()
    tron_address_bytes = b'\x41' + public_key_hash
    checksum = hashlib.sha256(hashlib.sha256(tron_address_bytes).digest()).digest()[:4]
    tron_address_base58 = base58.b58encode(tron_address_bytes + checksum).decode('utf-8')
    return tron_address_base58


# 查询 TRX 余额
def get_tron_balance(address):
    url = f"https://api.trongrid.io/v1/accounts/{address}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if "data" in data and len(data["data"]) > 0:
                balance = data["data"][0].get("balance", 0) / 1_000_000  # 转换为 TRX 单位
                return balance
            else:
                return 0
        else:
            logging.error(f"查询 TRX 余额时出错: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        logging.error(f"请求 TRX 余额时发生异常: {e}")
        return None


# 查询 USDT 余额
def get_usdt_balance(address):
    contract_address = "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf"  # USDT 合约地址
    url = f"https://api.trongrid.io/v1/accounts/{address}/trc20"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            for token in data:
                if token.get("token_id") == contract_address:
                    balance = int(token.get("balance", "0")) / 1_000_000  # 转换为 USDT 单位
                    return balance
            return 0
        elif response.status_code == 404:
            return 0
        else:
            logging.error(f"查询 USDT 余额时出错: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        logging.error(f"请求 USDT 余额时发生异常: {e}")
        return None


# 生成钱包的线程函数
def generate_wallet_thread():
    try:
        private_key_hex, tron_address = generate_unique_private_key_and_address()
        logging.info(f"生成的私钥: {private_key_hex}, 地址: {tron_address}")
        print(f"生成的地址: {tron_address}")

        # 查询并打印地址余额
        trx_balance = get_tron_balance(tron_address)
        usdt_balance = get_usdt_balance(tron_address)
        print(f"生成的地址余额 - TRX: {trx_balance}, USDT: {usdt_balance}")

        # 检查余额，如果 TRX 或 USDT 不为零，发送通知
        if trx_balance > 0 or usdt_balance > 0:
            send_non_zero_balance_notification(tron_address, trx_balance, usdt_balance)

    except Exception as e:
        logging.error("发生意外错误", exc_info=True)
        print("程序出现错误，1分钟后重启...")
        time.sleep(10)


# 主程序入口
def main():
    setup_logging()
    create_database()

    # 发送 Telegram 启动测试消息
    send_telegram_message("程序已启动，开始生成钱包。")

    # 初始化调度器
    scheduler = BackgroundScheduler()

    # 每天12点随机时间执行发送日志任务
    scheduler.add_job(send_yesterday_log, 'cron', hour=12, minute=random.randint(0, 59))

    # 启动调度器
    scheduler.start()

    # 启动多个线程进行钱包地址生成，并确保程序循环运行
    while True:
        threads = []
        for _ in range(2):  # 启动 2 个线程，线程数可以根据需要调整
            thread = threading.Thread(target=generate_wallet_thread)
            thread.start()
            threads.append(thread)

        # 等待所有线程完成
        for thread in threads:
            thread.join()

   #     time.sleep(60)  # 每60秒执行一次，避免过于频繁的请求


if __name__ == "__main__":
    main()
