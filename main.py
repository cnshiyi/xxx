import os
import sqlite3
import logging
import time
import threading
from datetime import datetime
from eth_keys import keys
import hashlib
import base58
import requests
import config  # 导入配置文件

# 从 config.py 中读取配置
TELEGRAM_TOKEN = config.TELEGRAM_TOKEN
TELEGRAM_CHAT_ID = config.TELEGRAM_CHAT_ID
TRON_API_KEY = config.TRON_API_KEY


# 配置日志，按天生成新的日志文件，并使用UTF-8编码
def setup_logging():
    log_filename = f'wallet_generator_{datetime.now().strftime("%Y-%m-%d")}.log'
    logging.basicConfig(filename=log_filename, level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        encoding="utf-8")


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


# 发送余额不为零的通知
def send_non_zero_balance_notification(wallet_address, trx_balance, usdt_balance):
    message = f"钱包地址: {wallet_address}\nTRX 余额: {trx_balance}\nUSDT 余额: {usdt_balance}\n该钱包余额不为零，需注意！"
    send_telegram_message(message)
    logging.info(f"已发送非零余额通知: {message}")


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

    # 启动多个线程进行钱包地址生成，并确保程序循环运行
    while True:
        threads = []
        for _ in range(2):  # 启动 3 个线程，线程数可以根据需要调整
            thread = threading.Thread(target=generate_wallet_thread)
            thread.start()
            threads.append(thread)

        # 等待所有线程完成
        for thread in threads:
            thread.join()

        # 每轮生成完后延时一定时间，防止请求过于频繁
    #    logging.info("本轮生成完成，等待 60 秒后开始下一轮生成。")
      #  time.sleep(60)  # 延时 60 秒后继续


if __name__ == "__main__":
    main()
