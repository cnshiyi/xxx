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
    logging.info("程序启动，日志已配置")


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


# 发送测试消息
def send_startup_test_message():
    test_message = "测试消息：程序已启动并连接成功！"
    send_telegram_message(test_message)
    logging.info("发送 Telegram 测试消息成功")


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
    logging.info("数据库已连接并检查或创建所需的表结构")


# 保存生成的私钥和地址到数据库
def save_wallet_to_database(private_key, wallet_address):
    conn = sqlite3.connect('wallets.db')
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO wallets (private_key, wallet_address, trx_balance, usdt_balance)
                      VALUES (?, ?, 0, 0)''', (private_key, wallet_address))
    conn.commit()
    conn.close()
    logging.info(f"保存新的钱包到数据库 - 地址: {wallet_address}, 私钥: {private_key}")


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
            logging.info(f"生成唯一地址: {wallet_address}")
            # 保存生成的地址和私钥到数据库
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
                logging.info(f"查询地址 {address} 的 TRX 余额成功: {balance} TRX")
                return balance
            else:
                logging.info(f"地址 {address} 没有 TRX 余额")
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
                    logging.info(f"查询地址 {address} 的 USDT 余额成功: {balance} USDT")
                    return balance
            logging.info(f"地址 {address} 没有 USDT 余额")
            return 0
        elif response.status_code == 404:
            logging.info(f"地址 {address} 没有 TRC20 代币或未找到")
            return 0
        else:
            logging.error(f"查询 USDT 余额时出错: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        logging.error(f"请求 USDT 余额时发生异常: {e}")
        return None


# 从 TRONSCAN API 获取最新区块的交易数据
def fetch_latest_block_transactions():
    url = "https://apilist.tronscanapi.com/api/block"
    params = {"sort": "-number", "limit": 1}  # 排序并限制返回一条数据
    headers = {"TRON-PRO-API-KEY": TRON_API_KEY}  # 使用 API Key 进行身份验证

    try:
        response = requests.get(url, params=params, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if "data" in data and len(data["data"]) > 0:
                latest_block = data["data"][0]
                block_number = latest_block.get("number", "未知")
                transactions = latest_block.get("transactions", [])
                logging.info(f"监听到区块 {block_number}，包含 {len(transactions)} 笔交易")
                print(f"监听到区块 {block_number}，包含 {len(transactions)} 笔交易")
                return transactions
            else:
                logging.info("未找到最新区块数据")
                return []
        else:
            logging.error(f"获取最新区块数据时出错: {response.status_code} - {response.text}")
            return []
    except Exception as e:
        logging.error(f"请求最新区块数据时发生异常: {e}")
        return []


# 保存新交易到数据库并打印
def save_transaction(wallet_address, transaction_id, amount, timestamp):
    conn = sqlite3.connect('wallets.db')
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO transactions (wallet_address, transaction_id, amount, timestamp)
                      VALUES (?, ?, ?, ?)''', (wallet_address, transaction_id, amount, timestamp))
    conn.commit()
    conn.close()
    message = f"检测到新交易 - 地址: {wallet_address}, 交易ID: {transaction_id}, 金额: {amount} TRX, 时间: {timestamp}"
    print(message)
    logging.info(message)


# 监听数据库中钱包地址的交易
def listen_for_transactions():
    while True:
        conn = sqlite3.connect('wallets.db')
        cursor = conn.cursor()
        cursor.execute('SELECT wallet_address FROM wallets')
        db_addresses = {addr[0] for addr in cursor.fetchall()}
        conn.close()

        # 获取最新区块的交易数据
        transactions = fetch_latest_block_transactions()

        # 遍历区块交易，查找涉及数据库地址的交易
        for tx in transactions:
            tx_id = tx.get("txID")
            raw_data = tx.get("raw_data", {})
            timestamp = raw_data.get("timestamp", "")

            for contract in raw_data.get("contract", []):
                value = contract.get("parameter", {}).get("value", {})
                to_address = value.get("to_address")
                owner_address = value.get("owner_address")
                amount = value.get("amount", 0) / 1_000_000  # 转换为 TRX 单位

                # 打印区块和交易详情
                print(f"区块详情 - 交易 ID: {tx_id}, 发送地址: {owner_address}, 接收地址: {to_address}, 金额: {amount} TRX")

                # 检查是否有地址匹配
                if to_address in db_addresses or owner_address in db_addresses:
                    wallet_address = to_address if to_address in db_addresses else owner_address
                    save_transaction(wallet_address, tx_id, amount, timestamp)
                    logging.info(f"监控到钱包地址 {wallet_address} 有新的交易记录，交易 ID: {tx_id}, 金额: {amount} TRX")

        time.sleep(2)  # 每隔10秒检查一次最新区块


# 主程序入口
def main():
    setup_logging()
    create_database()

    # 发送 Telegram 启动测试消息
    send_startup_test_message()

    # 启动交易监听线程
    listener_thread = threading.Thread(target=listen_for_transactions)
    listener_thread.daemon = True
    listener_thread.start()

    # 生成地址和其他逻辑
    while True:
        try:
            private_key_hex, tron_address = generate_unique_private_key_and_address()
            logging.info(f"生成的私钥: {private_key_hex}, 地址: {tron_address}")
            print(f"生成的地址: {tron_address}")

            # 查询并打印地址余额
            trx_balance = get_tron_balance(tron_address)
            usdt_balance = get_usdt_balance(tron_address)
            print(f"生成的地址余额 - TRX: {trx_balance}, USDT: {usdt_balance}")

        except Exception as e:
            logging.error("发生意外错误", exc_info=True)
            print("程序出现错误，1分钟后重启...")
            time.sleep(60)


if __name__ == "__main__":
    main()
