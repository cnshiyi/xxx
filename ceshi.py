import os
import string
import pymysql
import logging
import time
import threading
from datetime import datetime
from eth_keys import keys
import hashlib
import base58
import requests
import config  # 导入配置文件
import random
import atexit
import json

# 从 config.py 中读取配置
TELEGRAM_TOKEN = config.TELEGRAM_TOKEN
TELEGRAM_CHAT_ID = config.TELEGRAM_CHAT_ID
DB_HOST = config.DB_HOST
DB_PORT = config.DB_PORT
DB_USER = config.DB_USER
DB_PASSWORD = config.DB_PASSWORD
DB_NAME = config.DB_NAME

# 初始化私钥种子
def generate_initial_private_key():
    return os.urandom(32)

INITIAL_PRIVATE_KEY = generate_initial_private_key()

# 保存当前计数器的文件路径
COUNTER_FILE_PATH = "counter_state.json"

# 配置日志，生成新的日志文件并使用UTF-8编码
def setup_logging():
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # 控制台日志处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # 文件日志处理器
    file_handler = logging.FileHandler('program.log', encoding='utf-8')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logging.info("日志已配置，程序启动")

# 发送 Telegram 消息，加入异常处理
def send_telegram_message(message):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        logging.warning("Telegram 配置未设置，跳过发送消息")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    try:
        response = requests.post(url, data=data)
        if response.status_code != 200:
            raise Exception(f"Telegram 通知发送失败: {response.text}")
    except Exception as e:
        logging.error(f"发送 Telegram 消息时出错: {e}")

# 获取当前外网 IP 地址
def get_current_ip():
    try:
        response = requests.get("https://api.ipify.org?format=json")
        if response.status_code == 200:
            return response.json().get("ip")
        else:
            logging.error(f"获取 IP 时出错: {response.status_code} - {response.text}")
            return "未知 IP"
    except Exception as e:
        logging.error(f"请求 IP 地址时发生异常: {e}")
        return "未知 IP"

# 创建数据库连接和表
def create_database():
    conn = pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS wallets (
                        id INTEGER PRIMARY KEY AUTO_INCREMENT,
                        private_key TEXT,
                        wallet_address TEXT,
                        trx_balance REAL,
                        usdt_balance REAL
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS non_zero_balances (
                        id INTEGER PRIMARY KEY AUTO_INCREMENT,
                        private_key TEXT,
                        wallet_address TEXT,
                        trx_balance REAL,
                        usdt_balance REAL
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS non_zero_wallets (
                        id INTEGER PRIMARY KEY AUTO_INCREMENT,
                        private_key TEXT,
                        wallet_address TEXT,
                        trx_balance REAL,
                        usdt_balance REAL
                    )''')
    conn.commit()
    conn.close()
    logging.info("数据库表创建完成，连接关闭")

# 保存生成的私钥和地址到数据库
def save_wallets_to_database(wallets):
    conn = pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
    cursor = conn.cursor()
    cursor.executemany('''INSERT INTO wallets (private_key, wallet_address, trx_balance, usdt_balance)
                          VALUES (%s, %s, %s, %s)''', wallets)
    conn.commit()
    conn.close()
    logging.info(f"保存了 {len(wallets)} 个钱包到数据库。数据库连接已关闭。")

# 保存余额非零的钱包地址到特定表
def save_non_zero_wallets_to_database(wallets):
    conn = pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
    cursor = conn.cursor()
    cursor.executemany('''INSERT INTO non_zero_wallets (private_key, wallet_address, trx_balance, usdt_balance)
                          VALUES (%s, %s, %s, %s)''', wallets)
    conn.commit()
    conn.close()
    logging.info(f"保存了 {len(wallets)} 个余额非零的钱包到数据库。数据库连接已关闭。")

# 保存余额不为零的钱包到特定表
def save_non_zero_balance_to_database(private_key, wallet_address, trx_balance, usdt_balance):
    conn = pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO non_zero_balances (private_key, wallet_address, trx_balance, usdt_balance)
                      VALUES (%s, %s, %s, %s)''', (private_key, wallet_address, trx_balance, usdt_balance))
    conn.commit()
    conn.close()
    logging.info(f"为地址保存的非零余额钱包数据：{wallet_address}。数据库连接已关闭。")

# 加载计数器状态
def load_counter():
    if os.path.exists(COUNTER_FILE_PATH):
        with open(COUNTER_FILE_PATH, 'r') as file:
            return json.load(file).get("counter", random.randint(0, 2**256 - 1))
    return random.randint(0, 2**256 - 1)

# 保存计数器状态
def save_counter(counter):
    with open(COUNTER_FILE_PATH, 'w') as file:
        json.dump({"counter": counter}, file)

# 随机选择一个位置用于递增
INDEX_TO_INCREMENT = None


# # 生成唯一的私钥和地址（随机选择一位递增，且该位固定）
# def generate_unique_private_key_and_address():
#     global counter
#     # 使用锁保护对全局计数器的访问和递增
#     with counter_lock:
#         # 将计数器转换为64位十六进制表示的字符串
#         counter_hex = f"{counter:064x}"
#         # 将十六进制字符串转换为列表，便于修改特定位
#         counter_list = list(counter_hex)
#
#         # 根据 INDEX_TO_INCREMENT 的位置决定递增方向
#         if INDEX_TO_INCREMENT >= 32:
#             # INDEX_TO_INCREMENT 大于等于 32 时，向前递增
#             for i in range(INDEX_TO_INCREMENT, -1, -1):
#                 current_value = int(counter_list[i], 16)
#                 new_value = (current_value + 1) % 16
#                 counter_list[i] = hex(new_value)[2:]
#                 if new_value != 0:
#                     break
#         else:
#             # INDEX_TO_INCREMENT 小于 32 时，向后递增
#             for i in range(INDEX_TO_INCREMENT, 64):
#                 current_value = int(counter_list[i], 16)
#                 new_value = (current_value + 1) % 16
#                 counter_list[i] = hex(new_value)[2:]
#                 if new_value != 0:
#                     break
#
#         # 生成新的计数器十六进制字符串
#         new_counter_hex = ''.join(counter_list)
#
#         # 打印调试信息，记录计数器状态
#      #   logging.info(f"计数器状态: {counter_hex} -> {new_counter_hex}")
#
#         # 更新全局计数器的值为新的十六进制字符串转换回的整数
#         counter = int(new_counter_hex, 16)
#
#     # 将十六进制字符串转换为字节
#     private_key_bytes = bytes.fromhex(new_counter_hex)
#
#     # 生成钱包地址
#     wallet_address = private_key_to_tron_address(private_key_bytes)
#
#     # 打印调试信息
#  #   logging.info(f"私钥递增位置: {INDEX_TO_INCREMENT}, 原始计数器: {counter_hex}, 新计数器: {new_counter_hex}")
#
#     return new_counter_hex, wallet_address

# 测试代码，从0开始（递增最后一位）
def generate_unique_private_key_and_address():
    global counter
    # 使用锁保护对全局计数器的访问和递增
    with counter_lock:
        # 将计数器转换为64位十六进制表示的字符串
        counter_hex = f"{counter:064x}"
        # 将十六进制字符串转换为列表，便于修改特定位
        counter_list = list(counter_hex)

        # 递增最后一位
        for i in range(63, -1, -1):
            current_value = int(counter_list[i], 16)
            new_value = (current_value + 1) % 16
            counter_list[i] = hex(new_value)[2:]
            if new_value != 0:
                break

        # 生成新的计数器十六进制字符串
        new_counter_hex = ''.join(counter_list)

        # 更新全局计数器的值为新的十六进制字符串转换回的整数
        counter += 1

    # 将十六进制字符串转换为字节
    private_key_bytes = bytes.fromhex(new_counter_hex)

    # 生成钱包地址
    wallet_address = private_key_to_tron_address(private_key_bytes)

    return new_counter_hex, wallet_address

# 将私钥转换为 Tron 地址
def private_key_to_tron_address(private_key_bytes):
    private_key = keys.PrivateKey(private_key_bytes)
    public_key = private_key.public_key
    public_key_hash = public_key.to_canonical_address()
    tron_address_bytes = b'\x41' + public_key_hash
    checksum = hashlib.sha256(hashlib.sha256(tron_address_bytes).digest()).digest()[:4]
    tron_address_base58 = base58.b58encode(tron_address_bytes + checksum).decode('utf-8')
    return tron_address_base58


# 发送余额不为零的通知
def send_non_zero_balance_notification(private_key, wallet_address, trx_balance, usdt_balance):
    current_ip = get_current_ip()
    message = (f"钱包地址: {wallet_address}\n"
               f"私钥: {private_key}\n"
               f"TRX 余额: {trx_balance}\n"
               f"USDT 余额: {usdt_balance}\n"
               f"当前 IP: {current_ip}\n"
               f"该钱包余额不为零，须注意！")
    send_telegram_message(message)
    logging.info(f"已发送非零余额通知: {message}")

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

# 查询钱包余额的线程函数
def generate_wallet_thread(thread_id, counter_lock, wallet_cache, cache_lock):
    while True:
        try:
            # 调用函数生成唯一的私钥和地址
            private_key_hex, tron_address = generate_unique_private_key_and_address()

            # 查询 TRX 和 USDT 余额
            trx_balance = get_tron_balance(tron_address) or 0.0
            usdt_balance = get_usdt_balance(tron_address) or 0.0

            wallet_data = (private_key_hex, tron_address, trx_balance, usdt_balance)
            # 检查余额，如果 TRX 或 USDT 不为零，发送通知并保存到特定表
            if (trx_balance is not None and trx_balance > 0) or (usdt_balance is not None and usdt_balance > 0):
                send_non_zero_balance_notification(private_key_hex, tron_address, trx_balance, usdt_balance)
                save_non_zero_balance_to_database(private_key_hex, tron_address, trx_balance, usdt_balance)
            # 使用锁保护缓存池的修改
            with cache_lock:
                wallet_cache.append(wallet_data)
                if len(wallet_cache) >= 100:
                    save_wallets_to_database(wallet_cache)
                    # 保存余额非零的钱包到特定表
                    non_zero_wallets = [wallet for wallet in wallet_cache if wallet[2] > 0 or wallet[3] > 0]
                    if non_zero_wallets:
                        save_non_zero_wallets_to_database(non_zero_wallets)
                    wallet_cache.clear()
                    logging.info("缓存池已清空，继续生成地址。")

            logging.info(f"生成的私钥: {private_key_hex}, 地址: {tron_address}, TRX 余额: {trx_balance}, USDT 余额: {usdt_balance}")

        except Exception as e:
            logging.error("发生意外错误", exc_info=True)

# 主程序入口
def main():
    setup_logging()  # 确保日志首先配置
    global INDEX_TO_INCREMENT
    # 随机代码
 #   INDEX_TO_INCREMENT = random.randint(0, 63)
    logging.info(f"随机选择的递增位置为: {INDEX_TO_INCREMENT}")

    global counter
    create_database()

    current_ip = get_current_ip()
    send_telegram_message(f"程序已启动，开始生成钱包。\n当前 IP: {current_ip}")

    # 加载计数器状态
    counter = 0   # 测试代码，从0开始
  #  counter = load_counter()

    # 使用锁保护不重复的连续计数器
    global counter_lock
    counter_lock = threading.Lock()
    cache_lock = threading.Lock()

    # 初始化缓存池
    wallet_cache = []

    # 启动多个线程进行钱包地址生成，每个线程独立运行
    threads = []
    for i in range(2):  # 启动 2 个线程，线程数可根据需要调整
        thread = threading.Thread(target=generate_wallet_thread, args=(i, counter_lock, wallet_cache, cache_lock))
        thread.start()
        threads.append(thread)



    # 注册程序退出时的处理函数，确保缓存池数据保存和计数器保存
    def on_exit():
        with cache_lock:
            if wallet_cache:
                save_wallets_to_database(wallet_cache)
                non_zero_wallets = [wallet for wallet in wallet_cache if wallet[2] > 0 or wallet[3] > 0]
                if non_zero_wallets:
                    save_non_zero_wallets_to_database(non_zero_wallets)
        save_counter(counter)
   #     logging.info("程序退出，缓存池和计数器状态已保存。")

    atexit.register(on_exit)

    # 确保主线程不会退出
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()
