#!pip install pycryptodome
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import time
import argparse
import json
import os
import subprocess
import re
import binascii
import time
import base64
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

parser = argparse.ArgumentParser()
parser.add_argument('--sessdata', required=True, help='Session data')
parser.add_argument('--bili_jct', required=True, help='Bilibili jct')
parser.add_argument('--refresh_token', required=True, help='Refresh token')
parser.add_argument('--encode_code', required=True, help='The encryption password')
args = parser.parse_args()
#args = parser.parse_args(['--sessdata', sessdata, '--bili_jct', bili_jct, '--refresh_token', 'refresh_token', '--encode_code', 'qs9BcBGxMv9jfWAC30YAswCSQ6mw2kWJyNEU28bDeKA='])

sessdata = args.sessdata
bili_jct = args.bili_jct
refresh_token = args.refresh_token

key_bytes = (args.encode_code.encode())
fernet = Fernet(key_bytes)
cookie_file_path = 'cookie.env'

if os.path.exists(cookie_file_path):
    with open(cookie_file_path, 'r') as env_file:
        for line in env_file:
            #print(line)
        #    line = line.decode('utf-8')
            key, encrypted_value = line.strip().split('=', 1)
            if encrypted_value.startswith("b'") and encrypted_value.endswith("'"):
                encrypted_value = encrypted_value[2:-1]

            if key == 'SESSDATA':
                sessdata = fernet.decrypt(encrypted_value).decode()

                print(f"解码sessdata", sessdata)
            elif key == 'BIILI_JCT':
                bili_jct = fernet.decrypt(encrypted_value).decode()
            elif key == 'REFRESH_TOKEN':
                refresh_token = fernet.decrypt(encrypted_value).decode()


else:

    sessdata = args.sessdata
    bili_jct = args.bili_jct
    refresh_token = args.refresh_token

#print(sessdata)
#print(bili_jct)
#print(refresh_token)
key = RSA.importKey('''\
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDLgd2OAkcGVtoE3ThUREbio0Eg
Uc/prcajMKXvkCKFCWhJYJcLkcM2DKKcSeFpD/j6Boy538YXnR6VhcuUJOhH2x71
nzPjfdTcqMz7djHum0qSZA0AyCBDABUqCrfNgCiJ00Ra7GmRj+YCK1NJEuewlb40
JNrRuoEUXpabUzGB8QIDAQAB
-----END PUBLIC KEY-----''')

def getCorrespondPath(ts):
    cipher = PKCS1_OAEP.new(key, SHA256)
    encrypted = cipher.encrypt(f'refresh_{ts}'.encode())
    return binascii.b2a_hex(encrypted).decode()

ts = round(time.time() * 1000)
print(getCorrespondPath(ts))
correspondPath = getCorrespondPath(ts)

import subprocess
import re


curl = f"""
curl -G "https://www.bilibili.com/correspond/1/{correspondPath}" \
  -b "SESSDATA={sessdata}" -H "Content-Type: application/octet-stream" -H "Accept: application/zip" | gunzip -d -c - | grep -o '<div id="1-name">.*</div>'
"""

curlout = subprocess.Popen(curl, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
curl_output, error = curlout.communicate()

# 将输出解码为字符串
curl_output_ = curl_output.decode('utf-8')
print(curl_output_)
match = re.search(r'<div id="1-name">([\s\S]+?)</div>', curl_output_)
if match:
    token = match.group(1).strip()  # 去除可能存在的空白字符
else:
    token = None

# 打印token
#print(token)
refresh_csrf = token

# 构建curl命令，使用字符串格式化来插入变量值
curl_command = f"""
curl -i 'https://passport.bilibili.com/x/passport-login/web/cookie/refresh' \
 --data-urlencode "csrf={bili_jct}" \
 --data-urlencode "refresh_csrf={refresh_csrf}" \
 --data-urlencode "source=main_web" \
 --data-urlencode "refresh_token={refresh_token}" \
 -b "SESSDATA={sessdata}"
"""
print(curl_command)
# 执行命令并捕获输出
process = subprocess.Popen(curl_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
curl_output, error = process.communicate()

# 将输出解码为字符串
curl_output_str = curl_output.decode('utf-8')
#print(curl_output_str)
# 使用正则表达式提取cookie值

sessdata_match = re.search(r'set-cookie: SESSDATA=([^;]+);', curl_output_str)
bili_jct_match = re.search(r'set-cookie: bili_jct=([^;]+);', curl_output_str)
refresh_token_match = re.search(r'"refresh_token":"([^"]+)"', curl_output_str)

# 设置新的cookie值
sessdata = sessdata_match.group(1) if sessdata_match else None
bili_jct = bili_jct_match.group(1) if bili_jct_match else None
refresh_token = refresh_token_match.group(1) if refresh_token_match else None

import subprocess
curl_post = f"""
curl 'https://api.vc.bilibili.com/dynamic_svr/v1/dynamic_svr/create' \
 --data-urlencode 'dynamic_id=0' \
 --data-urlencode 'type=4' \
 --data-urlencode 'rid=0' \
 --data-urlencode 'content=Hello Bug~' \
 --data-urlencode 'up_choose_comment=0' \
 --data-urlencode 'up_close_comment=0' \
 --data-urlencode 'at_uids=' \
 --data-urlencode 'ctrl=[]' \
 --data-urlencode 'csrf_token=de2731532b4ab96bc8536da948932668' \
 --data-urlencode 'csrf=de2731532b4ab96bc8536da948932668' \
    -b 'SESSDATA={sessdata}'
"""

process = subprocess.Popen(curl_post, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
curl_output, error = process.communicate()

# 将输出解码为字符串
curl_output_str = curl_output.decode('utf-8')
print(curl_output_str)
# 使用正则表达式提取cookie值
######
response_json = json.loads(curl_output_str)
current_time = datetime.utcnow() + timedelta(hours=8)

# 格式化时间为 "YYYY-MM-DD HH:MM:SS UTC+8"
formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S UTC+8")
log_filename = "README.md"

# 读取现有文件内容
try:
    with open(log_filename, 'r') as file:
        lines = file.readlines()
except FileNotFoundError:
    lines = []

# 检查 'dynamic_id' 是否在 JSON 响应的 'data' 部分
if 'dynamic_id' in response_json.get('data', {}):
    status_message = "cookie成功"
else:
    status_message = "cookie失败"
first_line = f"{formatted_time} - {status_message}\n"

# 将新时间添加到文件的第一行
lines.insert(0, first_line)

# 写回文件
with open(log_filename, 'w') as file:
    file.writelines(lines)
#######    
    # 打印结果
#print(f"new_sessdata = {sessdata}")
#print(f"new_bili_jct = {bili_jct}")
#print(f"new_refresh_token = {refresh_token}")
#print(f"refresh_token bytes = {refresh_token}")
encrypted_sessdata = fernet.encrypt(sessdata.encode())
encrypted_bili_jct = fernet.encrypt(bili_jct.encode())
encrypted_refresh_token = fernet.encrypt(refresh_token.encode())
print()
# 保存加密后的cookie值到文件
with open(cookie_file_path, 'wb') as env_file:
    env_file.write(f"SESSDATA={encrypted_sessdata}\n".encode())
    env_file.write(f"BIILI_JCT={encrypted_bili_jct}\n".encode())
    env_file.write(f"REFRESH_TOKEN={encrypted_refresh_token}\n".encode())

print(encrypted_sessdata)
