import datetime

# 获取当前 UTC+8 时间
current_time = datetime.datetime.utcnow() + datetime.timedelta(hours=8)
# 格式化时间
formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S UTC+8\n")

# 要写入的文件名
log_filename = "README.md"

# 读取现有文件内容
try:
    with open(log_filename, 'r') as file:
        lines = file.readlines()
except FileNotFoundError:
    lines = []

# 将新时间添加到文件的第一行
lines.insert(0, formatted_time)

# 写回文件
with open(log_filename, 'w') as file:
    file.writelines(lines)
