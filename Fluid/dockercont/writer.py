import time  
  
# 打开文件用于写入，如果文件不存在则创建  
with open('3.txt', 'a') as file:  
    # 初始化计数器  
    count = 1  
    # 循环直到达到100000  
    while count <= 100000:  
        # 将数字转换为字符串并写入文件，然后换行  
        file.write(f"{count}\n")  
        file.flush()
        print(count)
        # 递增计数器  
        count += 1  
        # 等待100毫秒  
        time.sleep(1)  
  
# 文件在这里自动关闭，因为with语句块已经结束