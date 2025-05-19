FROM ubuntu  
  
# 安装Python  
RUN apt-get update && apt-get install -y python3  
  
# 将Python脚本复制到容器中  
COPY writer.py /usr/local/bin/  
COPY wait.py /usr/local/bin/ 
# 设置脚本为可执行  
RUN chmod +x /usr/local/bin/writer.py 
RUN chmod +x /usr/local/bin/wait.py 
# 指定容器启动时执行的命令  
CMD ["python3", "/usr/local/bin/writer.py"]