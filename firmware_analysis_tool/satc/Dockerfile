# 使用基础镜像
# FROM satc_yjy:v1
FROM smile0304/satc
# 设置工作目录
WORKDIR /home/satc/SaTC
# USER root
# 创建目录并更改权限
# RUN mkdir -p /home/satc/SaTC/firmware_extracted /home/satc/SaTC/output /home/satc/SaTC/output/ghidra_extract_result /home/satc/SaTC/output/keyword_extract_result && \
#     chown -R satc:satc /home/satc/SaTC

# 复制启动脚本并设置权限
# COPY start.sh /home/satc/SaTC/start.sh
# RUN chmod +x /home/satc/SaTC/start.sh
# RUN su - satc -c "source /usr/share/virtualenvwrapper/virtualenvwrapper.sh && \ 
                # mkvirtualenv SaTC"
# 切换到 satc 用户
# USER satc
# ENTRYPOINT ["python", "satc.py"]
# 复制必要的文件（如果有）
# COPY . .

# 设置默认的入口点
# ENTRYPOINT ["/home/satc/SaTC/start.sh"]
# ENTRYPOINT ["/bin/sh", "-c", "su - satc -c 'cd /home/satc/SaTC && python satc.py'"]