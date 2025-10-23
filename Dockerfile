# 使用从 docker.1ms.run 拉取的 Ubuntu 20.04 镜像作为基础镜像
FROM docker.1ms.run/ubuntu:20.04


# 将本地目录复制到镜像中
COPY . /home/pyprogram/306_crawl

# 设置工作目录
WORKDIR /home/pyprogram/306_crawl


