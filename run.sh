#!/bin/bash

# 获取当前时间
currenttime=$(date +"%Y%m%d_%H%M%S")

# 运行脚本并重定向输出到指定的日志文件
.venv/bin/python src/dataProceScript/run_all_mutithread.py > logs/${currenttime}print_log.txt 2>&1