# from ua_info import ua_list
import fnmatch
import json
import random
import time
import xml.etree.ElementTree as ET
import pymongo
import requests
import re
import os
import io
from zipfile import ZipFile
from src.dataProceScript.spider_base import BaseSpider

from src.dataProceScript.dataProce import init_item, insert_mongo, getDeepin, isInDeepin
from src.dataProceScript.Setting import *
        
osv_source = """
https://osv-vulnerabilities.storage.googleapis.com/AlmaLinux/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/Alpine/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/Android/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/Bitnami/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/Chainguard/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/CRAN/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/GIT/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/GitHub%20Actions/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/Hackage/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/Hex/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/Linux/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/NuGet/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/OSS-Fuzz/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/Packagist/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/Pub/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/RubyGems/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/SwiftURL/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip,
https://osv-vulnerabilities.storage.googleapis.com/Wolfi/all.zip
"""
        
#(Get-ChildItem -Recurse -File | Measure-Object).Count
        
class OSV(BaseSpider):
  def __init__(self, db, vulnName):
    super().__init__(db, vulnName)
    self.key = 'id'
    self.path = 'src/refe_file/OSV_zip'  # 本地zip文件存放路径
    if not os.path.exists(self.path):
      os.makedirs(self.path)
    
  def get_header(self):
    # 常用User-Agent列表

    ua_list = [
      'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50',
      'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:2.0.1) Gecko/20100101 Firefox/4.0.1',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11',
      'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; 360SE)',
      'Mozilla/5.0 (Linux; U; Android 2.3.7; en-us; Nexus One Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1'

    ]
    header = {'UserAgent': random.choice(ua_list)}
    return header

  def get_data(self, url):
    req = None
    try:
      req = self.get(url = url, headers= self.get_header())
    except Exception as e:
      self.logger.error(f"请求 {url} 失败，错误信息：{e}")
      req = None
    return req
  
  def process_zip_files(self):
    """直接在内存中处理ZIP文件内容，避免解压到磁盘"""
    files = os.listdir(self.path)
    for name in files:
      if name.endswith('.zip'):
        zip_path = os.path.join(self.path, name)
        try:
          with ZipFile(zip_path, 'r') as zObject:
            # 获取ZIP文件中的所有JSON文件
            json_files = [f for f in zObject.namelist() if f.endswith('.json')]
            
            for json_file in json_files:
              # 在内存中读取JSON文件内容
              with zObject.open(json_file) as f:
                content = f.read().decode('utf-8')
                try:
                  data = json.loads(content)
                  # 直接插入MongoDB
                  insert_mongo(self.collection, [data], self.key)
                except json.JSONDecodeError as e:
                  self.logger.error(f"解析JSON文件 {json_file} 失败: {e}")
                except Exception as e:
                  self.logger.error(f"处理文件 {json_file} 时出错: {str(e)}")
        except Exception as e:
          self.logger.error(f"处理ZIP文件 {name} 失败: {e}")


  def crawl(self):
    """不再需要下载zip文件，直接使用本地文件"""
    pass

  def run(self):
    # 南洋给的数据，不用爬取
    self.collection.drop()
    self.crawl()
    self.process_zip_files()  # 替换unzip和osvToMongo
    self.count = self.collection.count_documents({})
    self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')
    # self.dataPreProc()


if __name__ == '__main__':
  # 获取当前时间
  start_time = time.time()
  client = pymongo.MongoClient('localhost', port=27017)
  db = client['306Project']
  collection = db['OSV']
  system = db['system']
  agent = OSV('OSV', collection, 'id', system)
  agent.run()

  client.close()
  # 获取程序结束时间
  end_time = time.time()
  # 计算程序耗时
  duration = end_time - start_time
  # 打印程序耗时
  print(f"程序耗时：{duration} 秒")