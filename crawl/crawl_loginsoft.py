from datetime import datetime
from urllib.parse import urljoin
import json
import subprocess
import re
import time
from bs4 import BeautifulSoup
from pymongo import MongoClient
from lxml import etree

from src.dataProceScript.spider_base import BaseSpider

class loginsoft(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.url = "https://research.loginsoft.com/category/vulnerability/"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
        }
        self.count=0
    
    def parse_vulnerability_detail(self, url):
        """解析漏洞详情页面并返回结构化数据"""
        try:
            response = self.session.get(url, headers=self.headers)
            response.raise_for_status()
            
            # 提取标题
            soup = BeautifulSoup(response.content, 'html.parser')
            title_tag = soup.find('h1', class_='entry-title')
            title = title_tag.get_text(strip=True) if title_tag else None
            
            # 提取entry-content div内容
            content_div = soup.find('div', class_='entry-content')
            content = content_div.get_text(separator='\n', strip=True) if content_div else None
            
            detail = {
                "title": title,
                "content": content,
                "url": url,
            }
            
            return detail
            
        except Exception as e:
            self.logger.error(f"解析漏洞详情 {url} 时发生异常：{e}")
            return None

    def geturls(self):
        all_urls = set()  # 使用集合自动去重
        
        try:
            # 处理1-6页
            for page in range(1, 7):
                page_url = f"{self.url}page/{page}/" if page > 1 else self.url
                try:
                    response = self.session.get(page_url, headers=self.headers)
                    response.raise_for_status()
                    html = response.text 
                    # 使用lxml进行XPath解析
                    tree = etree.HTML(html)
                    # 提取指定XPath下的所有URL
                    urls = tree.xpath('/html/body/div[1]/div[1]/div[2]/main/div/ul//a/@href')
                    # 处理提取到的URL
                    for url in urls:
                        full_url = urljoin(page_url, url)
                        all_urls.add(full_url)  # 自动去重     
                except Exception as e:
                    self.logger.error(f"处理页面 {page_url} 时发生异常：{e}")
                    continue      
            
            # 解析并存储所有漏洞详情
            for url in all_urls:
                detail = self.parse_vulnerability_detail(url)
                if detail:
                    self.collection.insert_one(detail)
            
            self.logger.info(f"共处理 {len(all_urls)} 个漏洞详情")
            
        except Exception as e:
            self.logger.error(f"获取URL过程中发生异常：{e}")
        
    def run(self):
        self.collection.drop()
        self.geturls()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')