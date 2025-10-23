import json
import os
import pymongo
import requests
import time
from bs4 import BeautifulSoup
import re
from typing import Dict, List, Optional
from src.dataProceScript.spider_base import BaseSpider

class kylinos(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.base_url = "https://support.kylinos.cn/"  # 提取基础URL
        self.api_url = f"{self.base_url}protalweb/security/sa/list"
        self.detail_api_url = f"{self.base_url}protalweb/security/sa/info"  # 详情API URL
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0',
            'Content-Type': 'application/json',
            'Referer': f'{self.base_url}#/security/sa',
            'Accept': 'application/json, text/plain, */*',
            'Origin': self.base_url
        }

    def crawl_vulnerabilities(self):
        """爬取所有漏洞信息"""
        self.logger.info("开始爬取所有漏洞信息...")
        sa_nos = []  # 存储所有sa_no的列表
        
        # 直接设置总页数为693
        total_pages = 693
        self.logger.info(f"总页数设置为: {total_pages}页")
        
        # 遍历所有页面
        for page in range(1, total_pages + 1):
            self.logger.info(f"正在爬取第{page}/{total_pages}页...")
            
            # 获取当前页数据
            data = self._fetch_page(page)
            if not data:
                self.logger.info(f"第{page}页爬取失败，跳过")
                continue
                
            vulnerabilities = data.get("obj", {}).get("data", [])
            if not vulnerabilities:
                self.logger.info(f"第{page}页未获取到漏洞数据")
                continue
                
            # 处理当前页的漏洞数据
            inserted_count = 0
            for vuln in vulnerabilities:
                sa_no = vuln.get("sa_no")  # 获取sa_no
                if sa_no:
                    sa_nos.append(sa_no)
                    
                    # 获取详情页数据
                    detail_data = self._fetch_detail(sa_no)

                    # 初始化字段值
                    title = ""
                    severity = ""
                    description = ""
                    public_date = ""
                    update_date = ""
                    KVE_id = ""

                    # 从detail_data中提取信息
                    if detail_data:
                        # 从information中提取基本信息
                        information = detail_data.get("information", {})
                        
                        # 提取标题
                        title = information.get("title", "")
                        
                        # 提取严重程度
                        severity = information.get("aggregate_severity", "")
                        
                        # 提取描述
                        description = information.get("details", "")
                        
                        # 提取日期
                        initial_date = information.get("initial_date", "")
                        release_date = information.get("release_date", "")
                        
                        public_date = initial_date[:10] if initial_date else ""
                        update_date = release_date[:10] if release_date else ""
                        
                        # 提取SA编号
                        sa_no = information.get("sa_no", sa_no)  # 如果详情中有，优先使用详情中的
                        
                        # 提取KVE_id（如果有的话）
                        cve_details = detail_data.get("cve_details", {})
                        if cve_details:
                            first_cve_info = list(cve_details.values())[0] if cve_details else {}
                            cve_id_info = first_cve_info.get("cve_id_info", {})
                            KVE_id = cve_id_info.get("kve", KVE_id)

                    # 构建格式化漏洞信息
                    formatted_vuln = {
                        "cve_id": sa_no,  # 将cve_id设置为sa_no的值
                        "title": title,
                        "severity": severity,
                        "description": description,
                        "public_date": public_date,
                        "update_date": update_date,
                        "KVE_id": KVE_id,
                        "sa_no": sa_no or "",
                        
                        # 添加结构化详情信息
                        "cve_details": detail_data.get("cve_details", {}) if detail_data else {},
                        "information": detail_data.get("information", {}) if detail_data else {},
                        "update_information": detail_data.get("update_information", "") if detail_data else "",
                        "packages": detail_data.get("packages", {}) if detail_data else {},
                        "package_sha256": detail_data.get("package_sha256", {}) if detail_data else {},
                        "products": detail_data.get("products", []) if detail_data else [],
                        
                        # 保留原始详情数据
                        "raw_detail_data": detail_data
                    }

                    try:
                        self.collection.insert_one(formatted_vuln)
                        inserted_count += 1
                        self.logger.info(f"成功插入漏洞 {sa_no}")
                    except Exception as db_error:
                        self.logger.error(f"数据库插入失败: {str(db_error)}")
                                
            # 添加延迟，避免请求过快
            time.sleep(1)

    def _fetch_page(self, page):
        """获取指定页的数据"""
        payload = {
            "row": 10,
            "page": page,
            "query": "",
            "productId": "",
            "arch": "",
            "timeStart": "",
            "timeEnd": "",
            "sortOrder": "desc",
            "sortord": "public_date"
        }
        
        try:
            response = requests.post(
                url=self.api_url,
                headers=self.headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("resultCode") == "0":
                    return data
                else:
                    self.logger.error(f"第{page}页API返回错误: {data.get('message', '未知错误')}")
            else:
                self.logger.error(f"第{page}页请求失败，状态码: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"第{page}页请求异常: {str(e)}")
            
        return None

    def _fetch_detail(self, sa_no):
        """获取指定sa_no的漏洞详情数据"""
        payload = {
            "saNo": sa_no
        }
        
        try:
            response = requests.post(
                url=self.detail_api_url,
                headers=self.headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("resultCode") == "0":
                    return data.get("obj", {})  # 返回详情数据对象
                else:
                    self.logger.error(f"详情页API返回错误 - SA_NO: {sa_no}, 错误信息: {data.get('message', '未知错误')}")
            else:
                self.logger.error(f"详情页请求失败 - SA_NO: {sa_no}, 状态码: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"详情页请求异常 - SA_NO: {sa_no}, 错误: {str(e)}")
            
        return {}
        



    def run(self):
        self.collection.drop()
        self.crawl_vulnerabilities()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')