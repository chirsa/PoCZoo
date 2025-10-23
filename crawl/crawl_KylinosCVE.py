import json
import os
import pymongo
import requests
import time
import parsel
import pymongo
from src.dataProceScript.spider_base import BaseSpider
from typing import Dict, List, Optional

class KylinosCVE(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.api_url = "https://support.kylinos.cn/protalweb/security/cve/list"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0',
            'Content-Type': 'application/json',
            'Referer': 'https://support.kylinos.cn/#/security/cve',
            'Accept': 'application/json, text/plain, */*',
            'Origin': 'https://support.kylinos.cn/'
        }

    def crawl_vulnerabilities(self):
        """爬取所有漏洞信息"""
        self.logger.info("开始爬取所有漏洞信息...")
        
        # 直接设置总页数为1796
        total_pages = 1796
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
                formatted_vuln = {
                    "cve_id": vuln.get("cve") or vuln.get("kve", "未知"),
                    "title": vuln.get("all_title", ""),
                    "severity": vuln.get("threat_severity", ""),
                    "description": vuln.get("cve_detail", ""),
                    "public_date": vuln.get("cve_publicdate", "")[:10] if vuln.get("cve_publicdate") else "",
                    "update_date": vuln.get("cve_updatedate", "")[:10] if vuln.get("cve_updatedate") else "",
                    "KVE_id": vuln.get("cve_id_info", {}).get("kve", "")
                }
                
                try:
                    self.collection.insert_one(formatted_vuln)
                    inserted_count += 1
                except Exception as db_error:
                    self.logger.error(f"数据库插入失败: {str(db_error)}")
            
            self.logger.info(f"第{page}页成功插入{inserted_count}条漏洞信息")
            
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

    def run(self):
        self.collection.drop()
        self.crawl_vulnerabilities()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')

    # def getContent(self):
    #     global data
    #     for page in range(1,345):
    #         # datas = []
    #         respone = requests.get("https://www.kylinos.cn/support/loophole/cve.html?page="+str(page))
    #         selector_1 = parsel.Selector(respone.text)
    #         hrefs = selector_1.css('.layui-table tbody tr td a::attr(href)').getall()
    #         for href in hrefs:
    #             data = requests.get("https://www.kylinos.cn" + href).text
    #             selector_2 = parsel.Selector(data)
    #             des = selector_2.css('body > div.base-content > div:nth-child(1) > div.base-desc > div')[0].xpath('string()').get()
    #             concent = selector_2.css('body .base-content div:nth-child(2) .base-desc')[0].xpath('string()').get()
    #             data={'des':des,'concent':concent}
    #             self.collection.insert_one(data)
    #         time.sleep(5)
    # def run(self):
    #     self.collection.drop()
    #     self.crawl_vulnerabilities()
    #     self.count = self.collection.count_documents({})
    #     self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')

# if __name__ == '__main__':
#     myclient = pymongo.MongoClient('localhost', port=27017)
#     db = myclient['306Project']
#     collection = db['kylinos_cve']
#     obj = KylinosCVE('kylinos',collection)
#     obj.run()
