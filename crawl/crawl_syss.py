from bs4 import BeautifulSoup as bs
import random
import requests
import re
import time
import pymongo
from src.dataProceScript.spider_base import BaseSpider

class syss(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.headers = {
            'Host': 'www.syss.de',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Connection': 'keep-alive',
        }
        self.advisory_pattern = re.compile(r'SYSS-(\d{4})-\d{3}\.txt')

    def get_advisory_content(self, url):
        try:
            response = self.get(url, headers=self.headers, timeout=10)
            if response is None:
                self.logger.info(f"{url}请求失败")
                return None
            else:
                response.raise_for_status()
                soup = bs(response.content, 'lxml')
                return soup.text.strip()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"请求失败: {url} - {str(e)}")
            return None

    def crawl(self):
        base_url = "https://www.syss.de/fileadmin/dokumente/Publikationen/Advisories/"
        
        for year in range(2014, 2025):
            for number in range(1, 101):
                url = f"{base_url}SYSS-{year}-{str(number).zfill(3)}.txt"
                self.logger.info(f"正在尝试获取: {url}")
                
                content = self.get_advisory_content(url)
                if content is None:
                    continue
                
                if match := self.advisory_pattern.search(url):
                    vulnerability = {
                        "source": 'syssde',
                        "source_id": f"SYSS-{year}-{str(number).zfill(3)}",
                        "description": content
                    }
                    try:
                        self.collection.insert_one(vulnerability)
                        self.logger.debug(f"成功存储: {url}")
                    except Exception as e:
                        self.logger.error(f"数据库写入失败: {str(e)}")
                
                time.sleep(random.uniform(0.25, 2.5))

    def run(self):
        self.collection.drop()
        self.crawl()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName} 共计爬取 {self.count} 条数据')

# if __name__ == "__main__":
#     client = pymongo.MongoClient("localhost", 27017)
#     try:
#         db = client['306Project']
#         spider = SyssDeSpider(db['syssde'], 'syssde')
#         spider.run()
#     finally:
#         client.close()