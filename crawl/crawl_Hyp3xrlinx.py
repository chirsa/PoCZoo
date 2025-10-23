import requests
from urllib.parse import urljoin
from lxml import html
import time
import pymongo
from src.dataProceScript.spider_base import BaseSpider
import random

class Hyp3xrlinx(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        # self.collection = collection
        self.base_url = 'https://hyp3rlinx.altervista.org/'
        # self.headers = {
        #      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        #     'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        #     'Accept-Language': 'en-US,en;q=0.5',
        #     'Accept-Encoding': 'gzip, deflate',
        #     'Connection': 'keep-alive',
        #     'Referer': 'https://www.google.com/',
        #     'DNT': '1'
        # }
        
        # 初始化时获取所有链接
        self.name_list = []
        self.url_list = []
        
    def getheaders(self):
        my_headers = [
            "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:30.0) Gecko/20100101 Firefox/30.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/537.75.14",
            "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Win64; x64; Trident/6.0)",
            'Mozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.1.11) Gecko/20071127 Firefox/2.0.0.11',
            'Opera/9.25 (Windows NT 5.1; U; en)',
            'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
            'Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.5 (like Gecko) (Kubuntu)',
            'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.12) Gecko/20070731 Ubuntu/dapper-security Firefox/1.5.0.12',
            'Lynx/2.8.5rel.1 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/1.2.9',
            "Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.7 (KHTML, like Gecko) Ubuntu/11.04 Chromium/16.0.912.77 Chrome/16.0.912.77 Safari/535.7",
            "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:10.0) Gecko/20100101 Firefox/10.0 "

        ]

        headers = {
            'User-Agent': random.choice(my_headers),
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'Referer': 'https://hyp3rlinx.altervista.org/',
        }

        return headers


    def _fetch_base_links(self):
        """获取基础页面的所有链接"""
        try:
            response = requests.get(self.base_url, headers=self.getheaders(), timeout=10)
            response.raise_for_status()
            tree = html.fromstring(response.content)
            
            # 提取名称和链接
            self.name_list = tree.xpath('//a/text()')
            raw_urls = tree.xpath('//a/@href')
            
            # 处理相对URL
            self.url_list = [urljoin(self.base_url, url) for url in raw_urls]
            
        except Exception as e:
            self.logger.error(f"Error fetching base links: {e}")

    def _get_valid_url(self, index):
        """安全获取URL"""
        try:
            return self.url_list[index]
        except IndexError:
            self.logger.error(f"Index {index} out of range")
            return None

    def crawl(self):
        """执行爬虫任务"""
        if not self.url_list:
            self.logger.info("No links found")
            return

        for idx in range(len(self.url_list)):
            url = self._get_valid_url(idx)
            if not url:
                continue

            try:
                # 获取页面内容
                response = requests.get(url, headers=self.headers, timeout=15)
                response.raise_for_status()
                
                # 解析内容
                tree = html.fromstring(response.content)
                content = ' '.join(tree.xpath('//text()')).strip()
                
                # 构建文档
                document = {
                    "title": self.name_list[idx] if idx < len(self.name_list) else "Unknown",
                    "url": url,
                    "content": content,
                }
                
                # 存入数据库
                self.collection.insert_one(document)
                # print(f"Inserted: {url}")
                
            except Exception as e:
                print(f"Error crawling {url}: {e}")
            
            # 礼貌性延迟
            time.sleep(1)

    def run(self):
        self.collection.drop()
        self._fetch_base_links()     
        self.crawl()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')
        

# if __name__ == '__main__':
#     """启动爬虫"""
#     print("Starting scraper...")
#     start_time = time.time()
#     # 初始化MongoDB连接
#     client = pymongo.MongoClient("localhost", 27017)
#     db = client['306Project']
#     collection = db['Hyp3rlinx']
    
#     # 启动爬虫
#     scraper = Hyp3rlinx(collection)
#     scraper.run()

#     duration = time.time() - start_time
#     print(f"Scraping completed in {duration:.2f} seconds")