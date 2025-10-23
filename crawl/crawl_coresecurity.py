import json
import random
import time
import urllib.request
from urllib.error import URLError, HTTPError
import os
import bs4
from pymongo import MongoClient
import requests
from src.dataProceScript.dataProce import init_item
from src.dataProceScript.spider_base import BaseSpider

class coresecurity(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.url ="https://www.coresecurity.com/core-labs/advisories"
        self.second_urls = []
        self.dic_list = []
        
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
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'Referer': 'https://www.coresecurity.com/',
        }

        return headers

    def get_urls(self, new_url):
        while True:
            try:
                request = urllib.request.Request(new_url, headers=self.getheaders())
                response = urllib.request.urlopen(request)
                content = response.read().decode('utf-8')
                soup = bs4.BeautifulSoup(content, 'html.parser')
                tds= soup.find_all('td' ,class_ = 'views-field views-field-title')
                for td in tds:
                    an = td.find('a')
                    if (an is not None):
                        # print('https://www.coresecurity.com/' + an.get('href'))
                        self.second_urls.append('https://www.coresecurity.com/' + an.get('href'))
                        # time.sleep(random.uniform(0.5, 3))
                break
            except urllib.error.URLError as e:
                # print(f"Request failed: {e}")
                self.logger.error(f"Request failed: {e}")
                time.sleep(random.uniform(10, 20))


    def singleCrawl(self,url):
        self.count += 1
        self.logger.info(f'正在处理第{self.count}个URL: {url}')
        
        dic = {
            'second_url': url,
            'Title': 'null',
            'content': 'null'
        }
        
        while True:
            try:
                request = urllib.request.Request(url, headers=self.getheaders())
                response = urllib.request.urlopen(request, timeout=20)
                content = response.read().decode('utf-8')
                soup = bs4.BeautifulSoup(content, 'html.parser')
                
                # 获取标题
                title_elements = soup.find_all('h1', class_='node__title h2 text-light')
                if title_elements:
                    dic['Title'] = title_elements[0].text.strip()
                
                # 获取主内容区域(使用id选择器更精确)并提取纯文本
                main_content = soup.find('main', id='content')
                if main_content:
                    dic['content'] = main_content.get_text(separator='\n', strip=True)
                
                self.dic_list.append(dic)
                self.collection.insert_one(dic)
                break
            except HTTPError as http_err:
                self.logger.error(f"HTTP error occurred: {http_err}")
                time.sleep(random.uniform(0, 10))
            except ConnectionError as conn_err:

                # print(f"HTTP error occurred: {conn_err}")
                self.logger.error(f"Connection error occurred: {conn_err}")
            except urllib.error.URLError as e:
                # print(f"Connection error occurred: {e}")
                self.logger.error(f"Connection error occurred: {e}")
                time.sleep(random.uniform(0, 10))

            except requests.exceptions.Timeout as timeout_err:
                # print(f"Timeout error: {timeout_err}")
                self.logger.error(f"Timeout error occurred: {timeout_err}")
                time.sleep(random.uniform(0, 10))



    def crwal(self):
        """单线程爬取所有URL"""
        self.logger.info(f'----------{self.vulnName}开始爬取(单线程模式)----------')
        total = len(self.second_urls)
        for i, url in enumerate(self.second_urls, 1):
            self.logger.info(f'正在处理第{i}/{total}个URL: {url}')
            self.singleCrawl(url)
            # time.sleep(3 + random.uniform(0, 2))  # 3-5秒随机间隔防止反爬

    # def coreSecurityToMongo(self, collection):
    #     # 读取JSON文件并插入到MongoDB
    #     # print(f'----------{self.vulnName} 开始存储----------')
    #     self.logger.info(f'----------{self.vulnName} 开始存储----------')
    #     with open('data.json', 'r', encoding='utf-8') as f:
    #         data_list = json.load(f)
    #         collection.insert_many(data_list)
    #     # 删除JSON文件
    #     os.remove('data.json')
    #     self.logger.info(f'----------{self.vulnName} 存储结束----------')

    # def dataPreProc(self):
    #     print(f'----------{self.vulnName}开始数据预处理----------')
    #     collection = self.collection
    #     system = self.system
    #     count = 1
    #     for doc in collection.find():
    #         item = init_item(self.vulnName)
    #         # item['source_id'] = doc['\n\t\tWPVDB ID\t'] if doc['\n\t\tWPVDB ID\t'] is not None else 'null'
    #         item['source_id'] = doc['second_url']
    #         item['date'] = doc['Date published'] if doc[
    #                                                                 'Date published'] is not None else 'null'
    #         if item['date'] == ' ':
    #             item['date'] = 'null'
    #         item['details'] = doc['description'] if doc['description'] is not None else 'null'
    #         item['title'] = doc['Title'] if doc['Title'] is not None else 'null'
    #         item['type'] = doc['class'] if doc['class'] is not None else 'null'
    #         item['platform'] = 'null'
    #         item['author'] = "null"
    #         item['cve_id'] = doc['CVE Name'] if doc['CVE Name'] is not None else 'null'
    #         item['vul_id'] = f"038_{str(count).zfill(6)}"
    #         item['source'] = self.vulnName
    #         item['software_version'] = 'null'
    #         # if item['cve_id'] != 'null':
    #         #     item['software_version'] = isInDeepin(item['cve_id'], self.deepin2309, self.deepin2404)
    #         # 其他字段丢进related
    #         related_data = {key: doc[key] for key in doc if
    #                         key not in ['_id', "id", "description", "type_id", "platform_id"
    #                             , 'author_id', 'code', 'type', 'platform', 'author']}
    #         # 将所有字段转换为字符串类型
    #         related_data = {key: str(val) for key, val in related_data.items()}
    #         item['related'] = related_data
    #         count += 1
    #         # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
    #         system.insert_one(item)
    #     print(f'----------{self.vulnName} 数据预处理完成----------')

    def run(self):
        """单线程执行爬取流程"""
        self.collection.drop()
        
        # 单线程获取分页URL
        self.logger.info('开始获取分页URL(单线程)')
        for i in range(0, 11):
            page_url = self.url + '?page=' + str(i)
            self.logger.info(f'正在获取第{i+1}页URL')
            self.get_urls(page_url)
            # time.sleep(2 + random.uniform(0, 1))  # 2-3秒随机间隔
            
        # URL去重并添加特殊URL
        self.second_urls = list(set(self.second_urls))
        self.second_urls.append('https://www.coresecurity.com//core-labs/advisories/unified-office-total-connect-sql-injection')
        
        # 执行单线程爬取
        self.crwal()
        
        # 直接存储数据到MongoDB
        # self.coreSecurityToMongo(self.collection)
        
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}单线程爬取完成，共计{self.count}条数据')


# if __name__ == '__main__':
#     start_time = time.time()
#     client = MongoClient('localhost', 27017)
#     db = client['306Project']
#     # 选择集合，如果不存在则MongoDB会自动创建
#     collection = db['coreSecurity']
#     system = db['system']

#     agen = coreSecurity('coreSecurity', 'https://www.coresecurity.com/core-labs/advisories', collection, system, 16)
#     agen.run()

#     client.close()
#     # 获取程序结束时间
#     end_time = time.time()
#     # 计算程序耗时
#     duration = end_time - start_time
#     # 打印程序耗时
#     print(f"程序耗时：{duration} 秒")
