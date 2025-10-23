import json
import os
import random
import shutil
import time

import requests
from fake_headers import Headers
from pymongo import MongoClient
from src.dataProceScript.spider_base import BaseSpider
from src.dataProceScript.Setting import DATA_PATH, CURRENT_TIME
from src.dataProceScript.dataProce import insert_mongo, init_item
from bs4 import BeautifulSoup as bs

class gentoo(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.key = 'adversory_id'

        self.url = 'https://security.gentoo.org'
        header = Headers(browser='chrome',
                         os='win',
                         headers=True).generate()
        self.headers = {
            'Host': 'security.gentoo.org',
            'User-Agent': header['User-Agent']

        }

    def crawlAndstorage(self):
        self.logger.info('开始爬取gentoo漏洞数据')
        response = self.get(self.url+'/glsa', headers=self.headers)
        if response and response.status_code == 200:
            soup = bs(response.content, 'lxml')
            table = soup.find('table')
            a_s = table.find_all('a')
            flag = 0
            for a in a_s:
                if flag == 0:
                    flag = 1
                    continue
                else:
                    url = a.get('href')
                    self.getDetail(url)
                    time.sleep(random.uniform(0.5,3))
                # break
    def getDetail(self,url):
        response = self.get(self.url + url, headers=self.headers)
        if response and response.status_code == 200:
            soup = bs(response.text, 'lxml')
            # print(response.text)
            adversory_id = f'GLSA-{url.split("/")[2]}'
            try:
                title = soup.find('h1',attrs={'class':'first-header'}).text.strip()
                title = title.replace('\n','')
            except Exception as e:
                title = 'null'

            try:
                description = soup.find('p',attrs={'class':'lead'}).text.strip()
            except Exception as e:
                description = 'null'

            products = []
            try:
                tbody = soup.find('table')
                tds = tbody.find_all('td')
                product_name = tds[0].find('strong').text
                product_version = tds[1].text
                product_dict = {'product_name':product_name,'product_version':product_version}
                products.append(product_dict)
            except Exception as e:
                products = []

            try:
                div = soup.find('div',attrs={'class':'col-12 col-md-2'})
                p_list = div.find_all('p')
                publish_time = p_list[0].text
                publish_time = publish_time.strip()
                publish_time = publish_time.replace('\n','')
                publish_time = publish_time.replace('Release date','')
                publish_time = publish_time.strip()


                severity = p_list[2].text
                severity = severity.strip()
                severity = severity.replace('Severity', '')
                severity = severity.strip()

            except Exception as e:
                description = 'null'

            cves = []
            links = []
            try:
                ul1 = soup.find_all('ul')[1]
                # print(ul1.text)
                a_list1 = ul1.find_all('a')
                for a in a_list1:
                    cve_id = a.text
                    if cve_id.startswith('CVE-'):
                        cves.append(cve_id)
                    links.append(a.get('href'))

                ul2 = soup.find_all('ul')[2]
                # print(ul2.text)
                a_list2 = ul2.find_all('a')
                for a in a_list2:
                    links.append(a.get('href'))
            except Exception as e:
                links = []
                cves = []

            item = {
                'adversory_id':adversory_id,
                'title':title,
                'description':description,
                'publish_time':publish_time,
                'severity':severity,
                'products':products,
                'cves':cves,
                'references':links
            }
            insert_data = [item]
            insert_mongo(self.collection, insert_data, self.key)
    def dataPreProc(self):
        print(f'----------{self.vulnName} 开始数据预处理----------')
        collection = self.collection
        system = self.system
        # 先把总数据表中对应数据源所有数据删除
        query = {'source': self.vulnName}
        result = system.delete_many(query)
        # print(f"删除了 {result.deleted_count} 条数据。")
        count = 1
        for doc in collection.find():
            item = init_item(self.vulnName)

            base = doc['base'] if doc['base'] is not None else 'null'
            item['source_id'] = base[base.find('报告编号：') + 5:base.find('报告来源')]
            # 其他字段丢进related
            related_data = {key: doc[key] for key in doc if
                            key not in ['_id', "update_time_str", "title", "description"]}
            # 将所有字段转换为字符串类型
            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data
            # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
            system.insert_one(item)
        self.logger.info(f'{self.vulnName} 数据预处理完成')

    def run(self):
        self.collection.drop()
        self.crawlAndstorage()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')        
        # self.dataPreProc()


# if __name__ == '__main__':
#     # 获取当前时间
#     start_time = time.time()
#     # 连接 MongoDB 数据库
#     client = MongoClient('localhost', 27017)
#     # 获取指定数据库和集合
#     db = client['306Project']
#     collection = db['gentoo']

#     system = db['system']
#     agent = Gentoo('gentoo', collection, 'adversory_id', system)

#     agent.run()

#     client.close()
#     # 获取程序结束时间
#     end_time = time.time()
#     # 计算程序耗时
#     duration = end_time - start_time
#     # 打印程序耗时
#     print(f"程序耗时：{duration} 秒")
