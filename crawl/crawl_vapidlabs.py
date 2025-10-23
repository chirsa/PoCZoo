import os
import random

import pymongo
import requests
from bs4 import BeautifulSoup
from lxml import etree
import time
from src.dataProceScript.Setting import DATA_PATH, CURRENT_TIME
from src.dataProceScript.dataProce import insert_mongo, queryrepeat, getVulid, init_item, getDeepin, isInDeepin
from src.dataProceScript.spider_base import BaseSpider

class vapidlabs(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.key = 'Title'

        self.headers = {
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
        }
        # self.deepin23beta3, self.deepin2404 = getDeepin()
    def initial(self):
        vuln = {
            'Title':'',
            'Author':'',
            'Date':'',
            'CVE-ID':'',
            'CWE':'',
            'Download_Site':'',
            'Vendor':'',
            'Vendor_Notified':'',
            'Vendor_Contact':'',
            'Advisory':'',
            'Description':'',
            'Vulnerability':'',
            'Export':'',
            'Exploit_Code':'',
            'Screen Shots':'',
            'Notes':''
        }
        return vuln

    def crawl(self):
        try:
            response = self.get("http://www.vapidlabs.com/list.php", headers=self.headers)
            # print(response.text)
            if response.status_code == 200:
                html = response.text
                bs = BeautifulSoup(html, "html.parser")
                table = bs.find_all('td')
                address = bs.find_all('a')
                count4 = 1
                for item in address:
                    if (len(item.get('href')) <= 20):
                        if (count4 == 1):
                            count4 += 1
                            continue
                        link = 'http://www.vapidlabs.com/' + item.get('href')
                        # print(link)
                        self.getDetail(link)
                        time.sleep(random.uniform(0.2, 2))
                        count4 += 1

            else:
                # print(response.status_code)
                self.logger.error(f"http://www.vapidlabs.com/list.ph请求失败，状态码：{response.status_code}")
        except Exception as e:
            self.logger.error(f"http://www.vapidlabs.com/list.ph请求失败，错误信息：{e}")
    def getDetail(self,link):
        try:
            response = self.get(link, headers=self.headers)
            vuln = self.initial()
            if response.status_code == 200:
                html = response.text
                bs = BeautifulSoup(html, "html.parser")
                # print(bs)
                tbody = bs.find('tbody')
                trs = tbody.find_all('tr')
                for index, tr in enumerate(trs):
                    if index == 0:
                        continue
                    td = tr.find('td').get_text()
                    field_name = tr.find('b').get_text()
                    res = td.replace(field_name,'')
                    field_name = field_name.split(":")[0]
                    field_name = field_name.replace(' ','_')
                    vuln[field_name] = res
                self.collection.insert_one(vuln)
            else:
                # print(response.status_code
                self.logger.error(f"请求失败，状态码：{response.status_code}")
            return 1
        except Exception as e:
            self.logger.error(f"{link}请求失败，错误信息：{e}")
            return 0



    def dataPreProc(self):
        print('----------vapidlabs 开始数据预处理----------')
        collection = self.collection
        system = self.system
        count = 1
        # 先把总数据表中对应数据源所有数据删除
        query = {'source': self.vulnName}
        result = system.delete_many(query)
        # print(f"删除了 {result.deleted_count} 条数据。")
        for doc in collection.find():
            item = init_item(self.vulnName)
            item['source_id'] = doc['Advisory'] if doc['Advisory'] is not None else 'null'
            item['date'] = doc['Date'] if doc['Date'] is not None else 'null'
            item['details'] = doc['Exploit_Code'] if doc['Exploit_Code'] is not None else 'null'
            item['title'] = doc['Title'] if doc['Title'] is not None else 'null'
            item['vul_id'] = f"018_{str(count).zfill(6)}"
            item['cve_id'] =  doc['CVE-ID'] if doc['CVE-ID'] is not None else 'null'
            if item['cve_id'] != 'null':
                item['software_version'] = isInDeepin(item['cve_id'])

            item['author'] = doc['Author'] if doc['Author'] is not None else 'null'
            count += 1

            # 其他字段丢进related
            related_data = {key: doc[key] for key in doc if
                            key not in ['_id',"Advisory", "Date", "Exploit_Code", "Title", "CVE-ID","Author"]}
            # 将所有字段转换为字符串类型
            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data

            # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
            system.insert_one(item)

        print('----------vapidlabs 数据预处理完成----------')



    def run(self):
        self.collection.drop()  
        self.crawl()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')



if __name__ == '__main__':
    # 获取当前时间
    start_time = time.time()
    # 连接数据库，运行程序
    myclient = pymongo.MongoClient('localhost', port=27017)
    db = myclient['306Project']
    collection = db['vapidlabs']
    # 每个源数据预处理后存入总数据表，总数据表名称
    system = db['system']

    obj = vapidlabs('vapidlabs', collection, 'Title', system)
    obj.run()
    myclient.close()

    # 获取程序结束时间
    end_time = time.time()
    # 计算程序耗时
    duration = end_time - start_time
    # 打印程序耗时
    print(f"程序耗时：{duration} 秒")
