import json
import os
import time

import requests
from fake_headers import Headers
from pymongo import MongoClient

from src.dataProceScript.Setting import DATA_PATH, CURRENT_TIME
from src.dataProceScript.dataProce import insert_mongo, init_item
from src.dataProceScript.spider_base import BaseSpider

class wordfence(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.key = 'id'

        header = Headers(browser='chrome',
                         os='win',
                         headers=True).generate()
        self.headers = {
            'Host':'www.wordfence.com',
            'User-Agent': header['User-Agent']

        }
        self.url = 'https://www.wordfence.com/api/intelligence/v2/vulnerabilities/scanner'


    def crawlAndstorage(self):
        # print(f'----------{self.vulnName} 开始爬取----------')
        self.logger.info(f'----------{self.vulnName} 开始爬取----------')
        try:
            response = self.get(url=self.url, headers=self.headers)
            if response.status_code == 200:
                # print(response.text)
                res = json.loads(response.text)
                for key, value in res.items():
                    # print(value)
                    insert_data = [value]
                    insert_mongo(self.collection,insert_data,self.key)
            else:
                self.logger.error(f'{self.vulnName} 爬取失败，原因：{response.status_code}')
        except Exception as e:
            self.logger.error(f'{self.vulnName} 爬取失败，原因：{e}')



    def run(self):
        self.collection.drop()
        self.crawlAndstorage()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')
        # self.dataPreProc()


if __name__ == '__main__':
    # 获取当前时间
    start_time = time.time()
    # 连接 MongoDB 数据库
    client = MongoClient('localhost', 27017)
    # 获取指定数据库和集合
    db = client['306Project']
    collection = db['wordfence']

    system = db['system']
    agent = wordfence('wordfence', collection, 'id', system)

    agent.run()

    client.close()
    # 获取程序结束时间
    end_time = time.time()
    # 计算程序耗时
    duration = end_time - start_time
    # 打印程序耗时
    print(f"程序耗时：{duration} 秒")
