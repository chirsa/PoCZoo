import fnmatch
import random

import pymongo
import os
import time
import json
import requests
from fake_headers import Headers
from pymongo import MongoClient

from src.dataProceScript.dataProce import jsonToList, queryrepeat, distinct, insert_mongo, init_item, getDeepin, isInDeepin
from src.dataProceScript.Setting import *
from src.dataProceScript.spider_base import BaseSpider

class Redhat(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.key = 'CVE'
        self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        self.base_url = 'https://access.redhat.com/hydra/rest/securitydata/cve.json?page={}'
    def get_headers(self):
        headers = Headers(
            browser='chrome',
            os='win',
            headers=True
        )
        return headers.generate()

    def get_detail(self, url,i):
        dir = self.path
        req = self.get(url=url, headers=self.get_headers(), timeout=10)
        if req and req.status_code == 200:
            cve_list = req.json()
            path = os.path.join(f'{dir}', f'redhat_{i}.json')
            # print(path)
            with open(path, "w") as file:
                json.dump(cve_list, file)
    def crawl(self):
        for i in range(1, 35):#1,33
            # print(i)
            url = self.base_url.format(i)
            self.get_detail(url,i)
            time.sleep(random.uniform(0.2, 2))

    def redhatToMongo(self):
        for root, dirnames, filenames in os.walk(self.path):
            for filename in fnmatch.filter(filenames, '*.json'):
                filepath = os.path.join(root, filename)  # 获取文件的完整路径
                # print(filepath)
                data = jsonToList(filepath)
                insert_mongo(self.collection, data, self.key)
        # 查重
        # queryrepeat(self.vulnName, self.collection, self.key)

    # def dataPreProc(self):
    #     print('----------redhat 开始数据预处理----------')
    #     collection = self.collection
    #     system = self.system
    #     count = 1
    #     # 先把总数据表中对应数据源所有数据删除
    #     query = {'source': self.vulnName}
    #     result = system.delete_many(query)
    #     # print(f"删除了 {result.deleted_count} 条数据。")
    #     for doc in collection.find():
    #         item = init_item(self.vulnName)
    #         item['title'] = doc['bugzilla'] if doc['bugzilla'] is not None else 'null'
    #         item['date'] = doc['public_date'] if doc['public_date'] is not None else 'null'
    #         item['cve_id'] = doc['CVE'] if doc['CVE'] is not None else 'null'
    #         if item['cve_id'] != 'null':
    #             item['software_version'] = isInDeepin(item['cve_id'])

    #         item['details'] = doc['bugzilla_description'] if doc['bugzilla_description'] is not None else 'null'
    #         item['vul_id'] = f"015_{str(count).zfill(6)}"
    #         count += 1
    #         # 其他字段丢进related
    #         related_data = {key: doc[key] for key in doc if
    #                         key not in ['_id',"bugzilla", "public_date", "CVE", "bugzilla_description"]}
    #         # 将所有字段转换为字符串类型
    #         related_data = {key: str(val) for key, val in related_data.items()}
    #         item['related'] = related_data
    #         # 数据预处理前存入的数据库已经做过去重，这里可以直接存进
    #         system.insert_one(item)
    #     print('----------redhat 数据预处理完成----------')

    def run(self):
        self.collection.drop()
        self.crawl()
        self.redhatToMongo()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')
        # self.dataPreProc()

# if __name__=='__main__':
#     start_time = time.time()
#     # 连接 MongoDB 数据库
#     client = MongoClient('localhost', 27017)
#     # 获取指定数据库和集合
#     db = client['306Project']
#     collection = db['redhat']
#     system = db['system']
#     obj = Redhat_to_db('redhat',collection,'CVE',system)
#     obj.run()
#     # 获取程序结束时间
#     end_time = time.time()
#     # 计算程序耗时
#     duration = end_time - start_time
#     # 打印程序耗时
#     print(f"程序耗时：{duration} 秒")