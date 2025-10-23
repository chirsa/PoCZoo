import json
import os
import random
import re
import time

import requests
from bs4 import BeautifulSoup as bs

import pymongo
# from src.dataProceScript.Setting import DATA_PATH, CURRENT_TIME
from src.dataProceScript.dataProce import insert_mongo_many, queryrepeat, getVulid, init_item, insert_mongo, getDeepin, \
    isInDeepin
from src.dataProceScript.spider_base import BaseSpider

class Curl(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        # self.vulnName = vulnName
        # self.collection = collection
        # self.system = system
        self.key = 'id'
        # self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        # if not os.path.exists(self.path):
        #     os.makedirs(self.path)

        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0'
        }
        self.url = 'https://curl.se/docs/vuln.json'  #官方提供的网址可以直接获取json格式的全部漏洞
        # self.deepin23beta3,self.deepin2404 = getDeepin()

    def crawl(self):

        # 新建Session对象
        s = requests.Session()

        # 发送GET请求，获取登录页面Cookie
        r = s.get(self.url, headers=self.headers)
        # print('----------curl 连接成功，开始爬取----------')
        self.logger.info('----------curl 连接成功，开始爬取----------')
        # print(r.text)
        # saveFile(os.path.join(self.path,'curl_data.json'),r.text)
        # print('----------curl 爬取完成，存入文件----------')
        return r.text

    def curlToMongo(self,str):
        # print('----------curl 开始存入数据库----------')
        self.logger.info('----------curl 开始存入数据库----------')
        res = json.loads(str)
        insert_mongo(self.collection,res,self.key)
        # 查重
        queryrepeat(self.vulnName, self.collection, self.key)
        # print('----------curl 存入数据库完成----------')
        self.logger.info('----------curl 存入数据库完成----------')


    def dataPreProc(self):
        print('----------curl 开始数据预处理----------')
        collection = self.collection
        system = self.system
        count = 1
        # 先把总数据表中对应数据源所有数据删除
        query = {'source': self.vulnName}
        result = system.delete_many(query)
        # print(f"删除了 {result.deleted_count} 条数据。")

        for doc in collection.find():
            item = init_item(self.vulnName)
            item['source_id'] = doc['id'] if doc['id'] is not None else 'null'
            item['date'] = doc['published'] if doc['published'] is not None else 'null'
            item['details'] = doc['details'] if doc['details'] is not None else 'null'
            item['title'] = doc['summary'] if doc['summary'] is not None else 'null'
            item['vul_id'] = f"001_{str(count).zfill(6)}"
            count += 1
            if len(doc['aliases']) > 1:
                print("curl存在一对多情况",doc['source_id'])
            for cve_id in doc['aliases']:
                item['cve_id'] = cve_id
            if item['cve_id'] != 'null':
                item['software_version'] = isInDeepin(item['cve_id'])
            # 其他字段丢进related
            related_data = {key: doc[key] for key in doc if
                            key not in ['_id',"id", "published", "details", "summary", "aliases"]}
            # 将所有字段转换为字符串类型
            related_data = {key: str(val) for key, val in related_data.items()}  
            item['related'] = related_data

            # 数据预处理前存入的数据库已经做过去重，这里可以直接存进
            system.insert_one(item)

        print('----------curl 数据预处理完成----------')

    def run(self):
        self.collection.drop()
        str = self.crawl()
        self.curlToMongo(str)
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')
        # self.dataPreProc()


# if __name__ == '__main__':
#     # 获取当前时间
#     start_time = time.time()

#     # 连接数据库，运行程序
#     client = pymongo.MongoClient('localhost', port=27017)
#     db = client['306Project']
#     collection = db['curl']
#     # 每个源数据预处理后存入总数据表，总数据表名称
#     system = db['system']

#     obj = CURL('curl', collection, 'id',system)
#     obj.run()
#     client.close()

#     # 获取程序结束时间
#     end_time = time.time()
#     # 计算程序耗时
#     duration = end_time - start_time
#     # 打印程序耗时
#     print(f"程序耗时：{duration} 秒")
