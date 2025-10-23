# _*_ coding : utf-8 _*_
# @Time : 2024/7/17 20:56
# @Author : spiderzhu
# @Project : 306_vuln_db-master
import fnmatch
import json
import time
import random

import pymongo
import requests
from fake_headers import Headers
import os

from pymongo import MongoClient
from src.dataProceScript.spider_base import BaseSpider
from src.dataProceScript.Setting import DATA_PATH, CURRENT_TIME
from src.dataProceScript.dataProce import init_item, isInDeepin, getDeepin


from src.dataProceScript.dataProce import jsonToList, insert_mongo, queryrepeat


class hackerone(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.key = 'id'
        # self.key = key


        self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        print(self.path)
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        self.url = 'https://hackerone.com/graphql'

        self.detail_url = "https://hackerone.com/reports/"

        header = Headers(browser='chrome',
                         os='win',
                         headers=True).generate()
        self.headers = {
            'User-Agent': header['User-Agent'],
            'Content-Type':'application/json'
        }
        self.totalCount = self.getTotal()
        self.website_tail_id_list = []





    def getTotal(self):
        data = {"operationName":"HacktivitySearchQuery","variables":{"queryString":"disclosed:true","size":25,"from":0,"sort":{"field":"latest_disclosable_activity_at","direction":"DESC"},"product_area":"hacktivity","product_feature":"overview"},"query":"query HacktivitySearchQuery($queryString: String!, $from: Int, $size: Int, $sort: SortInput!) {\n  me {\n    id\n    __typename\n  }\n  search(\n    index: CompleteHacktivityReportIndex\n    query_string: $queryString\n    from: $from\n    size: $size\n    sort: $sort\n  ) {\n    __typename\n    total_count\n    nodes {\n      __typename\n      ... on HacktivityDocument {\n        id\n        _id\n        reporter {\n          id\n          username\n          name\n          __typename\n        }\n        cve_ids\n        cwe\n        severity_rating\n        upvoted: upvoted_by_current_user\n        public\n        report {\n          id\n          databaseId: _id\n          title\n          substate\n          url\n          disclosed_at\n          report_generated_content {\n            id\n            hacktivity_summary\n            __typename\n          }\n          __typename\n        }\n        votes\n        team {\n          id\n          handle\n          name\n          medium_profile_picture: profile_picture(size: medium)\n          url\n          currency\n          __typename\n        }\n        total_awarded_amount\n        latest_disclosable_action\n        latest_disclosable_activity_at\n        submitted_at\n        disclosed\n        has_collaboration\n        __typename\n      }\n    }\n  }\n}\n"}
        data = json.dumps(data)
        response = requests.post(url=self.url, headers=self.headers, data=data)
        if response:
            res = json.loads(response.text)
            # print(self.path)
            # print('爬取数据个数的状态码为')
            # print(response.status_code)
            # print(res)
            totalCount = res['data']['search']['total_count']
            # print(totalCount)
            self.logger.info(f"获取{self.vulnName}漏洞总数为{totalCount}")
            return totalCount
        else:
            self.logger.error(f"获取{self.vulnName}漏洞总数失败")


    # getIds()获取尾号,此处写入文件中直接保存即可,方便下次使用
    def getIds(self):
        for i in range(0,int(self.totalCount/25)):
        # for i in range(1, 3):
            data= {"operationName":"HacktivitySearchQuery","variables":{"queryString":"disclosed:true","size":25,"from":(i - 1) * 25,"sort":{"field":"disclosed_at","direction":"ASC"},"product_area":"hacktivity","product_feature":"overview"},"query":"query HacktivitySearchQuery($queryString: String!, $from: Int, $size: Int, $sort: SortInput!) {\n  me {\n    id\n    __typename\n  }\n  search(\n    index: CompleteHacktivityReportIndex\n    query_string: $queryString\n    from: $from\n    size: $size\n    sort: $sort\n  ) {\n    __typename\n    total_count\n    nodes {\n      __typename\n      ... on HacktivityDocument {\n        id\n        _id\n        reporter {\n          id\n          username\n          name\n          __typename\n        }\n        cve_ids\n        cwe\n        severity_rating\n        upvoted: upvoted_by_current_user\n        public\n        report {\n          id\n          databaseId: _id\n          title\n          substate\n          url\n          disclosed_at\n          report_generated_content {\n            id\n            hacktivity_summary\n            __typename\n          }\n          __typename\n        }\n        votes\n        team {\n          id\n          handle\n          name\n          medium_profile_picture: profile_picture(size: medium)\n          url\n          currency\n          __typename\n        }\n        total_awarded_amount\n        latest_disclosable_action\n        latest_disclosable_activity_at\n        submitted_at\n        disclosed\n        has_collaboration\n        __typename\n      }\n    }\n  }\n}\n"}
            data = json.dumps(data)
            max_retries = 3  # 增加重试次数
            retries = 0
            while retries < max_retries:
                retries += 1
                try:
                    response = requests.post(url=self.url, headers=self.headers, data=data)
                    
                    response.raise_for_status()  # 如果响应状态码不是200，会抛出HTTPError

                    # print(response.status_code)

                    res = json.loads(response.text)

                    # print(res)

                    website_tail_ids = res['data']['search']['nodes']
                    # print(website_tail_ids)
                    # print("--------------------爬取第"+str(i)+"页数据------"+str((i-1)*25+1)+"到"+str((i-1)*25+25)+"--------------------")
                    for website_tail_id in website_tail_ids:
                        self.website_tail_id_list.append(website_tail_id['_id'])
                        # print(website_tail_id['_id'])
                        # 数据写到列表里面
                    time.sleep(random.uniform(0.07, 0.47))
                    break  # 如果请求成功，跳出循环
                except Exception as e:
                    self.logger.error(f"第{i}页数据请求失败，正在重试，重试次数{retries}/{max_retries}")


    def saveFile(self, data):
        with open(f"{self.path}/data.json", 'a') as f:
            f.write(data)
            # self.i+=1
            f.close()
        # print('----------hackerone 爬取完成，存入文件----------')
        self.logger.info(f"hackerone 爬取完成，存入文件")

    # getDetail()直接使用爬出保存的尾号,进行使用,获取网站所有json文件保存到data文件夹中,实际会是不是断连,只能记录断连处,分开爬完
    def getDetail(self):
        # 直接读取爬出的尾号,进行使用,免去重复工作
        # with open('list.json','r')as file:
        #     self.website_tail_id_list=json.load(file)
        i = 0
        if os.path.exists(f"{self.path}/data.json"):
            os.remove(f"{self.path}/data.json")
        # i = 8211
        # print(len(self.website_tail_id_list))
        # print(self.website_tail_id_list)

        for website_tail_id in self.website_tail_id_list[i:]:
            i = i + 1
            # print(i)
            # print(self.detail_url+website_tail_id+'.json')
            max_retries = 3  # 增加重试次数
            retries = 0
            while retries < max_retries:
                retries += 1
                try:
                    response = self.get(url=self.detail_url+website_tail_id+'.json')
                    if response==None:
                        self.logger.error(f"第{i}个网址{self.detail_url}{website_tail_id}.json请求失败，返回None")
                        continue
                    # print(type(response.status_code))
                    # print(f"第{i}个网址{self.detail_url}{website_tail_id}.json请求的状态码为{response.status_code}")
                    # print(response.text)
                    res = response.json()
                    # self.detailList.append(res)
                    self.collection.insert_one(res)
                    # time.sleep(random.uniform(0.12, 0.3))
                    time.sleep(random.uniform(0.07, 0.47))
                    
                    break  # 如果请求成功，跳出循环
                except Exception as e:
                    # print(f"第{i}个网址{self.detail_url}{website_tail_id}.json请求失败，正在重试，重试次数{retries}/{max_retries}")
                    self.logger.error(f"第{i}个网址{self.detail_url}{website_tail_id}.json请求失败，正在重试，重试次数{retries}/{max_retries}")

    # # 此处插入数据库直接图形化界面插入的,暂时没有管
    def insertToMongo(self):
        # print('----------hackerone 开始存入数据库----------')
        for root, dirnames, filenames in os.walk(self.path):
            for filename in fnmatch.filter(filenames, '*.json'):
                filepath = os.path.join(root, filename)  # 获取文件的完整路径
                # print(filepath)
                data = jsonToList(filepath)
                insert_mongo(self.collection, data, self.key)
        # 查重
        # queryrepeat(self.vulnName, self.collection, self.key)
        # print('----------hackerone 存入数据库完成----------')
        self.logger.info(f"hackerone 存入数据库完成")


    # def dataPreProc(self):
    #     print('----------hackerone 开始数据预处理----------')
    #     # 先把总数据表中对应数据源所有数据删除
    #     query = {'source': self.vulnName}
    #     result = system.delete_many(query)

    #     collection = self.collection
    #     count =1

    #     for doc in collection.find():
    #         item = init_item(self.vulnName)
    #         item['source'] = self.vulnName
    #         item['source_id'] = doc.get('id')
    #         item['details'] = doc.get('vulnerability_information', 'null')
    #         if item['details'] == "":
    #             print('内容为空')
    #             item['details'] = 'null'
    #         # item['details'] = 'null'

    #         item['date'] = doc.get('created_at','null')
    #         item['title'] = doc.get('title', 'null')
    #         item['vul_id'] = f"012_{str(count).zfill(6)}"
    #         count += 1
    #         item['cve_id'] = doc.get('cve_ids', 'null')
    #         if item['cve_id'] == []:
    #             item['cve_id'] = 'null'
    #         if item['cve_id'] != 'null':
    #             item['software_version'] = isInDeepin(item['cve_id'])
    #         related_data = {key: doc[key] for key in doc if
    #                         key not in ['_id', "reporter", "vulnerability_information", "created_at", "title",
    #                                     "cve_ids"]}
    #         # 将所有字段转换为字符串类型
    #         related_data = {key: str(val) for key, val in related_data.items()}
    #         item['related'] = related_data
    #         # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
    #         self.system.insert_one(item)
    #         print("成功存入"+str(count)+"条数据")

    #     print(f'----------{self.vulnName} 数据预处理完成----------')

    def run(self):
        self.collection.drop()
        self.getIds()
        self.getDetail()
        self.insertToMongo()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')
        # self.dataPreProc()


# if __name__ == '__main__':

#     # 获取当前时间
#     start_time = time.time()

#     # 连接数据库，运行程序
#     client = pymongo.MongoClient('localhost', port=27017)
#     db = client['306Project']
#     collection = db['hackerone']
#     # 每个源数据预处理后存入总数据表，总数据表名称
#     system = db['system']
#     # 删除集合中所有元素
#     collection.delete_many({})
#     obj = hackerone('hackerone',collection,'id',system)
#     obj.run()

#     client.close()

#     # 获取程序结束时间
#     end_time = time.time()
#     # 计算程序耗时
#     duration = end_time - start_time
#     # 打印程序耗时
#     print(f"程序耗时：{duration} 秒")



