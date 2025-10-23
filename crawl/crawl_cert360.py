import json
import os
import random
import shutil
import time

import requests
from bs4 import BeautifulSoup
from pymongo import MongoClient
import sys
# print(sys.path)
# from src.dataProceScript.Setting import DATA_PATH, CURRENT_TIME
from src.dataProceScript.dataProce import insert_mongo, init_item, getDeepin
from src.dataProceScript.spider_base import BaseSpider

class cert360(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        # self.vulnName = vulnName
        # self.collection = collection
        # self.system = system
        self.key = 'url'
        # self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        # if not os.path.exists(self.path):
        #     os.makedirs(self.path)
        self.page = self.getPage()
        # self.deepin23beta3, self.deepin2404 = getDeepin()  没有cveid不需要做deepin关联漏洞处理


    def getPage(self):
        url = "https://cert.360.cn/report/searchbypage?length=10&start=0"
        data = self.get(url)
        a = json.loads(data.text)
        page = int(a['recordsTotal']/10)
        # print(f'一共需要爬取{page}页!!!')
        self.logger.info(f'一共需要爬取{page}页!!!')
        return page
    def crawlAndstorage(self):
        # print(f'----------{self.vulnName} 开始爬取----------')
        self.logger.info(f'----------{self.vulnName} 开始爬取----------')

        # fw = open(os.path.join(self.path, "url-安全报告.txt"), "a", encoding="utf-8")
        # fw1 = open(os.path.join(self.path, "cert360-安全报告.json"), "a", encoding="utf-8")
        # fw1.write('[\n')
        for i in range(0, self.page+1):
            url = "https://cert.360.cn/report/searchbypage?length=10&start=" + str(i * 10)
            data = self.get(url)
            if data.status_code!= 200 or data==None:
                continue
            a = json.loads(data.text)
            for d1 in a['data']:
                url = d1['id']
                url1 = "https://cert.360.cn/report/detail?id=" + url
                o = {
                    "add_time_str": d1['add_time_str'] if 'add_time_str' in d1.keys() else '',
                    "description": d1['description'] if 'description' in d1.keys() else '',
                    "title": d1['title'] if 'title' in d1.keys() else '',
                    "update_time_str": d1['update_time_str'] if 'update_time_str' in d1.keys() else '',
                    "tag": d1['tag'] if 'tag' in d1.keys() else '',
                    "url": url1
                }
                random_time = random.uniform(0.2, 2)
                time.sleep(random_time)
                data1 = self.get(url1)
                soup = BeautifulSoup(data1.text, "html.parser")
                text_list = []
                text_list_names = []
                flag = True
                for link in soup.findAll(name="div", attrs={"class": "news-content"}):
                    for content in link.contents:
                        if content != '\n':
                            if content.name == "h2":  # or content.name=='h3':
                                text_list_names.append(content.get_text())
                                flag = False
                            elif content.name == "table":
                                if flag == False:
                                    text_list.append(str(content))
                                    flag = True
                                else:
                                    if len(text_list) == 0:
                                        text_list.append(str(content))
                                    else:
                                        text_list[-1] = text_list[-1] + "\n" + str(content)
                            else:
                                if flag == False:
                                    text_list.append(str(content.get_text()))
                                    flag = True
                                else:
                                    if len(text_list) == 0:
                                        text_list.append(str(content.get_text()))
                                    else:
                                        text_list[-1] = text_list[-1] + "\n" + content.get_text()
                o["base"] = text_list[0]
                for t_i in range(1, len(text_list)):
                    o[text_list_names[t_i - 1]] = text_list[t_i]

                # fw.write(url1 + "\n")
                # fw.flush()
                # fw1.write(json.dumps(o, ensure_ascii=False) + ",\n")
                res = [o]
                insert_mongo(self.collection, res, self.key)
            random_time = random.uniform(0.2, 2)
            time.sleep(random_time)
        # fw.close()
        # fw1.write(']')
        # fw1.close()

    def dataPreProc(self):
        # print(f'----------{self.vulnName} 开始数据预处理----------')
        self.logger.info(f'----------{self.vulnName} 开始数据预处理----------')
        collection = self.collection
        system = self.system
        # 先把总数据表中对应数据源所有数据删除
        query = {'source': self.vulnName}
        result = system.delete_many(query)
        # 先把总数据表中对应数据源所有数据删除
        query = {'source': '360CERT'}
        result = system.delete_many(query)
        # print(f"删除了 {result.deleted_count} 条数据。")
        count = 1
        for doc in collection.find():
            item = init_item(self.vulnName)

            base = doc['base'] if doc['base'] is not None else 'null'
            item['source_id'] = base[base.find('报告编号：') + 5:base.find('报告来源')]

            item['date'] =  doc['update_time_str'] if doc['update_time_str'] is not None else 'null'
            item['details'] = doc['description'] if doc['description'] is not None else 'null'
            item['title'] = doc['title'] if doc['title'] is not None else 'null'
            item['author'] = '360CERT'

            item['vul_id'] = f"005_{str(count).zfill(6)}"
            item['cve_id'] = 'null'
            item['software_version'] = 'null'
            count += 1

            # 其他字段丢进related
            related_data = {key: doc[key] for key in doc if
                            key not in ['_id',"update_time_str", "title", "description"]}
            # 将所有字段转换为字符串类型
            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data
            # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
            system.insert_one(item)
        # print(f'----------{self.vulnName} 数据预处理完成----------')
        self.logger.info(f'----------{self.vulnName} 数据预处理完成----------')


    def run(self):
        self.collection.drop()
        self.crawlAndstorage()
        # self.dataPreProc()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')


# if __name__ == '__main__':
#     # 获取当前时间
#     start_time = time.time()
#     # 连接 MongoDB 数据库
#     client = MongoClient('localhost', 27017)
#     # 获取指定数据库和集合
#     db = client['306Project']
#     collection = db['360CERT']

#     system = db['system']
#     agent = cert360('360CERT', collection, 'url', system)

#     agent.run()

#     client.close()
#     # 获取程序结束时间
#     end_time = time.time()
#     # 计算程序耗时
#     duration = end_time - start_time
#     # 打印程序耗时
#     print(f"程序耗时：{duration} 秒")
