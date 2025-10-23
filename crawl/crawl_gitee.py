import json
import random
import re
import time
from multiprocessing.dummy import Pool
import pandas as pd
import requests
from bs4 import BeautifulSoup
from pymongo import MongoClient
from src.dataProceScript.spider_base import BaseSpider
import os
from src.dataProceScript.dataProce import init_item


class gitee(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.THREAD_COUNT = 16
        self.second_urls = []
        self.dic_list = []


    def get_urls(self):
        self.logger.info("开始获取gitee漏洞url")
        # 获取当前文件的绝对路径
        current_file_path = os.path.abspath(__file__)
        # 获取文件所在的文件夹路径
        folder_path = os.path.dirname(current_file_path)
        input_file_path = os.path.join(folder_path,'..','refe_file', 'gitee.xlsx')
        self.logger.info(f"开始读取{input_file_path}文件")
        df = pd.read_excel(input_file_path)
        for index, row in df.iterrows():
            self.second_urls.append(row['URL'])

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
            'Cookie': 'gitee-session-n=bEFPMkJ5cHhXNjl6cGhtbUZ3bmlZaGVnYS9jUlRKc0tKVVhWai84SUh4emdwRXk3SnlUZHE2VEtGS0lwcUlpRHo2anI3QnZUVzk3clU0dldmcEdvYXVZOExiYUU2dDRjMnEyYjdIQVJCbXQ0ckd5YWFwT3l1MExGNEFvVXhCc1F4NW9kczYreVNaVUVUZWtnaldYaVg2TjR4bWZSMkZLY28wa2FkeGJOMGk4SnNsQXlqZ25KRU5YWU9TUXl5NzRtQnhaZWNlV0FxcG10cUFMWGZYbFIzc2h1Y3FteFQvUmVaRjltdDgzMGdtY0F5ZVQzWkZIOUhERzFjNkN2bTdiUWQ2dk80WTQ0RnNtYWZYV2QrWGVtOU0xN1JVK3lzaVZ0WExuR1V2RXVPZ0N0Q1NraW92M3BZMjFrQjd3MXBuSGg3Tm1MN1hhNkhWbDZoSGlZc3JvTFZPVEo5M3U3NmZSaU0rMTZPZUQrcVppTjF5a3JzVEhRZEk3aXpmcnJvQXJZY3JaOTFOOTVjZ3J2YWs1ZVgxNHU2M2R1WStVTXNYMHNCRnRibWJjSnRCWkFUSFd0cXo1ZWZvTFNzaW5NUU5aNWNGeU41cW5BUUV3dXVFVzR3YmZMejNVb3VWbFA4a2Z0TFNOZlhEcWdxZzZiS0FxMjRzcWdBMFpaZkJEZ3VxN1hrclVPTGZTUDZCUzArOTdKNWduWm1VaFNmV2c3MVIzVGF3T3ZiOGIxRXhjMldXZENHTFlyT3FWdGw1bHFJUTBJTkdDRnBTZ1hrTVRMaUxYZ0d2WWlHNzNqNkpQNVpSYnBvVUN5QlpmeDAzc2xxUjgxbUFuN1MrQW9PeDRUNDBlSUtSRU5LdHBWTU1BZ01WR09lcy83WjZwam5qQlFkN2xHaDltNTFjRVJCOUNtcG1TRFBuWmFUR1hKRlg0Yzh2UThOdDUyQUJQT3JkT2l3QUVSb2oydjNCTnN6V2lOdXFNMXQwRUZySk9nRXBCbmZYNkNDaVYwYTNEYTlLeEZ1QjFYVEU0MUNwTFFQUTVjejExM3RCTXRvbUg0ZEVwb0JiNDFlaDJFdFFMYWRzTXpWV0FtSzR3UFExaFhVRnJxK0pjYS0tWWljMXdLbWcvUmhhSmVzRU0vc0Jwdz09--996a8472a80dd31eecc8a8566f2f4b3096859b76; domain=.gitee.com; path=/; HttpOnly'
        }

        return headers

    def extract_cve(self, text):
        # 正则表达式匹配[]中的内容，不区分大小写
        pattern = re.compile(r'\[(.*?)\]', re.IGNORECASE)  # 添加 re.IGNORECASE 标志
        matches = re.findall(pattern, text)

        # 过滤出包含'CVE'的匹配项，不区分大小写
        # 这里不需要再添加 re.IGNORECASE，因为我们只检查字符串中是否包含 'CVE'
        cve_matches = [match for match in matches if 'CVE' in match.upper()]

        return cve_matches

    def detect_type(self,text):
        # 定义正则表达式模式，匹配SQL Injection、XSS、Command Injection、Buffer Overflow、Injection、API
        pattern = re.compile(r'\b(SQL Injection|XSS|Command Injection|Buffer Overflow|Injection|API)\b', re.IGNORECASE)
        # 搜索文本
        if pattern.search(text):
            # 如果找到匹配项，返回找到的第一个匹配项
            return pattern.search(text).group()
        else:
            # 如果没有找到匹配项，返回'null'
            return 'null'

    def singleCrawl(self,url):
        retry_count = 0
        start_time = time.time()
        dic = {
            'title':'null',
            'cve_id':'null',
            'type':'null',
            'detail':'null',
            'date':'null',
            'author':'null',
            'issue-state':'null',

        }
        self.count += 1
        while time.time() - start_time < 30 :
            try:
                req = self.get(url)
                if req is None:
                    self.logger.info(f"{url}请求失败")
                    break
                if req.status_code == 404:
                    # print('404:' + url)
                    self.logger.info(f"404:{url}")
                    self.count -= 1
                    break  
                if req.status_code == 200:
                    dic['second_url'] = url
                    soup = BeautifulSoup(req.text, 'html.parser')
                    spans = soup.find_all('span',id='git-issue-title')
                    if len(spans) > 0:
                            # print(spans[0].text)
                            dic['title'] = spans[0].text
                            if self.extract_cve(spans[0].text) != 'null':
                                if len(self.extract_cve(spans[0].text)) > 0:
                                    dic['cve_id'] = self.extract_cve(spans[0].text)[0]
                            dic['type'] = self.detect_type(spans[0].text)
                    divs = soup.find_all('div',class_='git-issue-description markdown-body')

                    if len(divs) > 0:
                            dic['detail'] = divs[0].text

                    divs = soup.find_all('div',class_='created_at d-align-center ml-2')
                    if len(divs) > 0:
                            spans = divs[0].find_all('span')
                            if len(spans) > 0:
                                dic['date'] = spans[0].text
                    usrs = soup.find_all('div',class_='username')
                    if len(usrs) > 0:
                            dic['author'] = usrs[0].text
                    sts = soup.find_all('i',class_='iconfont icon-task-state-21')
                    if len(sts) > 0:
                            dic['issue-state'] = sts[0].next_sibling.text


                    time.sleep(random.uniform(0.5, 3.5))
                    self.dic_list.append(dic)
                    self.collection.insert_one(dic)
                    break
                else:
                #     # print(f"Request failed with status code: {req.status_code}")
                    if req is not  None:
                        self.logger.error(f"Request failed with status code: {req.status_code}")
                    else:
                        self.logger.error("Request returned None (可能网络错误或请求未完成)")
                    time.sleep(10)
            except requests.exceptions.RequestException as e:
                # print(f"Request failed: {e}")
                self.logger.error(f"Request failed: {e}")
                time.sleep(random.uniform(5, 10))


    def crawl(self):
        # pool = Pool(self.THREAD_COUNT)
        # pool.map(self.singleCrawl, self.second_urls)
        # with open('data.json', 'w', encoding='utf-8') as f:
        #     json.dump(self.dic_list, f, ensure_ascii=False, indent=4)
        # self.logger.info(f"爬取完成，共爬取{self.count}条数据")
        for url in self.second_urls:
            self.singleCrawl(url)


    def giteeToMongo(self, collection):
        # 读取JSON文件并插入到MongoDB
        with open('data.json', 'r', encoding='utf-8') as f:
            data_list = json.load(f)
            collection.insert_many(data_list)
        # 删除data
        os.remove('data.json')


    # def dataPreProc(self):
    #     print(f'----------{self.vulnName}开始数据预处理----------')
    #     collection = self.collection
    #     system = self.system
    #     count = 1
    #     for doc in collection.find():
    #         item = init_item(self.vulnName)
    #         # item['source_id'] = doc['\n\t\tWPVDB ID\t'] if doc['\n\t\tWPVDB ID\t'] is not None else 'null'
    #         item['source_id'] = doc['second_url']
    #         item['date'] = doc['date']
    #         item['details'] = doc['detail']
    #         item['title'] = doc['title']
    #         item['type'] = doc['type']
    #         item['platform'] = 'null'
    #         item['author'] = doc['author']
    #         item['cve_id'] = doc['cve_id']
    #         item['vul_id'] = f"043_{str(count).zfill(6)}"
    #         item['source'] = self.vulnName
    #         item['software_version'] = 'null'
    #         # 其他字段丢进related
    #         related_data = {key: doc[key] for key in doc if
    #                         key not in ['_id', "id", "detail", "type_id", "platform_id"
    #                             , 'author_id', 'code', 'type', 'platform', 'author']}
    #         # 将所有字段转换为字符串类型
    #         related_data = {key: str(val) for key, val in related_data.items()}
    #         item['related'] = related_data
    #         count += 1
    #         # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
    #         system.insert_one(item)
    #     print(f'----------{self.vulnName} 数据预处理完成----------')


    def run(self):
        self.collection.drop()
        self.get_urls()
        # self.second_urls.append('https://gitee.com/earclink/espcms/issues/I5WSA0')
        self.crawl()
        # self.giteeToMongo(self.collection)
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')



# if __name__ == '__main__':
#     start_time = time.time()
#     client = MongoClient('localhost', 27017)
#     db = client['306Project']
#     # 选择集合，如果不存在则MongoDB会自动创建
#     collection = db['gitee']
#     system = db['system']

#     agen = gitee('gitee', 'null', collection, system, 16)
#     agen.run()

#     client.close()
#     # 获取程序结束时间
#     end_time = time.time()
#     # 计算程序耗时
#     duration = end_time - start_time
#     # 打印程序耗时
#     print(f"程序耗时：{duration} 秒")


