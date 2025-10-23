import json
import os
import random
import time

import requests
from bs4 import BeautifulSoup
from lxml import etree
from pymongo import MongoClient
from requests.exceptions import RequestException, ConnectTimeout, ConnectionError

from src.dataProceScript.Setting import DATA_PATH, CURRENT_TIME
from src.dataProceScript.dataProce import insert_mongo, init_item
from src.dataProceScript.spider_base import BaseSpider


class ffmpeg(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.key = 'title'
        self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        self.start_url = 'https://trac.ffmpeg.org/'
        self.page = 32
        self.max_retries = 3  # 最大重试次数
        self.timeout = 10     # 请求超时时间

    def crawlAndStorage(self):
        self.logger.info('----------开始爬取ffmpeg漏洞----------')
        url = self.start_url + 'query?page={}'
        for i in range(1, self.page):
            current_url = url.format(i)
            retries = 0
            success = False
            
            while retries < self.max_retries and not success:
                try:
                    res = requests.get(url=current_url, timeout=self.timeout)
                    if res and res.status_code == 200:
                        soup = BeautifulSoup(res.text, 'html.parser')
                        tree = etree.HTML(str(soup))
                        process_list = tree.xpath("//td[@class='summary']/a")
                        
                        for process in process_list:
                            p = process.xpath("./@href")
                            detail_url = 'https://trac.ffmpeg.org' + p[0]
                            self.getDetail(detail_url)
                            time.sleep(random.uniform(0.2, 1.5))
                            
                        success = True  # 标记当前页处理成功
                        
                    else:
                        self.logger.error(f"{current_url} 请求失败")
                        break
                        
                except (ConnectTimeout, ConnectionError) as e:
                    retries += 1
                    self.logger.warning(f"连接超时 ({current_url})，第 {retries}/{self.max_retries} 次重试...")
                    if retries >= self.max_retries:
                        self.logger.error(f"{current_url} 重试{self.max_retries}次后失败：{str(e)}")
                    time.sleep(5)
                    
                except RequestException as e:
                    self.logger.error(f"请求异常 ({current_url})：{str(e)}")
                    break
                    
                except Exception as e:
                    self.logger.error(f"未知错误 ({current_url})：{str(e)}")
                    break

    def getValue(self, response, key):
        try:
            res = response.xpath(key)
            return res if res else ['null']
        except Exception as e:
            self.logger.warning(f"XPath解析失败：{str(e)}")
            return ['null']
    def getDetail(self, detail_url):
        retries = 0
        success = False
        
        while retries < self.max_retries and not success:
            try:
                res = requests.get(url=detail_url, timeout=self.timeout)
                if res and res.status_code == 200:
                    soup = BeautifulSoup(res.text, 'html.parser')
                    response = etree.HTML(str(soup))
                    
                    try:
                        detail_summary = self.getValue(response, "//span[@class='summary']/text()")[0]
                        detail_status = self.getValue(response, "//span[@class='trac-status']/a/text()")[0]
                        detail_type = self.getValue(response, "//span[@class='trac-type']/a/text()")[0]
                        h_reporter = self.getValue(response, "//a[@class='trac-author']/text()")[0]
                        h_owner = self.getValue(response, "//td[@headers='h_owner']/a/text()")[0]
                        h_priority = self.getValue(response, "//td[@headers='h_priority']/a/text()")[0]
                        h_component = self.getValue(response, "//td[@headers='h_component']/a/text()")[0]
                        h_vesion = self.getValue(response, "//td[@headers='h_version']/a/text()")[0]

                        h_keywords = ''
                        keywords_list = self.getValue(response, "//td[@headers='h_keywords']/a")
                        if keywords_list != ['null']:
                            for list in keywords_list:
                                t = self.getValue(list, "./text()")[0]
                                h_keywords = h_keywords + str(t) + ' '

                        h_reproduced = self.getValue(response, "//td[@headers='h_reproduced']/a/text()")[0]
                        h_analyzed = self.getValue(response, "//td[@headers='h_analyzed']/a/text()")[0]

                        h_cc = ''
                        cc_list = self.getValue(response, "//td[@headers='h_cc']/a")
                        if cc_list != ['null']:
                            for list in cc_list:
                                t = list.xpath("./text()")[0]
                                h_cc = h_cc + str(t) + ' '

                        h_blockedby = self.getValue(response, "//td[@headers='h_blockedby']/a/text()")[0]
                        h_blocking = self.getValue(response, "//td[@headers='h_blocking']/a/text()")[0]

                        description_list = self.getValue(response, "//div[@class='searchable']//text()")
                        detail_description = ''
                        if description_list != ['null']:
                            for list in description_list:
                                if list.strip() == "":
                                    pass
                                else:
                                    detail_description = detail_description + str(list) + " "

                        changelog_list = self.getValue(response, "//div[@id='changelog']//text()")
                        detail_changelog = ''
                        if changelog_list != ['null']:
                            for list in changelog_list:
                                if list.strip() == "":
                                    pass
                                else:
                                    detail_changelog = detail_changelog + str(list) + " "

                        item = {
                            'title': str(detail_summary),
                            'status': str(detail_status),
                            'type': str(detail_type),
                            'reporter': str(h_reporter),
                            'owner': str(h_owner),
                            'priority': str(h_priority),
                            'component': str(h_component),
                            'vesion': str(h_vesion),
                            'keywords': str(h_keywords),
                            'missing': str(h_cc),
                            'blockedby': str(h_blockedby),
                            'blocking': str(h_blocking),
                            'Isreproduced': str(h_reproduced),
                            'Isanalyzed': str(h_analyzed),
                            'description': str(detail_description),
                            'changelog': str(detail_changelog)
                        }

                        # 插入MongoDB
                        self.collection.insert_one(item)
                        
                        # 写入本地文件（确保可序列化）
                        with open(os.path.join(self.path, "data.json"), 'a', encoding='utf-8') as f:
                            # 复制item并移除任何不可序列化的字段（如ObjectId）
                            json_item = item.copy()
                            if '_id' in json_item:
                                del json_item['_id']
                            f.write(json.dumps(json_item, ensure_ascii=False))
                            f.write(',\n')
                        
                        success = True
                        
                    except Exception as parse_error:
                        self.logger.error(f"解析详情页失败 ({detail_url})：{str(parse_error)}")
                        break
                        
                else:
                    self.logger.error(f"{detail_url} 请求失败，状态码：{res.status_code}")
                    break
                    
            except (ConnectTimeout, ConnectionError) as e:
                retries += 1
                self.logger.warning(f"详情页连接超时 ({detail_url})，第 {retries}/{self.max_retries} 次重试...")
                if retries >= self.max_retries:
                    self.logger.error(f"{detail_url} 重试{self.max_retries}次后失败：{str(e)}")
                time.sleep(5)
                
            except RequestException as e:
                self.logger.error(f"详情页请求异常 ({detail_url})：{str(e)}")
                break
                
            except Exception as e:
                self.logger.error(f"处理详情页时未知错误 ({detail_url})：{str(e)}")
                break
    def dataPreProc(self):
        self.logger.info('----------ffmpeg 开始数据预处理----------')
        collection = self.collection
        system = self.system
        count = 1
        query = {'source': self.vulnName}
        system.delete_many(query)
        
        for doc in collection.find():
            try:
                item = init_item(self.vulnName)
                item.update({
                    'author': doc.get('reporter', 'null'),
                    'details': doc.get('description', 'null'),
                    'title': doc.get('title', 'null'),
                    'type': doc.get('type', 'null'),
                    'vul_id': f"014_{str(count).zfill(6)}",
                    'cve_id': 'null',
                    'software_version': 'null',
                })
                related_data = {k: str(v) for k, v in doc.items() if k not in ['_id', "reporter", "description", "title", "type"]}
                item['related'] = related_data
                system.insert_one(item)
                count += 1
            except Exception as e:
                self.logger.error(f"数据预处理失败：{str(e)}")
                continue
                
        self.logger.info('----------ffmpeg 数据预处理完成----------')

    def run(self):
        try:
            self.collection.drop()
            self.crawlAndStorage()
            self.count = self.collection.count_documents({})
            self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')
        except Exception as e:
            self.logger.critical(f"爬虫运行失败：{str(e)}")
            raise

# if __name__ == '__main__':
#     client = MongoClient('localhost', 27017)
#     db = client['306Project']
#     collection = db['ffmpeg']
#     system = db['system']
    
#     spider = ffmpeg(db, 'ffmpeg')
#     try:
#         spider.run()
#     finally:
#         client.close()