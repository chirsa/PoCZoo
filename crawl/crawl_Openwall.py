import os
import random
import re
import time
import pymongo
import requests
from bs4 import BeautifulSoup
from fake_headers import Headers
from urllib.parse import urljoin

from requests.exceptions import RequestException, ConnectTimeout, ConnectionError
from src.dataProceScript.spider_base import BaseSpider
from src.dataProceScript.Setting import DATA_PATH, CURRENT_TIME
from src.dataProceScript.dataProce import insert_mongo_one, init_item

class Openwall(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.key =  'title'
        self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        self.url = "https://www.openwall.com/lists/oss-security/"
        # header = Headers(browser='chrome',
        #                  os='win',
        #                  headers=True).generate()
        # self.headers = {
        #     'User-Agent': header['User-Agent'],
        #     'Host': 'www.openwall.com',
        # }
        self.count = 0
        self.max_retries = 3  # 最大重试次数
        self.timeout = 10     # 请求超时时间（秒）

    def safe_request(self, url, headers=None):
        """带超时重试的请求方法"""
        retries = 0
        while retries < self.max_retries:
            try:
                header = Headers(browser='chrome', os='win', headers=True).generate()
                final_headers = {
                    'User-Agent': header['User-Agent'],
                    'Host': 'www.openwall.com',
                }
                response = requests.get(
                    url, 
                    headers=final_headers,
                    timeout=self.timeout  # 连接+读取总超时
                )
                response.raise_for_status()  # 检查 HTTP 错误状态
                return response
            except requests.exceptions.Timeout:
                self.logger.warning(f"请求超时 ({url}), 正在重试 ({retries+1}/{self.max_retries})")
                retries += 1
                time.sleep(random.uniform(1, 3) * (retries + 1))
            except requests.exceptions.RequestException as e:
                self.logger.error(f"请求异常 ({url})：{str(e)}")
                break
        return None  # 全部重试失败
    def crawl(self):
        try:
            flag = False
            # res = requests.get(url=self.url, headers=self.headers)
            res = self.safe_request(self.url)  # 使用安全请求方法
            if res.status_code == 200:
                soup = BeautifulSoup(res.text, 'html.parser')
                table = soup.find('table',class_='cal_brief')
                a_s = table.find_all('a')
                for a in a_s:
                    href = a.get('href')
                    if len(href) == 8:
                        # print(href)
                        self.getMonthList(href)
                        time.sleep(random.uniform(1,3))
        except Exception as e:
            self.logger.error(f"主页面爬取失败：{str(e)}")
                  
    def getMonthList(self,month_url):
        try:
            full_url = urljoin(self.url, month_url)
            res = self.safe_request(full_url)
            if res and res.status_code == 200:
                soup = BeautifulSoup(res.text, 'html.parser')
                ul = soup.find_all('ul')
                for u in ul:
                    a_s = u.find_all('a')
                    for a in a_s:
                        href = a.get('href')
                        # print(href)
                        if href is not None:
                            if self.check_pattern(href):
                                detail_url =  month_url + href
                                # print(detail_url)
                                self.getDetail(detail_url)
                                time.sleep(random.uniform(0.2, 3))
        except Exception as e:
            self.logger.error(f"月份列表爬取失败 ({month_url})：{str(e)}")


    def check_pattern(self,input_string):
        pattern1 = r'\d{2}/\d'
        pattern2 = r'\d{2}/\d{2}'
        pattern3 = r'\d{2}/\d{3}'
        if re.fullmatch(pattern1, input_string) or re.fullmatch(pattern2, input_string) or re.fullmatch(pattern3, input_string):
            return True
        else:
            return False
        
    def clean_value(self, match):
        """清洗正则匹配结果"""
        if match:
            value = match.group(1).strip()
            # 处理HTML转义字符
            value = value.replace('&lt;', '<').replace('&gt;', '>')
            # 移除尾部多余符号
            return re.sub(r'[;\s]*$', '', value)
        return ""

    def getDetail(self,detail_url):
        try:
            url = urljoin(self.url, detail_url)
            res = self.safe_request(url)
            if res and res.status_code == 200 :
                # soup = BeautifulSoup(res.text, 'html.parser')
                # response = etree.HTML(str(soup))
                # text = response.xpath('/html/body/pre/text()')[0]
                # # print(text)

                soup = BeautifulSoup(res.text, 'html.parser')
                pre_tag = soup.find('pre')

                # 初始化字段变量
                date = from_field = to = subject = description_text = ""

                if pre_tag:
                    # 获取pre标签全部文本内容
                    raw_text = pre_tag.get_text()
                    
                    # 使用正则表达式提取关键字段
                    date_match = re.search(r'Date:\s*([^\n]+)', raw_text)
                    from_match = re.search(r'From:\s*([^\n]+)', raw_text)
                    to_match = re.search(r'To:\s*([^\n]+)', raw_text)
                    subject_match = re.search(r'Subject:\s*([^\n]+)', raw_text)
                    
                    # 处理提取结果
                    date_text = self.clean_value(date_match)
                    

                    from_field = self.clean_value(from_match)
                    to = self.clean_value(to_match)
                    subject = self.clean_value(subject_match)
                    cve_ids = ['null']  # 默认值
                    if subject:  # 仅当 subject 存在时尝试提取
                        cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', subject, re.IGNORECASE)
                        if cve_matches:
                            cve_ids = list(set(cve_matches))  # 去重
                            # print(f"提取到 CVE：{cve_ids}")
                    
                    description_text = raw_text  # 保留原始文本



            vulnerability = {
                'Date': date_text,
                'From': from_field,
                'To': to,
                'title': subject,  # 使用提取的subject
                'Description': description_text,
                'CVE-id': cve_ids[0]
            } 
        except Exception as e:
            self.logger.error(f"详情页爬取失败 ({detail_url})：{str(e)}") 


        self.collection.insert_one(vulnerability)  

    def itemToMongo(self, item):
        # print(f"准备插入数据：{item['title']}")  # 添加调试日志
        insert_mongo_one(self.collection, item, self.key)
        # print(f"插入数据：{item['title']}")
        


#     def run(self):
#         self.crawl()


# if __name__ == '__main__':
#     start_time = time.time()
#     myclient = pymongo.MongoClient('localhost', port=27017)
#     db = myclient['306Project']
#     collection = db['openwall']
#     system = db['system']
#     obj = openwall('openwall', collection, 'title',system)
#     obj.run()
#     end_time = time.time()
#     # 计算程序耗时
#     duration = end_time - start_time
#     # 打印程序耗时
#     print(f"程序耗时：{duration} 秒")
    def run(self):
        try:
            self.collection.drop()
            self.crawl()
            self.count = self.collection.count_documents({})
            self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')
            # self.dataPreProc()  # 按需启用
        except Exception as e:
            self.logger.critical(f"爬虫运行失败：{str(e)}")
            raise