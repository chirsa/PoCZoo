import json
import logging
import re
import os


from concurrent.futures import ThreadPoolExecutor

import requests
from bs4 import BeautifulSoup as bs
from fake_headers import Headers
from pymongo import MongoClient
from requests.adapters import HTTPAdapter
from urllib3 import Retry


# from src.dataProceScript.Setting import DATA_PATH, CURRENT_TIME
from src.dataProceScript.dataProce import init_item, isInDeepin, getDeepin
from src.dataProceScript.spider_base import BaseSpider
# 设置日志


class codeSecurity(BaseSpider):

    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        # self.vulnName = vulnName
        # self.collection = collection
        self.failed_requests_count = 0  # 添加一个属性来记录失败的请求次数
        # self.system = system
        # self.key = key
        # self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        # if not os.path.exists(self.path):
        #     os.makedirs(self.path)

        self.session = requests.Session()
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[502, 503, 504])
        self.session.mount('https://', HTTPAdapter(max_retries=retries))
        # self.deepin2309, self.deepin2404 = getDeepin()

        header = Headers(browser='chrome',
                         os='win',
                         headers=True).generate()
        self.headers = {
            'User-Agent': header['User-Agent'],
            'Host': 'securitylab.github.com',
            'cookie': "HWWAFSESID=4eecb763af3286c2d6; HWWAFSESTIME=1713232623934; sensorsdata2015jssdkcross=%7B%22distinct_id%22%3A%2218ee49f44ebc37-0299ab94671a326-4c657b58-3686400-18ee49f44ec1243%22%2C%22first_id%22%3A%22%22%2C%22props%22%3A%7B%22%24latest_traffic_source_type%22%3A%22%E7%9B%B4%E6%8E%A5%E6%B5%81%E9%87%8F%22%2C%22%24latest_search_keyword%22%3A%22%E6%9C%AA%E5%8F%96%E5%88%B0%E5%80%BC_%E7%9B%B4%E6%8E%A5%E6%89%93%E5%BC%80%22%2C%22%24latest_referrer%22%3A%22%22%7D%2C%22identities%22%3A%22eyIkaWRlbnRpdHlfY29va2llX2lkIjoiMThlZTQ5ZjQ0ZWJjMzctMDI5OWFiOTQ2NzFhMzI2LTRjNjU3YjU4LTM2ODY0MDAtMThlZTQ5ZjQ0ZWMxMjQzIn0%3D%22%2C%22history_login_id%22%3A%7B%22name%22%3A%22%22%2C%22value%22%3A%22%22%7D%2C%22%24device_id%22%3A%2218ee49f44ebc37-0299ab94671a326-4c657b58-3686400-18ee49f44ec1243%22%7D; agreed-cookiepolicy=120240314; Hm_lvt_ace49cc6c2f3d0542e97ce86732094dc=1713232696; Hm_lpvt_ace49cc6c2f3d0542e97ce86732094dc=1713426198"
        }

    def crawl(self):
        url = f'https://securitylab.github.com/advisories/'
        # proxies_list = [
        #     {'ip': '220.161.241.226', 'port': '4345'},
        #     {'ip': '111.227.122.233', 'port': '4335'},
        #     {'ip': '175.167.1.130', 'port': '4302'},
        #     {'ip': '223.242.222.46', 'port': '4345'},
        # ]
        # 目标URL
        # 遍历代理列表并尝试每个代理
        # for proxy in proxies_list:
        try:
                # 构造代理地址
                # proxy_address = f"http://{proxy['ip']}:{proxy['port']}"
                # # 设置代理
                # proxies = {
                #     'http': proxy_address,
                #     'https': proxy_address
                # }
        # print(f'----------开始爬取 {url} ----------')

                response = self.session.get(url, headers=self.headers, timeout=30)

                response.raise_for_status()  # 检查请求是否成功
                html = response.text
                return html
        except requests.exceptions.HTTPError as errh:
        #    print(f'HTTP Error: {errh}')
            self.logger.error(f'HTTP Error: {errh}')
        # except requests.exceptions.ConnectionError as errc:
        #     logging.error(f'Error Connecting: {errc}')
        # except requests.exceptions.Timeout as errt:
        #     logging.error(f'Timeout Error: {errt}')
        # except requests.exceptions.RequestException as err:
        #     logging.error(f'OOps: Something Else: {err}')


    def parse_page(self, html):
        soup = bs(html, 'html.parser')
        exploits = []
        count = 0
        # 查找所有的 <div> 标签
        div_tags = soup.find_all('div', class_='col-12 col-md-9')
        for div in div_tags:
            # 在每个 <div> 标签中查找 <a> 标签并获取 href 属性
            a_tag = div.find('a', href=True)
            if a_tag:
                href = a_tag['href']
                exploit = {
                    'link': f'https://securitylab.github.com{href}'
                }
                exploits.append(exploit)
                count +=1
        # print(f'找到的漏洞链接数量: {count}')  # 输出找到的链接数量
        # logging.info(f'找到的漏洞链接数量: {count}')

        return exploits


    def crawl_detail(self, exploit):

        # print(f'----------开始爬取详细信息 {exploit["link"]} ----------')
        # self.logger.info(f'----------开始爬取详细信息 {exploit["link"]} ----------')
        try:
            response = self.session.get(exploit["link"], headers=self.headers, timeout=30)

            response.raise_for_status()  # 检查请求是否成功
            html = response.text
            soup = bs(html, 'html.parser')

            # 提取详细信息
            source = exploit["link"]

            title = soup.find(attrs={'class': 'page-title mb-3 mb-md-4'}).text.strip() if soup.find(
                attrs={'class': 'page-title mb-3 mb-md-4'}) else 'null'
            #
            a_tag = soup.find('a', class_='sc-frDJqD')
            author = a_tag.find('span').text.strip() if a_tag and a_tag.find('span') else 'null'

            h2_tag = soup.find('h2',id = 'coordinated-disclosure-timeline')
            if h2_tag:
                date_line = h2_tag.find_next_sibling() 
                if date_line:
                    full_date_info = date_line.find_all('li')[0].text.strip() if date_line.find_all('li') else 'null'
                    date =  full_date_info.split(':')[0].strip() if full_date_info != 'null' else 'null'



            
            h2_tag = soup.find('h2', id='details')
            # 获取 <h2> 标签下所有子标签
            if h2_tag:
            # 初始化内容列表
                details = []
                        
                for tag in h2_tag.find_all_next():
                # 如果遇到下一个 <h2> 标签，则停止
                    if tag.name == 'h2':
                        break
                # 获取文本，去除空白
                    if tag.name in ['p', 'h3', 'h4', 'ul']:
                         details.append(tag.get_text(strip=True)) if tag.get_text(strip=True) else None
                         # 处理 <div> 标签
                    if tag.name == 'pre':
                        details.append(tag.get_text(strip=True)) if tag.get_text(strip=True) else None
                   
                    

            h2_tag = soup.find('h2', id='contact')
            # 如果找到了 <h2> 标签，搜索其后的首个 <p> 标签
            if h2_tag:
                p_tag = h2_tag.find_next_sibling() if h2_tag.find_next_sibling() else None
                if p_tag:
                   contact= p_tag.text.strip() if p_tag.text.strip() else 'null'

            h2_tag = soup.find('h2', id='tested-version')
            # 如果找到了 <h2> 标签，搜索其后的首个 <p> 标签
            if h2_tag:
                p_tag = h2_tag.find_next_sibling() if h2_tag.find_next_sibling() else None
                if p_tag:
                    testedversion = p_tag.text.strip()  if p_tag.text.strip() else 'null'

            h2_tag = soup.find('h2', id='cve')
            # 如果找到了 <h2> 标签，搜索其后的首个 <p> 标签
            if h2_tag:
                p_tag = h2_tag.find_next_sibling() if h2_tag.find_next_sibling() else None
                if p_tag:
                    cve_id = p_tag.find('li').text.strip() if p_tag.find('li') else 'null'

            h2_tag = soup.find('h2', id='summary')
            # 如果找到了 <h2> 标签，搜索其后的首个 <p> 标签
            if h2_tag:
                p_tag = h2_tag.find_next_sibling() if h2_tag.find_next_sibling() else None
                if p_tag:
                    summary = p_tag.text.strip() if p_tag.text.strip() else 'null'

            exploit = {
                'url': source,
                # 'source_id': '',
                'title': title,
                'author': author,
                'cve_id': cve_id,
                'contact':contact,
                ' testedversion': testedversion,
                'details': details,
                'date': date,
                'summary':summary    
            }
            # print(exploit)
            self.collection.insert_one(exploit)
            # print(f'成功爬取详细信息 {exploit["link"]}')

            return exploit
        except requests.RequestException as e:
            # print(f'请求失败：{e}')
            self.logger.error(f'请求失败：{e}')
            self.failed_requests_count += 1  # 增加失败请求的计数
            return None



    def save_to_file(self, exploits):
        filename = f'sercurity_page.json'
        filepath = os.path.join(self.path, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(exploits, f, ensure_ascii=False, indent=4)
        # print(f'----------数据存入文件 {filename} ----------')

    def insert_to_mongo(self, exploits):
        # print('----------开始存入数据库----------')
        for exploit in exploits:
            self.collection.insert_one(exploit)
        # print('----------存入数据库完成----------')

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
            item['date'] = doc.get('date', 'null')
            item['details'] = doc.get('details', 'null')
            item['title'] = doc.get('title', 'null')
            item['author'] = doc.get('author', 'null')
            item['type'] = doc.get('type', 'null')
            item['cve_id'] = doc.get('cve_id', 'null')
            item['source_id'] = doc.get('source_id', 'null')
            item['platform'] = doc.get('platform', 'null')

            item['vul_id'] = f"0039_{str(count).zfill(6)}"
            count += 1

            if item['cve_id'] != 'null':
                item['software_version'] = isInDeepin(item['cve_id'], self.deepin2309, self.deepin2404)
            # 其他字段丢进related
            related_data = {key: doc[key] for key in doc if
                            key not in ['vul_id', "cve_id", "title", 'source_id', "platform",
                                        'author', 'type', 'platform',  '_id', 'details', 'date']}
            # 将所有字段转换为字符串类型
            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data

            # 数据预处理前存入的数据库已经做过去重，这里可以直接存进
            system.insert_one(item)

        print('----------curl 数据预处理完成----------')

    def run(self):
        self.collection.drop()

        with ThreadPoolExecutor(max_workers=8) as executor:
            # print(f'开始爬取页面 ')
            self.logger.info(f'开始爬取页面 ')
            html = self.crawl()
            if html:
                exploits = self.parse_page(html)
                for exploit in exploits:
                    executor.submit(self.crawl_and_process_page, exploit)
        self.final_report()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')

    def crawl_and_process_page(self, exploit):
        """爬取单个页面并处理数据"""
        exploit_detail = self.crawl_detail(exploit)
        if exploit_detail:
            # 保存单个详细数据到文件和数据库，而不是全部之后再保存
            # self.save_to_file([exploit_detail])
            self.insert_to_mongo([exploit_detail])
        else:
        #   print(f'页面没有找到漏洞信息')
            self.logger.error(f'页面没有找到漏洞信息')

    def final_report(self):
        # 程序结束前打印失败请求的统计信息
    #   print(f'总共有 {self.failed_requests_count} 个请求失败')
        self.logger.error(f'总共有 {self.failed_requests_count} 个请求失败')




      
# if __name__ == '__main__':
#     # 获取当前时间
#     import time

#     start_time = time.time()

#     # 连接数据库，运行程序
#     client = MongoClient('localhost', port=27017)
#     db = client['306Project']
#     collection = db['securitylab']
#     # 每个源数据预处理后存入总数据表，总数据表名称
#     system = db['system']

#     obj = Security('security', collection, 'id', system)
#     obj.run()
#     obj.dataPreProc()
#     obj.final_report()

#     client.close()

#     # 获取程序结束时间
#     end_time = time.time()
#     # 计算程序耗时
#     duration = end_time - start_time
#     # 打印程序耗时
#     print(f"程序耗时：{duration} 秒")
