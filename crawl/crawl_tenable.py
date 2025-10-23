import os
import time
import pymongo
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import sys

# 导入自定义模块
from src.dataProceScript.Setting import DATA_PATH, CURRENT_TIME
from src.dataProceScript.dataProce import insert_mongo, init_item, isInDeepin
from src.dataProceScript.spider_base import BaseSpider
class tenable(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.key = 'Patch_ID'
        self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        self.session = self.setup_session()

    def setup_session(self):
        """设置请求会话"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; YourBot/0.1)'
        })
        session.mount('https://', requests.adapters.HTTPAdapter(max_retries=3))
        return session

    def extract_text(self, element):
        """提取元素中的文本内容"""
        return element.get_text(strip=True) if element else None

    def crawl(self, cve_id):
        """爬取单个CVE的详细信息"""
        detail_url = f"https://www.tenable.com/security/research/{cve_id}"
        try:
            response = self.session.get(detail_url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            vulname = soup.find('h1', class_='giga hmb')
            #<div class="onethird last">a class="__ptNoRemap"h3 class="widget-header active"
            Patch1=soup.find('div', class_='onethird last')
            Patchs = Patch1.find_all('div')
            pps=Patch1.find_all('a', class_='__ptNoRemap')
            section_elements = soup.find_all('div', class_='widget-content')
            if not section_elements:
                   return None
            if len(section_elements) > 1:
                disclosure_timeline = (self.extract_text(section_elements[3]) if len(section_elements) > 4
                                       else self.extract_text(section_elements[1]) if section_elements else 'null')
            else:
                disclosure_timeline = 'null'

            reference = self.extract_text(section_elements[2]) if len(section_elements) > 4 else 'null'

            # 查找日期，作者,并将日期格式化为YYYY-MM-DD
            date_elements = soup.find('div', class_='onethird last').find('div', class_='widget-container')
            advisory_timeline_content = 'null'
            if date_elements:
                advisory_timeline_header = date_elements.find('h3')
                if advisory_timeline_header and "Advisory Timeline" in advisory_timeline_header.text:
                    advisory_timeline_content = date_elements.find('div', class_='widget-content').text.strip()
                    if advisory_timeline_content:
                        pass
                    else:
                        advisory_timeline_content = 'null'

                    
                   
                            

            author_elements = soup.find('div', class_='onethird last'). find(lambda tag: tag.name == 'div' and 'Credit:' in tag.text)
            if author_elements:
                author_element = author_elements.get_text(strip=True)
                author_element=author_element.replace("Credit:", "").strip()
            else:
                author_element = 'null'
                    
            cve_details = {
                "Patch_ID": self.extract_text(Patchs[0])if len(pps) > 0 else 'null',
                "Patch_Name": self.extract_text(vulname),
                "Source": "Tenable",
                "CVE ID": cve_id,
                'Synopsis': self.extract_text(section_elements[0]),
                'Solution': self.extract_text(section_elements[1]) if len(section_elements) > 2 else 'null',
                'Additional References': reference,
                'Disclosure Timeline': advisory_timeline_content if advisory_timeline_content is not None else 'null',
                'author': author_element
            }
            return cve_details
        except requests.exceptions.RequestException:
            self.logger.error(f"请求 {detail_url} 时出错")
            return None

    def main(self):
        """主函数，爬取CVE列表并获取详细信息"""
        url = 'https://www.tenable.com/security/research'
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            # print('---------- 连接成功，开始爬取----------')
            soup = BeautifulSoup(response.content, 'html.parser')
            vulas = soup.find_all('a', attrs={'hreflang': 'en'})
            for vula in vulas:
                cve_id = vula['href'].split('/')[-1]
                cve_details = self.crawl(cve_id)
                if cve_details:
                    self.collection.insert_one(cve_details)
                    # print(f"CVE {cve_id} 详细信息已保存到数据库。")
                else:
                    # print(f"未能获取CVE {cve_id}的详细信息。")
                    self.logger.error(f"未能获取CVE {cve_id}的详细信息。")
        except requests.exceptions.RequestException as e:
            # print(f"请求 {url} 时出错: {e}")
            self.logger.error(f"请求 {url} 时出错: {e}")

    def run(self):
        self.collection.drop() 
        self.main()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据') 


    # def dataPreProc(self):
    #     """数据预处理函数"""
    #     print('---------- 开始数据预处理----------')
    #     collection = self.collection
    #     # system = self.system
    #     count = 1
    #     query = {'source': self.vulnName}
    #     result = system.delete_many(query)
    #     print(f"删除了 {result.deleted_count} 条数据。")
    #     for doc in collection.find():
    #         item = init_item(self.vulnName)
    #         item['cve_id'] = doc['Patch_ID'] if doc['Patch_ID'] is not None else 'null'
    #         if item['cve_id'] != 'null':
    #             item['software_version'] = isInDeepin(item['cve_id'])

    #         item['date'] = doc['Disclosure Timeline'] if doc['Disclosure Timeline'] is not None else 'null'
    #         item['title'] = doc['Patch_Name'] if doc['Patch_Name'] is not None else 'null'
    #         item['source_id'] = doc['CVE ID'] if doc['CVE ID'] is not None else 'null'
    #         item['source'] = doc['Source'] if doc['Source'] is not None else 'null'
    #         item['details'] = doc['Synopsis'] if doc['Synopsis'] is not None else 'null'
    #         item['vul_id'] = f"016_{str(count).zfill(6)}"
    #         item['author']=doc['author'] if doc['author'] is not None else 'null'
    #         count += 1
    #         related_data = {key: doc[key] for key in doc if
    #                         key not in ['_id', "Patch_ID", "Disclosure Timeline", "Patch_Name", "Source_ID", "Source",
    #                                     "Synopsis"]}
    #         related_data = {key: str(val) for key, val in related_data.items()}
    #         item['related'] = related_data
    #         system.insert_one(item)
    #     print('---------- 数据预处理完成----------')

# if __name__ == '__main__':
#     start_time = time.time()
#     myclient = pymongo.MongoClient('localhost', 27017)
#     db = myclient['306Project']
#     collection = db['tenable']
#     system = db['system']
#     obj = Tenable('tenable', collection, 'Patch_ID', system)
#     obj.main()
#     obj.dataPreProc()  # 数据预处理只需在main函数结束后执行一次
#     end_time = time.time()
#     duration = end_time - start_time
#     print(f"程序耗时：{duration} 秒")