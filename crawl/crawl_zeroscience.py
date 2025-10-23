import os
import time
import random
import requests
from bs4 import BeautifulSoup as bs
from pymongo import MongoClient
from src.dataProceScript.spider_base import BaseSpider

from src.dataProceScript.Setting import DATA_PATH, CURRENT_TIME
from src.dataProceScript.dataProce import insert_mongo, queryrepeat, init_item, getDeepin, isInDeepin


class zeroscience(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.key = "Advisory_ID"
        self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        self.url = ("https://www.zeroscience.mk/en/vulnerabilities/")
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"}

        self.dataList = []
        self.deepin23beta3, self.deepin2404 = getDeepin()

    def crawl(self):
        # print(f'----------{self.vulnName} 开始爬取----------')
        self.logger.info(f'{self.vulnName} 开始爬取')
        res = self.get(self.url, headers=self.headers)
        if res and res.status_code == 200:
            soup0 = bs(res.text, "html.parser")
            pages = soup0.findAll('a')
            for page in pages:
                if 'php' in page.get('href'):
                    page_re = page.get('href')
                    link = "https://www.zeroscience.mk/en/vulnerabilities/"+ page_re
                    # print(link)
                    self.getDetails(link)
                    delay = random.uniform(0.25, 2.5)  # 生成一个介于0.25和2.5之间的随机小数
                    time.sleep(delay)
            with open(os.path.join(self.path, "data.json"), 'w', encoding='UTF-8') as f:
                for data in self.dataList:
                    f.write(str(data) + ',\n')
                f.close()
        else:
            # print(res.status_code)
            self.logger.error(f'{self.vulnName} 爬取失败')
        # print(f'----------{self.vulnName} 爬取完成----------')
        self.logger.info(f'{self.vulnName} 爬取完成')

    def getDetails(self,link):
        res = self.get(link, headers=self.headers)
        if res and res.status_code == 200:
            soup = bs(res.content, 'lxml')
            # span_text1 = '未找到描述'
            # span_text2 = '未找到安全级别'
            section1 = soup.find('div', attrs={'class': 'post'})
            if section1 is None:
                return section1
            else:
                # 找到漏洞 title
                h1 = section1.find_all('h4', class_='title')
                span_text1 = h1[0].text
                # print(span_text1)
                # div_element1 = section1[1].find('div')
                h2 = section1.find('div', class_='entry')
                if h2 is not None:
                    # 找到从 AdvisoryID 到 提交日期
                    advisory_id = h2.find('a', href=True)
                    span_text2 = advisory_id.text.strip()
                    # print(span_text2)
                    br_list = h2.find_all('br')
                    # 直到提交日期
                    if br_list is not None:
                        span_text3 = br_list[1].next_sibling.split(':')[1]
                        # print(span_text3)
                        span_text4 = br_list[2].next_sibling.split(':')[1]
                        # print(span_text4)
                        span_text5 = br_list[3].next_sibling.split(':')[1]
                        # print(span_text5)
                        span_text6 = br_list[4].next_sibling.split(':')[1]
                        # print(span_text6)
                    h5_tags = soup.find_all('h5')
                    value1 = None
                    value2 = ""
                    value3 = None
                    for tag in h5_tags:
                        if tag.text == 'Description':
                            value1 = tag.next_sibling.strip()
                            # print(value1)
                        if tag.text == 'PoC':
                            poc_txt = tag.find_next('a', href=True).text.strip()
                            txt_list = poc_txt.split('.')
                            if 'txt' in txt_list or 'html' in txt_list:
                                poc_txt = txt_list[0]
                            else:
                                poc_txt = txt_list[0] + '.' + txt_list[1]
                            # print(poc_txt)
                            poc_url = f"https://www.zeroscience.mk/codes/{poc_txt}.txt"
                            r1 = self.get(poc_url, headers=self.headers)
                            if r1 and r1.status_code == 200:
                                soup1 = bs(r1.content, 'lxml')
                                section2 = soup1.find_all(name='p')
                                if section2:
                                    for item in section2:
                                        value2 += item.text.strip()
                                        break
                                # print(value2)
                                else:
                                    for item in soup1:
                                        value2 += str(item)
                                        break
                                # print(value2)
                        if tag.text == 'References':
                            value3 = tag.find_next('a', href=True).text.strip()
                            # print(value3)

                    # 将漏洞信息插入MongoDB数据库
                vulnerability = {
                    "Title": span_text1,
                    "Advisory_ID": span_text2,
                    "Type": span_text3,
                    "Impact": span_text4,
                    "Risk": span_text5,
                    "Date": span_text6,
                    "Description": value1,
                    "PoC": value2,
                    "References": value3
                }
                # print(vulnerability)
                self.dataList.append(vulnerability)
                insert_data = [vulnerability]
                insert_mongo( self.collection,insert_data, self.key)
        else:
            # print(res.status_code)
            self.logger.error(f'{link} 爬取失败')

    def dataPreProc(self):
        print(f'----------{self.vulnName} 开始数据预处理----------')
        collection = self.collection
        system = self.system
        # 先把总数据表中对应数据源所有数据删除
        query = {'source': self.vulnName}
        result = system.delete_many(query)
        count = 1
        for doc in collection.find():
            item = init_item(self.vulnName)
            item['source_id'] = doc.get('Advisory_ID', 'null')
            item['date'] = doc.get('Date', 'null')
            item['details'] = doc.get('Description', 'null')
            item['title'] = doc.get('Title', 'null')
            item['cve_id'] = 'null'
            if item['cve_id'] != 'null':
                item['software_version'] = isInDeepin(item['cve_id'])

            item['vul_id'] = f"009_{str(count).zfill(6)}"
            count += 1
            # 其他字段丢进related
            related_data = {key: doc[key] for key in doc if
                            key not in ['_id', "Advisory_ID", "Date", "Description", "Title"]}
            # 将所有字段转换为字符串类型
            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data
            # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
            system.insert_one(item)
        print(f'----------{self.vulnName} 数据预处理完成----------')
    def run(self):
        self.collection.drop()  
        
        self.crawl()
        # 查重
        # queryrepeat(self.vulnName, self.collection, self.key)
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')


if __name__ == '__main__':
    # 获取当前时间
    start_time = time.time()
    # 连接 MongoDB 数据库
    client = MongoClient('localhost', 27017)
    # 获取指定数据库和集合
    db = client['306Project']
    collection = db['zeroscience']

    system = db['system']

    obj = Zeroscience('zeroscience', collection, 'Advisory_ID', system)
    obj.run()

    client.close()
    # 获取程序结束时间
    end_time = time.time()
    # 计算程序耗时
    duration = end_time - start_time
    # 打印程序耗时
    print(f"程序耗时：{duration} 秒")
