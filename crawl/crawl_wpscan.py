import random
import requests
import json
import bs4
import os
import time

from multiprocessing.dummy import Pool
from bs4 import BeautifulSoup
from pymongo import MongoClient
from src.dataProceScript.dataProce import init_item, fieldToValue, isInDeepin
from src.dataProceScript.spider_base import BaseSpider

headers = {
    'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
    'Cookie': '_ga=GA1.1.1302331162.1721041060; tk_ai=QZljY%2FSX%2BErrGBptTI0uun5m; wpscan_remember_token=Z0%2FhNlpZ25sIicIiXvKmGp6z%2FLLTtqj4%2Bo2UtG1rZ3MyWHRiT0FTdjVsTW50Wkw0RExzPQ%3D%3D; country_code=CN; region=Jiangsu; tk_qs=; _ga_0YSM9K8B6W=GS1.1.1721182566.9.1.1721182578.48.0.'
}

class wpscan(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        
        self.config = [
            {
                'vulnName': 'wpscan',
                'vulnName2': 'wpscan/themes',
                'url': 'https://wpscan.com/themes/'
            },
            {
                'vulnName': 'wpscan',
                'vulnName2': 'wpscan/plugins',
                'url': 'https://wpscan.com/plugins/'
            },
            {
                'vulnName': 'wpscan',
                'vulnName2': 'wpscan/WordPress',
                'url': 'https://wpscan.com/wordpresses/'
            }
        ]
        
        self.dic_list = []  # 字典列表
        self.target_url = []
        self.count = 0
        self.pages_list = []

    def getheaders(self):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
            'Cookie': '_ga=GA1.1.1302331162.1721041060; tk_ai=QZljY%2FSX%2BErrGBptTI0uun5m; country_code=CN; region=Jiangsu; wpscan_remember_token=Z0%2FhNlpZ25sIicIiXvKmGp6z%2FLLTtqj4%2Bo2UtG1rZ3MyWHRiT0FTdjVsTW50Wkw0RExzPQ%3D%3D; _ga_0YSM9K8B6W=GS1.1.1721129513.7.1.1721129563.10.0.0'
        }
        return headers

    def getpages(self):
        for i in range(0, 27):
            new_url = self.url + '?get=' + chr(i + 96)
            if i == 0:
                new_url = 'https://wpscan.com/themes/'
            while True:
                try:
                    req = self.get(new_url, headers=self.getheaders())
                    if req and req.status_code == 200:
                        soup = bs4.BeautifulSoup(req.text, 'html.parser')
                        pages = soup.find_all('ul', class_='vulnerabilities__pagination')
                        self.pages_list.append(len(pages[0].find_all('li')) - 2)
                        break
                    else:
                        # print(f"Request failed with status code: {req.status_code}")
                        self.logger.error(f"{new_url}Request failed")
                        time.sleep(10)
                except requests.exceptions.RequestException as e:
                    # print(f"Request failed: {e}")
                    self.logger.error(f"{new_url}Request failed: {e}")
                    time.sleep(10)

    def get_url(self, url):
        # print(f'----------{self.vulnName2}开始爬取目标网站URL----------')
        self.logger.info(f'----------{self.vulnName2}开始爬取目标网站URL----------')

        count = 0
        if self.vulnName2 == 'wpscan/WordPress':
            for i in range(1, 12):
                while True:
                    try:
                        new_url = url + '?page=' + str(i)
                        # print(new_url)
                        req = self.get(new_url, headers=self.getheaders())
                        if req and req.status_code == 200:
                            soup = BeautifulSoup(req.text, 'html.parser')
                            divs = soup.find_all('div', class_='vulnerabilities__table--title')
                            for div in divs:
                                an = div.find('a')
                                if an is not None:
                                    count += 1
                                    self.target_url.append(an.get('href'))
                                    # print(f'----------已获取{count}个URL----------')
                            break
                        else:
                            # print(f"Request failed with status code: {req.status_code}")
                            self.logger.error(f"{new_url}Request failed ")
                            time.sleep(10)
                    except requests.exceptions.RequestException as e:
                        # print(f"Request failed: {e}")
                        self.logger.error(f"{new_url}Request failed: {e}")
                        time.sleep(10)
        else:
            self.getpages()
            for i in range(0, 27):
                for j in range(1, self.pages_list[i] + 1):
                    new_url = url + '?page=' + str(j) + '&get=' + chr(i + 97)
                    # print(new_url)
                    if i == 0:
                        new_url = url
                    while True:
                        try:
                            req = self.get(new_url, headers=self.getheaders())
                            if req and req.status_code == 200:
                                soup = BeautifulSoup(req.text, 'html.parser')
                                divs = soup.find_all('div', class_='vulnerabilities__table--title')
                                for div in divs:
                                    an = div.find('a')
                                    if an is not None:
                                        count += 1
                                        self.target_url.append(an.get('href'))
                                        # print(f'----------已获取{count}个URL----------')
                                        # print(an.get('href'))
                                break
                            else:
                                # print(f"Request failed with status code: {req.status_code}")
                                self.logger.error(f"{new_url}Request failed ")
                                time.sleep(10)
                        except requests.exceptions.RequestException as e:
                            # print(f"Request failed: {e}")
                            self.logger.error(f"{new_url}Request failed: {e}")
                            time.sleep(10)

        # print(f'----------{self.vulnName2}正在对网站URL去重----------')
        self.target_url = list(set(self.target_url))

    def singleCrawl(self, url):
        self.count += 1
        # print(f'----------{self.vulnName2}正在爬取第{self.count}/{len(self.target_url)}----------')
        dic = {
            'CVE': 'null',
            'Added': 'null',
            'CWE': 'null',
            'Verified': 'null',
            'Original Researcher': 'null',
            'Submitter website': 'null',
            'Submitter': 'null',
            'Exploitdb': 'null',
            'Type': 'null',
            'WPVDB ID': 'null',
            'Last Updated': 'null',
            'CVSS': 'null',
            'Submitter twitter': 'null',
            'Publicly Published': 'null',
            'URL': 'null',
            'title': 'null',
            'OWASP top 10': 'null',
            'description': 'null',
            'PoC': 'null',
            'affect_themes': 'null',
            'second_url': 'null'
        }

        while True:
            try:
                req = self.get(url, headers=self.getheaders(), timeout=10)
                if req and req.status_code == 200:
                    soup = BeautifulSoup(req.text, 'html.parser')
                    dic['second_url'] = url
                    if soup.find_all('h1', class_='vulnerabilities__title'):
                        dic['title'] = soup.find_all('h1', class_='vulnerabilities__title')[0].text
                    divs = soup.find_all('div', class_='vulnerabilities__single-description')
                    if divs:
                        for div in divs:
                            if div.find('p'):
                                dic['description'] = div.find('p').text
                    pres = soup.find_all('pre', class_='vulnerabilities-single__poc')
                    if pres:
                        dic['PoC'] = pres[0].text
                    divs = soup.find_all('div', class_='vulnerabilities__table--slug')
                    if divs:
                        dic['affect_themes'] = divs[0].find('a').text if divs[0].find('a') else 'null'
                    divs = soup.find_all('div', class_='vulnerabilities-single__data-row')
                    if divs:
                        for div in divs:
                            key = div.find_all('div')[0].text.strip()
                            value = div.find_all('div')[1].text.strip() if div.find_all('div')[1] else 'null'
                            dic[key] = value
                    self.dic_list.append(dic)
                    break
                else:
                    # print(f"Request failed with status code: {req.status_code}")
                    self.logger.error(f"{url}Request failed ")
                    time.sleep(10)
            except requests.exceptions.RequestException as e:
                # print(f"Request failed: {e}")
                self.logger.error(f"{url}Request failed: {e}")
                time.sleep(random.uniform(10, 20))

    def crawl(self):
        # print(f'----------{self.vulnName2}开始爬取----------')
        self.logger.info(f'----------{self.vulnName2}开始爬取----------')
        pool = Pool(16)
        pool.map(self.singleCrawl, self.target_url)
        with open('wpscan_data.json', 'w', encoding='utf-8') as f:
            json.dump(self.dic_list, f, ensure_ascii=False, indent=4)
        # print('爬取结束')

    def wpscandbToMongo(self):
        # print(f'----------{self.vulnName2} 开始存储----------')
        with open('wpscan_data.json', 'r', encoding='utf-8') as f:
            data_list = json.load(f)
            self.collection.insert_many(data_list)
        # 删除临时文件
        os.remove('wpscan_data.json')
        

    def dataPreProc(self):
        print(f'----------{self.vulnName}开始数据预处理----------')
        count = self.collection.count_documents({})
        for doc in self.collection.find():
            item = init_item(self.vulnName2)
            item['source_id'] = doc['second_url']
            trimmed_string = doc['Publicly Published']
            open_parenthesis_index = trimmed_string.find('(')
            if open_parenthesis_index != -1:
                result = trimmed_string[:open_parenthesis_index].strip()
            item['date'] = result if doc['Publicly Published'] else 'null'
            item['details'] = doc['description'] if doc['description'] else 'null'
            item['title'] = doc['title'] if doc['title'] else 'null'
            item['type'] = doc['Type'].strip() if doc['Type'] else 'null'
            item['platform'] = 'null'
            item['author'] = doc['Submitter'].strip() if doc['Submitter'] else "null"
            if item['author'] == "null":
                item['author'] = doc['Original Researcher'].strip() if doc['Original Researcher'] else "null"
            item['cve_id'] = doc['CVE'].strip() if doc['CVE'] else 'null'
            item['vul_id'] = f"033_{str(count).zfill(6)}"
            item['source'] = self.vulnName
            item['software_version'] = 'null'
            if item['cve_id'] != 'null':
                item['software_version'] = isInDeepin(item['cve_id'])
            related_data = {key: doc[key] for key in doc if
                            key not in ['_id', "id", "description", 'second_url', 'Publicly Published', 'title', 'Type',
                                        'Submitter', 'Original Researcher', 'CVE']}
            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data
            count += 1
            self.system.insert_one(item)
        print(f'----------{self.vulnName} 数据预处理完成----------')

    def run(self):
        self.collection.drop() 
        for config in self.config:
            self.vulnName = config['vulnName']
            self.vulnName2 = config['vulnName2']
            self.url = config['url']
            self.dic_list = []
            self.target_url = []
            self.count = 0
            self.pages_list = []
            self.get_url(self.url)
            self.crawl()
            self.wpscandbToMongo()
            # self.dataPreProc()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')
        
if __name__ == '__main__':
    start_time = time.time()
    agen = wpscan()
    agen.run()
    agen.client.close()
    end_time = time.time()
    duration = end_time - start_time
    print(f"程序耗时：{duration} 秒")