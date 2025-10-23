import json
import random
import re
import time
from multiprocessing.dummy import Pool
from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd
import requests
from bs4 import BeautifulSoup
from pymongo import MongoClient
import os
from src.dataProceScript.spider_base import BaseSpider


class Github(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.THREAD_COUNT = 16
        self.second_urls = []
        self.count = 0
        self.dic_list = []


    def get_urls(self):
        self.logger.info("开始获取github漏洞url")
        # 获取当前文件的目录
        current_file_path = os.path.abspath(__file__)
        # 获取文件所在的文件夹路径
        # file_path = os.path.join(current_dir, 'github_url.xlsx')
        folder_path = os.path.dirname(current_file_path)
        input_file_path = os.path.join(folder_path,'..','refe_file', 'github_url.xlsx')
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
         # 正则表达式匹配格式为 CVE-XXXX-XXXXX 的字符串
        pattern = re.compile(r'CVE-\d{4}-\d{5}')
        cve_matches = re.findall(pattern, text)
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


    def issues_crawl(self,url):
        start_time = time.time()
        dic = {
            'title':'null',
            'date':'null',
            'cve_id':'null',
            'detail':'null'
        }
        self.count += 1
        # self.logger.info(f'----------{self.vulnName}正在爬取第{self.count}/{len(self.second_urls)}----------')
        while True:
            end_time = time.time()
            if end_time - start_time > 30:
                return
            try:
                req = requests.get(url)
                if req.status_code == 200:
                    dic['url'] = url
                    soup = BeautifulSoup(req.text, 'html.parser')
                    spans = soup.find_all('bdi',class_='Box-sc-g0xbh4-0 lhNOUb markdown-title')
                    if len(spans) > 0:
                        # print(spans[0].text)
                        dic['title'] = spans[0].text
                        # print(spans[0].text)
            
                        dic['cve_id'] = self.extract_cve(spans[0].text)[0] if len(self.extract_cve(spans[0].text)) > 0 else 'null'
                        # print(dic['cve_id'])
                            
                    
                    div = soup.find('relative-time',class_='sc-aXZVg gcWyXp')
                    if div is not None:
                        time_content = div.text.strip()
                        dic['date'] = time_content.split('T')[0]  # 只保留日期部分
                        # print(time_content.split('T')[0])

                    div = soup.find('div',class_='IssueBodyViewer-module__IssueBody--MXyFt')
                    if div is not None:
                        dic['detail'] = div.text.strip()
                        # print(div.text.strip())

                    

                    self.collection.insert_one(dic)
                    # print(f'{self.count}/{len(self.second_urls)} 爬取成功,已插入mongodb')
                    

                    # time.sleep(random.uniform(0.5, 1))
                    # self.dic_list.append(dic)
                    break

                elif req.status_code == 404:
                    self.logger.error(f"资源不存在 (404): {url}")
                    return
                
                elif req.status_code == 429:
                    self.logger.warning(f"请求过于频繁 (429)，等待 {retry_after:.2f} 秒后重试: {url}")
                    retry_after = random.uniform(5, 10)
                    time.sleep(retry_after)
                    continue
                else:
                    self.logger.error(f"Request failed with status code: {req.status_code}")
                    return

            except requests.exceptions.RequestException as e:
                self.logger.error(f"Request failed: {e}")
                time.sleep(random.uniform(5, 10))

    def GHSA_crawl(self,url):
        start_time = time.time()
        dic = {
            'title':'null',
            'date':'null',
            'cve_id':'null',
            'GHSA_id':'null',
            'package':'null',
            'Affected_versions':'null',
            'Patched_versions':'null',
            'description':'null',
            'Severity':'null',
            'CVSS_vector':'null',
            'weaknesses':'null'
        }
        self.count += 1
        # print(f'----------{self.vulnName}正在爬取第{self.count}/{len(self.second_urls)}----------')
        while True:
            end_time = time.time()
            if end_time - start_time > 30:
                return
            try:
                req = requests.get(url)
                if req.status_code == 200:
                    dic['url'] = url
                    GHSA_id = url.split('/')[-1]
                    dic['GHSA_id'] = GHSA_id

                    soup = BeautifulSoup(req.text, 'html.parser')
                    # print(soup)
                    title = soup.find('h1',class_ = 'gh-header-title')
                    if title is not None:
                        # print(title.text.strip())
                        dic['title'] = title.text.strip()
                        

                    date = soup.find('relative-time')['datetime']
                    dic['date'] = date.split('T')[0]  # 只保留日期部分
                    # print(date.split('T')[0])

                    box = soup.find('div',class_ = 'Box-body')
                    if box is not None:
                        package = box.find('div',class_ = 'float-left col-12 col-md-6 pr-md-2').find('div')
                        if package is not None:
                            package_text = package.text.strip()
                            lines = [line for line in package_text.splitlines() if line.strip()]
                            # 将非空行重新组合成一个字符串
                            cleaned_text = '\n'.join(lines)
                            # 将处理后的文本存入字典
                            dic['package'] = cleaned_text
                            # print(cleaned_text)


                        affected_versions = box.find('div',class_ = 'float-left col-6 col-md-3 py-2 py-md-0 pr-2').find('div')
                        if affected_versions is not None:
                            dic['Affected_versions'] = affected_versions.text.strip()
                            # print(affected_versions.text.strip())
                        patched_versions = box.find('div',class_ = 'float-left col-6 col-md-3 py-2 py-md-0').find('div')
                        if patched_versions is not None:
                            dic['Patched_versions'] = patched_versions.text.strip()
                            # print(patched_versions.text.strip())

                    description = soup.find('div',class_ = 'markdown-body comment-body p-0')
                    if description is not None:
                        dic['description'] = description.text.strip()
                        # print(description.text.strip())

                    right_sidebar = soup.find('div',class_ = 'col-12 col-md-3 pl-md-4 mt-3 mt-md-0')
                    if right_sidebar is not None:
                        component = right_sidebar.find('div',class_ = 'discussion-sidebar-item js-repository-advisory-details')
                        if component is not None:
                            severity = component.find('div',class_ = 'd-flex flex-items-baseline pb-1')
                            if severity is not None:
                                Severity_text = severity.text.strip()
                                lines = [line for line in Severity_text.splitlines() if line.strip()]
                                # 将非空行重新组合成一个字符串
                                cleaned_text = '\n'.join(lines)
                                # 将处理后的文本存入字典
                                dic['Severity'] = cleaned_text
                                # print(cleaned_text)

                            CVSS_vector = component.find('div',class_ = 'mt-2')
                            if CVSS_vector is not None:
                                dic['CVSS_vector'] = CVSS_vector.text.strip()
                                # print(CVSS_vector.text.strip())

                            CVE_id = right_sidebar.find('div',class_ = 'color-fg-muted')
                            if CVE_id is not None:
                                dic['cve_id'] = CVE_id.text.strip()
                                # print(CVE_id.text.strip())

                            weaknesses = right_sidebar.find('a',class_ = 'Label Label--secondary mr-1 text-normal no-underline')
                            if weaknesses is not None:
                                dic['weaknesses'] = weaknesses.text.strip()
                                # print(weaknesses.text.strip())

                    self.collection.insert_one(dic)
                    # print(f'{self.count}/{len(self.second_urls)} 爬取成功,已插入mongodb')
                    

                    # time.sleep(random.uniform(0.5, 1))
                    break
                            
                elif req.status_code == 404:
                    self.logger.error(f"资源不存在 (404): {url}")
                    return
                
                elif req.status_code == 429:
                    self.logger.warning(f"请求过于频繁 (429)，等待 {retry_after:.2f} 秒后重试: {url}")
                    retry_after = random.uniform(5, 10)
                    time.sleep(retry_after)
                    continue
                else:
                    self.logger.error(f"Request failed with status code: {req.status_code}")
                    return
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Request failed: {e}")
                time.sleep(random.uniform(5, 10))
       
    def md_crawl(self,url):
        start_time = time.time()
        dic = {
            'title':'null',
            'date':'null',
            'cve_id':'null',
            'detail':'null'
        }
        self.count += 1
        # print(f'----------{self.vulnName}正在爬取第{self.count}/{len(self.second_urls)}----------')
        while True:
            end_time = time.time()
            if end_time - start_time > 30:
                return
            try:
                req = requests.get(url)
                if req.status_code == 200:
                    dic['url'] = url
                    dic['cve_id'] = self.extract_cve(url)

                    soup = BeautifulSoup(req.text, 'html.parser')

                    json_script = soup.find('script', {'type': 'application/json', 'data-target': 'react-app.embeddedData'})
                    if json_script:
                        try:
                            data = json.loads(json_script.string)
                            # 提取repo信息
                            repo_info = data.get('payload', {}).get('repo', {})

                            created_at = repo_info.get('createdAt', '')
                            dic['date'] = created_at.split('T')[0] if created_at and 'T' in created_at else 'null'

                            # 提取toc信息
                            header_info = data.get('payload', {}).get('blob', {}).get('headerInfo', {})
                            toc_list = header_info.get('toc', [])
                            # 筛选level=1的目录项
                            level1_toc = [item for item in toc_list if item.get('level') == 1]

                            if len(level1_toc) > 0:
                                # 取第一个level=1的text
                                dic['title'] = level1_toc[0].get('text', 'null')
                            else:
                                # 保留默认值
                                dic['title'] = 'null'
                                
                            
                            # 提取richText内容
                            richText = data.get('payload', {}).get('blob', {})
                            dic['detail'] = richText.get('richText')

                        except json.JSONDecodeError as e:
                            self.logger.error(f"JSON解析失败: {e}")



                    self.collection.insert_one(dic)
                    # print(f'{self.count}/{len(self.second_urls)} 爬取成功,已插入mongodb')

                    # time.sleep(random.uniform(0.5, 1))
                    # self.dic_list.append(dic)
                    break
                elif req.status_code == 404:
                    self.logger.error(f"资源不存在 (404): {url}")
                    return
                
                elif req.status_code == 429:
                    self.logger.warning(f"请求过于频繁 (429)，等待 {retry_after:.2f} 秒后重试: {url}")
                    retry_after = random.uniform(5, 10)
                    time.sleep(retry_after)
                    continue
                else:
                    self.logger.error(f"Request failed with status code: {req.status_code}")
                    return
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Request failed: {e}")
                time.sleep(random.uniform(5, 10))

    def cve_crawl(self,url):
        start_time = time.time()
        dic = {
            'title':'null',
            'cve_id':'null',
            'detail':'null',
            
        }
        self.count += 1
        # print(f'----------{self.vulnName}正在爬取第{self.count}/{len(self.second_urls)}----------')
        while True:
            end_time = time.time()
            if end_time - start_time > 30:
                return
            try:
                req = requests.get(url)
                if req.status_code == 200:
                    dic['url'] = url
                    soup = BeautifulSoup(req.text, 'html.parser')
                    article = soup.find('article',class_='markdown-body entry-content container-lg')

                    if article is not None:
                        title = article.find('div',class_='markdown-heading')
                        if title is not None:
                            dic['title'] = title.text.strip()
                            # print(title.text.strip())


                        first_markdown_heading = article.find('div',class_= 'markdown-heading')
                        if first_markdown_heading is not None:
                            second_markdown_heading = first_markdown_heading.find_next('div', class_='markdown-heading')
                            if second_markdown_heading is not None:
                                content_between = []
                                seen = set()# 使用集合来跟踪已添加的内容以避免重复
                                 # 从第一个 'markdown-heading' 之后开始提取内容
                                for tag in first_markdown_heading.find_all_next():
                                    if tag == second_markdown_heading:
                                        break  # 一旦到达下一个 'markdown-heading' 则停止
                                    else:
                                        text_content = tag.text.strip()
                                        if text_content and text_content not in seen:  # 仅在文本非空且未添加时添加
                                            seen.add(text_content) # 将文本添加到集合中以跟踪
                                            content_between.append(text_content)  # 添加到列表中
                                            # print(text_content)
                                dic['detail'] = content_between  # 将提取的文本列表赋值给 dic['detail']                    

                            # 使用正则表达式匹配 CVE-XXX-XXXX
                            cve_id_match = re.search(r'CVE-\d{4}-\d{4,7}', title.text,re.IGNORECASE)
                            if cve_id_match:
                                dic['cve_id'] = cve_id_match.group(0)  # 提取匹配的 CVE ID

                        

                    self.collection.insert_one(dic)
                    # print(f'{self.count}/{len(self.second_urls)} 爬取成功,已插入mongodb')
                    break        

                elif req.status_code == 404:
                    self.logger.error(f"资源不存在 (404): {url}")
                    return
                
                elif req.status_code == 429:
                    self.logger.warning(f"请求过于频繁 (429)，等待 {retry_after:.2f} 秒后重试: {url}")
                    retry_after = random.uniform(5, 10)
                    time.sleep(retry_after)
                    continue
                else:
                    self.logger.error(f"Request failed with status code: {req.status_code}")
                    return
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Request failed: {e}")
                time.sleep(random.uniform(5, 10))

    def crawl(self):
        # print(f'----------{self.vulnName}开始爬取----------')
        # pool = Pool(self.THREAD_COUNT)
        # pool.map(self.singleCrawl, self.second_urls)
        for url in self.second_urls:
            issue_pattern = re.compile(r'/issues/')
            GHSA_pattern = re.compile(r'GHSA-[\w-]+', re.IGNORECASE)
            md_pattern = re.compile(r'\.md$')
            cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
            
            
            # print(f"Checking URL: {url}")  # 调试信息
            if issue_pattern.search(url):
                self.issues_crawl(url)
                continue
            if GHSA_pattern.search(url):
                self.GHSA_crawl(url)
                continue
            if md_pattern.search(url):
                self.md_crawl(url)
                continue
            if cve_pattern.search(url):
                self.cve_crawl(url)
                continue    


    def run(self):
        self.collection.drop()
        self.get_urls()
        self.crawl()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')


# if __name__ == '__main__':
#     start_time = time.time()
#     client = MongoClient('localhost', 27017)
#     db = client['306Project']
#     # 选择集合，如果不存在则MongoDB会自动创建
#     collection = db['github']
#     system = db['system']

#     agen = github('github', 'null', collection, system, 16)
#     agen.run()

#     client.close()
#     # 获取程序结束时间
#     end_time = time.time()
#     # 计算程序耗时
#     duration = end_time - start_time
#     # 打印程序耗时
#     print(f"程序耗时：{duration} 秒")


