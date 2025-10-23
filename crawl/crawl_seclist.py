import os
import time
from datetime import datetime
import pymongo
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin
import random

from src.dataProceScript.Setting import DATA_PATH, CURRENT_TIME
from src.dataProceScript.dataProce import insert_mongo_many, insert_mongo_one, queryrepeat
from src.dataProceScript.spider_base import BaseSpider


class seclist(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.key =  'title'
        self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'
        }
        self.url = 'https://seclists.org/bugtraq/'

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
            'Cookie': '_gcl_au=1.1.1032223219.1721566123; _vwo_uuid_v2=D75B595D233E4F7EC414508FD064A2252|82a2606e3cbeb1349521dea17452352f; _gd_visitor=232233f2-5cd6-4975-8667-af893159361c; _an_uid=5653938270817846631; _vwo_uuid=D75B595D233E4F7EC414508FD064A2252; _vwo_ds=3%241721566123%3A26.4240961%3A%3A; hubspotutk=f0a3504c35e5323f6ce0d9f973e74ef9; _omappvp=f8IlWWq39V0VcFthUlYd0iTrXJc3jV6FZ2ypvmEWvxk5eDQ3AG3PI07jJyYarihESmZ7FKWwzRxLJZLRFD2JUc7eoEcpLkvc; __adroll_fpc=54733b4df5c4edb2213b190e9baa9ca0-1721566125056; __ar_v4=; _hjSessionUser_1621011=eyJpZCI6ImFkMDY5ODc2LWUwZTUtNTQ4Ny04ZmQ0LTA0MTI0N2EzZjdhNCIsImNyZWF0ZWQiOjE3MjE1NjYxMjUxODYsImV4aXN0aW5nIjp0cnVlfQ==; drift_aid=5d70443e-2919-4a21-8be7-d28285e18c5e; driftt_aid=5d70443e-2919-4a21-8be7-d28285e18c5e; notice_preferences=4:; notice_gdpr_prefs=0,1,2,3,4:; cmapi_gtm_bl=; cmapi_cookie_privacy=permit 1,2,3,4,5; _gid=GA1.2.1119103108.1721631975; _ga=GA1.1.1580977254.1721566125; TAsessionID=a136dd41-5c6f-4ee1-946d-87dc098e6c21|EXISTING; notice_behavior=implied,us; _gd_session=6c997a4b-ef27-41b2-83e7-adf8300d5ad7; _vis_opt_s=9%7C; _vis_opt_test_cookie=1; _hjSession_1621011=eyJpZCI6Ijc3Mzk0NDY3LWUyYzctNDI1MC05ZGIxLTk0MjRkYjJiMmFiMCIsImMiOjE3MjE3MDI4MTUzMjcsInMiOjAsInIiOjAsInNiIjowLCJzciI6MCwic2UiOjAsImZzIjowLCJzcCI6MH0=; drift_campaign_refresh=24468cd6-f89c-4b03-a1f3-bb20fa97612f; __hstc=220751815.f0a3504c35e5323f6ce0d9f973e74ef9.1721566124240.1721635408566.1721702817211.10; __hssrc=1; _vwo_sn=136692%3A3; __hssc=220751815.3.1721702817211; _ga_M6K485ELH5=GS1.1.1721702817.6.1.1721702932.60.0.0; _ga_NHMHGJWX49=GS1.1.1721702817.6.1.1721702932.60.0.0'
        }

        return headers
    def crawl(self):
        try:
            response = self.get(self.url, headers=self.headers)
        except Exception as e:
            self.logger.error(f"{self.url}发生了异常：{e}")
            return
        # 页面的HTML源码
        html = response.text
        # 通过status_code属性来查看网页返回的状态码
        # print(response.status_code)
        soup = BeautifulSoup(html, 'html.parser')
        # 定位表格的父节点
        calendar = soup.find(attrs={'class': 'calendar Monthly'})  # 修改了类名的空格为下划线
        monthList = calendar.find_all('a')  # 使用了正确的find_all方法并指定了name参数为'a'

        # 直接遍历元素逐个处理（无需先收集到列表）        
        for m in monthList:
            href = m['href']  # 直接获取当前元素的href
            new_url = urljoin(self.url, href)
            self.random_delay()     
            try:
                self.getthread(new_url)  # 立即处理当前月份
            except Exception as e:
                # print(f"处理 {new_url} 时出错: {e}")  # 建议添加更详细的错误日志
                self.logger.error(f"{new_url}发生了异常：{e}")


    def getthread(self,new_url):
        # headers = {
        #     'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'
        # }
        # print(new_url)
        try:
            # response_list = requests.get(new_url, headers=headers)
            response_list = self.get(new_url, headers=self.getheaders())
            html_list = response_list.text
            soup_list = BeautifulSoup(html_list, 'html.parser')

            # # 定位线程主体的父节点
            # thread_list = soup_list.find(attrs={'class': 'thread'})
            # thread_list_line = thread_list.find_all('a')
            # # print(thread_list_line)
            # thread_list_line_href = []
            # for t in thread_list_line:
            #     href = t['href']
            #     thread_list_line_href.append(href)
            # 获取页面中所有合法的 <a> 标签（无论位置）
            all_links = soup_list.select('li > a[href][name]')
            hrefs = list({link['href'] for link in all_links})  # 去重

            # 统一处理所有href（无重复）
            for href in hrefs:
                next_url = urljoin(new_url, href)
                # print(next_url)
                self.getcontent(next_url)
                self.random_delay()
        except Exception as e:
            self.logger.error(f"{new_url}发生了异常：{e}，状态码：{response_list.status_code}")

    def getcontent(self, next_url):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'
        }
        response_content = requests.get(next_url, headers=headers)
        html_content = response_content.text
        bs = BeautifulSoup(html_content, 'html.parser')
        try:
            content = bs.find(attrs={'id': 'nst-content'})
            main_content = content.get_text()
            # print(main_content)
        except Exception as e:
            # print(e)
            main_content = ''

        try:
            pre = content.find('pre').get_text()
        except Exception as e:
            # print(e)
            pre = ''

        try:
            title = bs.find('h1',class_= 'm-title').get_text()
        except Exception as e:
            # print(e)
            title = ''

        # 查找包含"From"文本的<em>标签
        from_tag = bs.find('em', text=lambda t: t and t.strip() == 'From')
        if from_tag:
            from_text = from_tag.next_sibling.strip().lstrip(':').strip()

        # 查找包含"Date"文本的<em>标签
        date_tag = bs.find('em', text=lambda t: t and t.strip() == 'Date')
        if date_tag:
            date_text1 = date_tag.next_sibling.strip().lstrip(':').strip()


        if (main_content and pre) != None :
            index_1 = main_content.find(title) + len(title)
            index_2 = main_content.rfind(pre)
            main_content = main_content[index_1:index_2] + pre

        try:
             # 匹配所有章节标题和内容（如Proof of Concept）
            sections = re.findall(r'\n([A-Za-z ]+)\n=+\n(.*?)(?=\n[A-Za-z ]+\n=+|\Z)', 
                         main_content, re.DOTALL)
            content_dict = {k.strip(): v.strip() for k,v in sections}
             # 单独提取Proof of Concept
            proof_content = content_dict.get('Proof of Concept', '')
        except Exception as e:
            # print(f"内容解析失败: {e}")
            self.logger.error(f"内容解析失败: {e}")
            proof_content = ''

        current_thread = bs.find('ul',class_='thread').get_text()
        
        vulnerability = {
            'title':title,
            'main_content': main_content,
            'From':from_text,
            'Date':date_text1 if date_text1 else '',
            'Proof_of_Concept': proof_content,
            'current_thread':current_thread,
            
        }

        # print(vulnerability)
        # with open(os.path.join(self.path, "data.json"), 'a', encoding='UTF-8') as f:
        #     f.write(str(vulnerability) + '\n')
        #     f.close()
        self.collection.insert_one(vulnerability)

    def random_delay(self):
        time.sleep(random.uniform(0.1,1))
    def itemToMongo(self, item):
        # 插入到 MongoDB 数据库
        insert_mongo_one(self.collection, item, self.key)
    def run(self):
        self.collection.drop()
        self.crawl()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据') 


# if __name__ == '__main__':
#     myclient = pymongo.MongoClient('localhost', port=27017)
#     db = myclient['306Project']
#     collection = db['seclist1']
#     obj = seclist('seclist', collection, 'title')
#     obj.run()
