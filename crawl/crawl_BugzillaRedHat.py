import os
import time

import openpyxl
import pandas as pd
import pymongo
import requests
from bs4 import BeautifulSoup
from datetime import datetime

# 导入自定义模块
# from src.dataProceScript.Setting import DATA_PATH, CURRENT_TIME
from src.dataProceScript.dataProce import insert_mongo, init_item, getDeepin, isInDeepin
from src.dataProceScript.spider_base import BaseSpider





class BugzillaRedHat(BaseSpider):

    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        # self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        # self.deepin2309, self.deepin2404 = getDeepin()
        self.session = self.setup_session()


    def setup_session(self):
        """设置请求会话"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; RustsecCrawler/1.0; +http://www.yourdomain.com/bot)'
        })
        session.mount('https://', requests.adapters.HTTPAdapter(max_retries=3))
        return session

    def crawl_cve(self,url):
            try:
                response = self.session.get(url, timeout=10)
                response.raise_for_status()

                # 使用BeautifulSoup解析HTML内容
                soup = BeautifulSoup(response.text, 'html.parser')
                # 直接打印Bug摘要
                bug_summary = soup.find('span', id='short_desc_nonedit_display')
                alias_th = soup.find('th', id='field_label_alias')

                if alias_th:
                    # 获取相邻的th
                    corresponding_td = alias_th.find_next('td')
                    if corresponding_td:
                        CVE_ID=corresponding_td.get_text(strip=True)
                # 直接打印Bug状态
                bug_status = soup.find('span', id='static_bug_status')

                # 打印产品和组件信息
                product = soup.find('td', id='field_container_product')
                component = soup.find('input', id='component').get('value')

                # 打印版本信息
                version = soup.find('span', id='version')

                # 打印报告者信息和报告时间
                reporter = soup.find('span', class_='fn')
                reported_time = soup.find('td', text='Reported:')


                # 打印评论
                comments = soup.find_all('div', class_='bz_comment')


                cve_details = {
                    "CVE_ID": CVE_ID,
                    "Patch Name": bug_summary.get_text(strip=True),
                    "Source": "Bugzilla",
                    "Source id": url,
                    "Status": bug_status.get_text(strip=True),
                    "Product": product.get_text(strip=True),
                    "Component": component,
                    "Version": version.get_text(strip=True),
                    "Reporter": reporter.get_text(strip=True) if reporter else "null",
                    "Reported Time": reported_time.find_next().get_text(strip=True) if reported_time else "null",
                    "Comments": [comment.get_text(strip=True, separator='\n') for comment in comments]
                }

                return cve_details

            except requests.exceptions.RequestException as e:
                self.logger.info(f"Request failed for {url}: {e}")
            except Exception as e:
                self.logger.info(f"An error occurred while crawling {url}: {e}")


    def run(self):
        self.collection.drop()
        self.main()
        # self.dataPreProc()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')
        
    def main(self):
        """主函数，爬取CVE列表并获取详细信息"""      
        # 获取当前文件的绝对路径
        current_file_path = os.path.abspath(__file__)
        # 获取文件所在的文件夹路径
        folder_path = os.path.dirname(current_file_path)
        input_file_path = os.path.join(folder_path,'..','refe_file', 'bugzilla_redhat.xlsx')
        # 读取Excel文件
        self.logger.info(f"开始读取{input_file_path}文件")
        # input_file_path = r'C:\Users\Administrator\Documents\WeChat Files\wxid_imr7q8oapztn22\FileStorage\File\2024-07\urls\bugzilla_redhat1.xlsx'
        df = pd.read_excel(input_file_path)

        # 设置请求头
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; RustsecCrawler/1.0; +http://www.yourdomain.com/bot)'
        }

        # 遍历DataFrame中的每一行
        for index, row in df.iterrows():
            url = row['URL']  # 假设Excel文件中有名为'URL'的列
            # print(url)
            cve_details = self.crawl_cve(url)
            if cve_details:
                self.collection.insert_one(cve_details)
            else:
                self.logger.info(f"Failed to retrieve details for C.")


    def dataPreProc(self):
        """数据预处理函数"""
        self.logger.info(f"开始数据预处理")
        collection = self.collection
        system = self.system
        count = 1
        query = {'source': self.vulnName}
        result = system.delete_many(query)
        self.logger.info(f"删除{result.deleted_count}条{self.vulnName}数据")
        for doc in collection.find():
            item = init_item(self.vulnName)
            item['cve_id'] =  doc['CVE_ID'] if doc['CVE_ID'] is not None else 'null'
            if item['cve_id'] != 'null':
                item['software_version'] = isInDeepin(item['cve_id'])

            item['date'] = doc['Reported Time'] if doc['Reported Time'] is not None else 'null'
            item['title'] = doc['Patch Name'] if doc['Patch Name'] is not None else 'null'
            item['source_id'] = doc['Source id'] if doc['Source id'] is not None else 'null'
            item['source'] = doc['Source'] if doc['Source'] is not None else 'null'
            item['details'] = doc['Comments'] if doc['Comments'] is not None else 'null'
            item['author'] = doc['Reporter'] if doc['Reporter'] is not None else 'null'
            item['software_version'] = doc['Version'] if doc['Version'] is not None else 'null'
            item['vul_id'] = f"016_{str(count).zfill(6)}"
            count += 1
            related_data = {key: doc[key] for key in doc if
                            key not in ['_id', "Patch ID", "Reported Time", "Patch Name", "Source id", "Source",
                                        "Comments","Reporter","Version"]}
            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data
            system.insert_one(item)
        self.logger.info(f"数据预处理完成")


# # 主程序
# if __name__ == '__main__':
#     myclient = pymongo.MongoClient('localhost', 27017)
#     db = myclient['306Project']
#     collection = db['bugzilla_redhat']
#     system = db['system']  # 根据实际情况可能需要使用
#     crawler = BugzillaRedHat('bugzilla', collection, 'Patch_ID', system)
#     crawler.main()
#     crawler.dataPreProc()
    