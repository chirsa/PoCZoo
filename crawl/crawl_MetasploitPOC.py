import time
import pymongo
import requests
from pymongo import UpdateOne
from pymongo.errors import BulkWriteError
from src.dataProceScript.spider_base import BaseSpider

class MetasploitPOC(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        # self.collection = collection
        # self.session = requests.Session()
        # self.failed_pages = []
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Accept': 'application/json'
        }
        # self.session.headers.update(self.headers)
        

    def parse_item(self, item):
        """标准化数据格式"""
        return {
            '_id': item['id'],
            'type': item.get('type'),
            'identifier': item.get('identifier'),
            'title': item.get('title'),
            'description': item.get('description', '').replace('\n', ' ').strip(),
            'data': {
                'disclosure_date': item['data'].get('disclosure_date'),
                'platform': item['data'].get('platform'),
                'authors': item['data'].get('authors', []),
                'rank': item['data'].get('rank'),
                'path': item['data'].get('path')
            },
            'references': [ref for ref in item.get('references', [])],
            'created_at': item['created_at'],
            'updated_at': item['updated_at'],
            'published_at': item['published_at']
        }

    def process_page(self, page_num):
        """处理单个页面"""
        url = f"https://www.rapid7.com/api/vulnerability-list/?page={page_num}&type=metasploit"
        
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            if not data.get('data'):
                return False

            bulk_ops = [
                UpdateOne(
                    {'_id': item['id']},
                    {'$set': self.parse_item(item)},
                    upsert=True
                ) for item in data['data']
            ]

            if bulk_ops:
                try:
                    result = self.collection.bulk_write(bulk_ops, ordered=False)
                    # print(f"Page {page_num}: Upserted {result.upserted_count} | Modified {result.modified_count}")
                    return True
                except BulkWriteError as bwe:
                    self.logger.error(f"Page {page_num} partial failure: {len(bwe.details['writeErrors'])} errors")
            return True

        except Exception as e:
            self.logger.error(f"Page {page_num} failed: {str(e)}")
            # self.failed_pages.append(page_num)
            return False

    def get_page(self, page_num):
        """精简后的方法"""
        return self.process_page(page_num)
    

    def crawl(self):
            TOTAL_PAGES = 302
            """主运行方法"""
            for page_num in range(1, TOTAL_PAGES + 1):
                retries = 3
                while retries > 0:
                    if self.process_page(page_num):
                        break
                    retries -= 1
                    time.sleep(2 ** (3 - retries))
                else:
                    self.logger.error(f"Page {page_num} failed after 3 retries")

    def run(self):
        self.collection.drop()
        self.crawl()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')


# if __name__ == '__main__':
#     start_time = time.time()
#     # 初始化MongoDB连接
#     client = pymongo.MongoClient("localhost", 27017)
#     db = client['306Project']
#     collection = db['MetasploitPOC']
#     obj = MetasploitPOC(collection)
#     obj.run()
#     end_time = time.time()
#     # 计算程序耗时
#     duration = end_time - start_time
#     # 打印程序耗时
#     print(f"程序耗时：{duration} 秒")