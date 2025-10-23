import pandas as pd
import requests
from bs4 import BeautifulSoup
from pymongo import MongoClient
import time
import random
import os
from requests.exceptions import RequestException, HTTPError, Timeout, ConnectionError
from src.dataProceScript.spider_base import BaseSpider


class launchpad(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        # 初始化配置
        self._setup_paths()
        self._setup_headers()
        self._load_data()
        self.max_retries = 3
        self.timeout = 15

    def _setup_paths(self):
        """配置文件路径"""
        current_file_path = os.path.abspath(__file__)
        folder_path = os.path.dirname(current_file_path)
        self.input_file_path = os.path.join(folder_path, '..', 'refe_file', 'bugs_launchpad.xlsx')

    def _setup_headers(self):
        """配置请求头"""
        self.headers = {
            'Host': 'bugs.launchpad.net',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'Connection': 'keep-alive',
        }

    def _load_data(self):
        """加载Excel数据"""
        try:
            self.df = pd.read_excel(self.input_file_path)
            self.logger.info(f"成功加载Excel文件，共{len(self.df)}条记录")
        except Exception as e:
            self.logger.error(f"加载Excel文件失败: {str(e)}")
            raise

    def _safe_request(self, url):
        """带重试机制的请求方法"""
        for attempt in range(self.max_retries):
            try:
                response = requests.get(
                    url,
                    headers=self.headers,
                    timeout=self.timeout
                )
                response.raise_for_status()
                return response
            except (Timeout, ConnectionError) as e:
                if attempt == self.max_retries - 1:
                    raise
                wait_time = (attempt + 1) * 2
                self.logger.warning(f"请求超时，{wait_time}秒后重试... (URL: {url})")
                time.sleep(wait_time)
            except HTTPError as e:
                self.logger.error(f"HTTP错误: {e.response.status_code} (URL: {url})")
                raise
            except RequestException as e:
                self.logger.error(f"请求异常: {str(e)} (URL: {url})")
                raise

    def _extract_field(self, soup, selector, attr=None, default="未知"):
        """通用字段提取方法"""
        try:
            element = soup.select_one(selector)
            if not element:
                return default
            return element.get_text(strip=True) if attr is None else element.get(attr, default)
        except Exception as e:
            self.logger.warning(f"提取字段失败: {str(e)} (Selector: {selector})")
            return default

    def _process_page(self, url):
        """处理单个页面"""
        try:
            response = self._safe_request(url)
            soup = BeautifulSoup(response.content, 'lxml')

            # 提取各字段
            description = self._extract_field(
                soup, 
                'div.yui3-editable_text-text',
                default="No description available"
            )
            
            cve_id = self._extract_field(
                soup,
                'li.sprite.cve'
            )
            
            title = self._extract_field(
                soup,
                'span.yui3-editable_text-text.ellipsis'
            )
            
            product = self._extract_field(
                soup,
                'a.sprite.product'
            )
            
            status = self._extract_field(
                soup,
                'div.status-content'
            )
            
            level = self._extract_field(
                soup,
                'div.importance-content'
            )
            
            author = self._extract_field(
                soup,
                'a.sprite.person'
            )

            # 构建文档
            document = {
                'url': url,
                'cve_id': cve_id,
                'title': title,
                'product': product,
                'status': status,
                'level': level,
                'author': author,
                'description': description,
                'source': 'bug_launchpad'
            }

            # 存储到MongoDB
            self.collection.insert_one(document)
            # self.logger.info(f"成功插入数据: {url}")
            return True

        except Exception as e:
            self.logger.error(f"处理页面失败: {str(e)} (URL: {url})")
            return False

    def main(self):
        """主爬取逻辑"""
        success_count = 0
        total_count = len(self.df)
        
        self.logger.info(f"开始爬取，共{total_count}个URL需要处理")
        
        for index, row in self.df.iterrows():
            url = row['URL']
            if self._process_page(url):
                success_count += 1
            time.sleep(random.uniform(0.25, 1.2))
        
        self.logger.info(f"爬取完成，成功处理{success_count}/{total_count}个页面")

    def run(self):
        """运行入口"""
        try:
            self.logger.info("开始执行爬虫任务")
            self.collection.drop()
            
            start_time = time.time()
            self.main()
            
            self.count = self.collection.count_documents({})
            elapsed = time.time() - start_time
            self.logger.info(f"{self.vulnName} 爬取完成，共获取 {self.count} 条数据，耗时 {elapsed:.2f}秒")
            
        except Exception as e:
            self.logger.critical(f"爬虫运行失败: {str(e)}")
            raise
        finally:
            self.logger.info("爬虫任务结束")


if __name__ == '__main__':
    # 测试代码
    client = MongoClient('localhost', 27017)
    try:
        db = client['306Project']
        collection = db['launchpad']
        
        spider = launchpad(db, 'launchpad')
        spider.run()
    finally:
        client.close()