import os
import time
import random
import logging
import pymongo
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from requests.exceptions import RequestException, ConnectTimeout, ConnectionError
from src.dataProceScript.spider_base import BaseSpider

# 导入自定义模块
from src.dataProceScript.Setting import DATA_PATH, CURRENT_TIME


class rustsec(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.key = 'Patch_ID'
        self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        self.session = self.setup_session()
        self.max_retries = 3
        self.timeout = 15

    def setup_session(self):
        """配置请求会话"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.95 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        })
        adapter = requests.adapters.HTTPAdapter(
            max_retries=3,
            pool_connections=10,
            pool_maxsize=100
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    def safe_request(self, url):
        """带重试机制的请求方法"""
        for attempt in range(self.max_retries):
            try:
                response = self.session.get(url, timeout=self.timeout)
                response.raise_for_status()
                return response
            except (ConnectTimeout, ConnectionError) as e:
                if attempt == self.max_retries - 1:
                    self.logger.error(f"请求最终失败 {url}: {str(e)}")
                    raise
                wait_time = (attempt + 1) * 2
                self.logger.warning(f"请求超时，等待 {wait_time}秒后重试...")
                time.sleep(wait_time)
            except RequestException as e:
                self.logger.error(f"请求异常 {url}: {str(e)}")
                raise

    def extract_text(self, element):
        """安全的文本提取"""
        if element is None:
            return 'null'
        return element.get_text(strip=True)

    def parse_date(self, date_str):
        """日期解析"""
        if date_str == 'null':
            return 'null'
        try:
            return datetime.strptime(date_str, '%B %d, %Y').strftime('%Y-%m-%d')
        except ValueError as e:
            self.logger.warning(f"日期解析失败: {date_str}, 错误: {str(e)}")
            return 'null'

    def crawl(self, cve_id):
        """爬取单个CVE详情"""
        detail_url = f"https://rustsec.org/advisories/{cve_id}"
        try:
            response = self.safe_request(detail_url)
            
            soup = BeautifulSoup(response.content, 'html.parser')
            main_content = soup.find('main')
            if not main_content:
                return None

            # 1. 基础信息提取
            aliase = self.extract_text(soup.find('dt', id='aliases').find_next('a')) if soup.find('dt', id='aliases') else 'null'
            source_id = self.extract_text(main_content.find('h1'))
            
            # 处理CVE别名逻辑
            if not aliase.lower().startswith('cve'):
                aliase = source_id if source_id.lower().startswith('cve') else 'null'

            # 2. 时间信息处理
            reported_time = self.parse_date(
                self.extract_text(soup.find('dt', id='reported').find_next('dd').find('time'))
            ) if soup.find('dt', id='reported') else 'null'

            issued_time = self.parse_date(
                self.extract_text(soup.find('dt', id='issued').find_next('dd').find('time'))
            ) if soup.find('dt', id='issued') else 'null'

            # 3. 漏洞详情提取
            vul_name = self.extract_text(main_content.find('p'))
            package = self.extract_text(soup.find('dt', id='package').find_next('dd').find('a')) if soup.find('dt', id='package') else 'null'
            vul_type = self.extract_text(soup.find('dt', id='type').find_next('dd')) if soup.find('dt', id='type') else 'null'
            
            # 4. 参考信息
            references = [a['href'] for a in soup.find('dt', id='details').find_next('dd').find_all('a')] if soup.find('dt', id='details') else 'null'
            
            # 5. 安全评分
            cvss_score = self.extract_text(soup.find('dt', id='cvss_score').find_next('dd')) if soup.find('dt', id='cvss_score') else 'null'
            cvss_details = self.extract_text(soup.find('dt', id='cvss_details').find_next('dd')) if soup.find('dt', id='cvss_details') else 'null'
            
            # 6. 版本信息
            patched_version = self.extract_text(soup.find('dt', id='patched').find_next('dd')) if soup.find('dt', id='patched') else 'null'
            unaffected = self.extract_text(soup.find('dt', id='unaffected').find_next('dd')) if soup.find('dt', id='unaffected') else 'null'
            
            # 7. 受影响函数
            affected_functions = []
            dl_tags = soup.find_all('dl')
            if len(dl_tags) > 1:
                second_dl = dl_tags[1]
                dt_tags = second_dl.find_all('dt')
                dd_tags = second_dl.find_all('dd')
                for dt, dd in zip(dt_tags, dd_tags):
                    affected_functions.append({
                        'function': self.extract_text(dt),
                        'version': self.extract_text(dd)
                    })
            
            # 8. 描述信息
            description = []
            h3_tag = soup.find('h3', id='description')
            if h3_tag:
                for tag in h3_tag.find_all_next():
                    if tag.name in ['p', 'h2', 'h3', 'h4', 'ul', 'ol']:
                        description.append(self.extract_text(tag))
            
            # 9. 分类信息
            categories = self.extract_text(soup.find('dt', id='categories').find_next('dd').find('a')) if soup.find('dt', id='categories') else 'null'
            keywords = self.extract_text(soup.find('dt', id='keywords').find_next('dd').find('a')) if soup.find('dt', id='keywords') else 'null'

            # 构建最终数据结构
            cve_details = {
                "cve_id": aliase,
                "Source ID": source_id,
                "Patch Name": vul_name,
                "Source": "Rustsec",
                "Type": vul_type,
                "Package": package,
                "Reported": reported_time,
                "Issued": issued_time,
                "References": references,
                "CVSS Score": cvss_score,
                "CVSS Details": cvss_details,
                "Patched Version": patched_version,
                "Affected Functions": affected_functions if affected_functions else 'null',
                "Description": description if description else 'null',
                "Categories": categories,
                "Keywords": keywords,
                "Unaffected": unaffected,
                "platform": "null",
                "author": "null"
            }

            return cve_details

        except Exception as e:
            self.logger.error(f"处理公告 {cve_id} 时发生错误: {str(e)}", exc_info=True)
            return None

    def main(self):
        """主爬取流程"""
        base_url = 'https://rustsec.org/advisories/'
        try:

            
            response = self.safe_request(base_url)
            soup = BeautifulSoup(response.content, 'html.parser')
            advisory_list = soup.find('ul')
            
            if not advisory_list:
                self.logger.error("未找到公告列表容器")
                return

            advisories = advisory_list.find_all('a')
            self.logger.info(f"发现 {len(advisories)} 个待处理公告")
            
            for idx, advisory in enumerate(advisories, 1):
                cve_id = advisory['href'].split('/')[-1]
                
                try:
                    cve_details = self.crawl(cve_id)
                    if cve_details:
                        self.collection.insert_one(cve_details)
                    else:
                        self.logger.warning(f"未能获取公告详情: {cve_id}")
                    time.sleep(random.uniform(0.5, 2))
                except Exception as e:
                    self.logger.error(f"处理公告 {cve_id} 时发生异常: {str(e)}", exc_info=True)
                    continue


        except Exception as e:
            self.logger.critical(f"主爬取流程失败: {str(e)}", exc_info=True)
            raise

    def run(self):
        """运行入口"""
        try:
            self.collection.drop()         
            start_time = time.time()
            self.main()        
            self.count = self.collection.count_documents({})
            elapsed = time.time() - start_time
            self.logger.info(f"爬取完成，共获取 {self.count} 条数据，耗时 {elapsed:.2f}秒")
        except Exception as e:
            self.logger.critical(f"爬虫运行失败: {str(e)}", exc_info=True)
            raise


