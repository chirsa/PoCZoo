from bs4 import BeautifulSoup as bs
import random
import requests
import time
import pymongo
from src.dataProceScript.spider_base import BaseSpider
import base64

class blogNintechnet(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.headers = {
            'Host': 'blog.nintechnet.com',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Connection': 'keep-alive',
        }
        

    def scrape_detail_page(self, detail_page_url):
        try:
            response = self.get(detail_page_url)
            response.raise_for_status()  # 检查请求是否成功
            soup = bs(response.content, 'lxml')

            # 解析文章标题
            div1 = soup.find('h1', class_='entry-title entry-title-single')
            title = div1.get_text(strip=True) if div1 else '未知标题'

            # 解析文章元数据
            section1 = soup.find('div', class_='entry-meta entry-meta-header-after')
            if section1:
                author_tag = section1.find('span', class_='entry-author-name')
                author = author_tag.text if author_tag else '未知作者'
                
                date_tag = section1.find('time', class_='entry-date published')
                date = date_tag.text if date_tag else '未知日期'
            else:
                author = '未知作者'
                date = '未知日期'

            # 解析文章内容
            section4 = soup.find('div', class_='entry-content')
            description = section4.get_text(strip=True) if section4 else '无内容'
            time.sleep(random.uniform(0.25, 2.5))
            return {
                "date": date,
                "author": author,
                "source": "blog nintechnet",
                "title": title,
                "description": description
            }
        except Exception as e:
            self.logger.error(f"解析详情页失败: {str(e)}")
            return None


    def crawl(self):
        base_url = 'https://blog.nintechnet.com'
        for page_number in range(1, 34):
            page_url = f'{base_url}/page/{page_number}/'
            self.logger.info(f'开始处理页面: {page_url}')
            
            try:
                response = self.get(page_url)
                soup = bs(response.content, 'lxml')
                # print(soup.prettify())
                links = soup.find_all('h1', class_='entry-title')
                
                for link in links:
                    a_tag = link.find('a')
                    if a_tag:
                        detail_url = a_tag.get('href')
                        self.logger.debug(f"解析到文章链接: {detail_url}")
                        vulnerability = self.scrape_detail_page(detail_url)
                        time.sleep(random.uniform(0.25, 2.5))
                        self.collection.insert_one(vulnerability)
                    else:
                        self.logger.debug(f"{link}未找到文章链接")
                self.logger.info(f'第 {page_number} 页存储完成')
            except Exception as e:
                self.logger.error(f"页面处理失败: {str(e)}")
            
            time.sleep(random.uniform(0.25, 2.5))

    def run(self):
        self.collection.drop()
        self.crawl()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName} 共计爬取 {self.count} 条数据')

if __name__ == '__main__':
    client = pymongo.MongoClient("localhost", 27017)
    try:
        db = client['306Project']
        spider = blogNintechnet(db['blog_nintechnet'], 'blog_nintechnet')
        spider.run()
    finally:
        client.close()