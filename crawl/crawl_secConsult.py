import json
import os
import random
import shutil
import time

import requests
from bs4 import BeautifulSoup
from lxml import etree
from pymongo import MongoClient

from src.dataProceScript.Setting import DATA_PATH, CURRENT_TIME
from src.dataProceScript.dataProce import insert_mongo, init_item, getDeepin, isInDeepin

from src.dataProceScript.spider_base import BaseSpider

class secConsult(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.key = 'url'
        self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        if not os.path.exists(self.path):
            os.makedirs(self.path)
        self.start_url = 'https://sec-consult.com/'
        # self.deepin23beta3, self.deepin2404 = getDeepin()

    def crawlAndstorage(self):
        # print(f'----------{self.vulnName} 开始爬取----------')
        self.logger.info(f'----------{self.vulnName} 开始爬取----------')
        url = self.start_url + 'vulnerability-lab/'
        res = self.get(url=url)
        # print(res.text)
        if res and res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            response = etree.HTML(str(soup))
            year_list = response.xpath("//li[@class='news-filter__item']")
            all = 1
            for y in year_list:
                # 忽略all
                if all != 1:
                    y_link = y.xpath("./a/@href")[0]
                    year_url = self.start_url + y_link
                    # print("-----uuuuuuuuuuuu-------", year_url)
                    # 回调年份网址
                    self.yearPage(year_url)
                    # 回调年份网址
                all = 2
    def getValue(self,response,key):
        try:
            res = response.xpath(key)
            if not res:
                return ['null']
            return res
        except Exception as e:
            self.logger.error(f"{key}获取值出错：{e}")
            return ['null']

    def yearPage(self,url):
        res = self.get(url=url)
        # print(res.text)
        if res and res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            response = etree.HTML(str(soup))
            a_list = response.xpath('//article[@class="news-item news-item--3"]')
            for a in a_list:
                temp_link = a.xpath('.//a/@href')[0]
                detail_url = 'https://sec-consult.com/' + temp_link
                self.getDetail(detail_url)
    def getDetail(self,url):
        res = self.get(url=url)
        # print(res.text)
        if res and res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            response = etree.HTML(str(soup))
            select_v = response.xpath('//div[@class="news-detail__data"]')
            # 这是近年格式
            if len(select_v) > 0:
                b_name = self.getValue(response,"//div[@class='news-detail__top']/h1/text()")[0]
                detail_title = self.getValue(response,
                    '//div[@class="news-detail__data-item"][1]/p[@class="news-detail__data-value"]/text()')[0]
                detail_product = self.getValue(response,
                    '//div[@class="news-detail__data-item"][2]/p[@class="news-detail__data-value"]/text()')[0]
                detail_vulnerable_version = self.getValue(response,
                    '//div[@class="news-detail__data-item"][3]/p[@class="news-detail__data-value"]/text()')[0]
                detail_fixed_product = self.getValue(response,
                    '//div[@class="news-detail__data-item"][4]/p[@class="news-detail__data-value"]/text()')[0]
                detail_cve_number = self.getValue(response,
                    '//div[@class="news-detail__data-item"][5]/p[@class="news-detail__data-value"]/text()')[0]
                detail_impact = self.getValue(response,
                    '//div[@class="news-detail__data-item"][6]/p[@class="news-detail__data-value"]/text()')[0]
                detail_homepage = self.getValue(response,
                    '//div[@class="news-detail__data-item"][7]/a[@href]/text()')[0]
                detail_found = self.getValue(response,
                    '//div[@class="news-detail__data-item"][8]/p[@class="news-detail__data-value"]/text()')[0]
                detail_by = self.getValue(response,
                    '//div[@class="news-detail__data-item"][9]/p[@class="news-detail__data-value"]/text()')[0]
                # teaser部分
                detail_teaser = ""
                teaser = response.xpath("//div[@class='news-detail__teaser']/p")
                for temp in teaser:
                    t1 = temp.xpath('./text()')[0]
                    detail_teaser = detail_teaser + str(t1)

                # detail_text部分(vendor_description)
                detail_text = response.xpath("//div[@class='news-detail__text']//text()")
                all_detail_text = ''
                for text in detail_text:
                    all_detail_text = all_detail_text + str(text) + "\n"
                # print("这是all_detail_text",all_detail_text)
                # detail_text部分(vendor_description)
                all_article = response.xpath("//div[@class='article']//text()")
                all_article_text = ''
                for text in all_article:
                    all_article_text = all_article_text + str(text) + "\n"
                # vendor_description
                vendor_description = ''
                flag = 0
                for line in all_article_text.splitlines():
                    if flag == 0:
                        if 'Vendor description' in line:
                            flag = 1
                        elif 'Vendor Description' in line:
                            flag = 1
                        else:
                            flag = 0
                    else:
                        if 'recommendation' in line:
                            break
                        if 'Recommendation' in line:
                            break
                        else:
                            vendor_description = vendor_description + line + '\n'
                business_recommendation = ''
                flag = 0
                for line in all_article_text.splitlines():
                    if flag == 0:
                        if 'Business recommendation' in line:
                            flag = 1
                        else:
                            flag = 0
                    else:
                        if 'Vulnerability' in line:
                            break
                        else:
                            business_recommendation = business_recommendation + line + '\n'
                # vulnerability_overview
                vulnerability_overview = ''
                flag = 0
                for line in all_article_text.splitlines():
                    if flag == 0:
                        if 'Vulnerability overview/description' in line:
                            flag = 1
                        elif 'Vulnerability Overview/ Description' in line:
                            flag = 1
                        else:
                            flag = 0
                    else:
                        if 'Proof' in line:
                            break
                        else:
                            vulnerability_overview = vulnerability_overview + line + '\n'
                proof_of_concept = ''
                flag = 0
                for line in all_article_text.splitlines():
                    if flag == 0:
                        if 'Proof of concept' in line:
                            flag = 1
                        elif 'Proof Of Concept' in line:
                            flag = 1
                        else:
                            flag = 0
                    else:
                        if 'tested versions' in line:
                            break
                        elif 'Tested Versions' in line:
                            break
                        else:
                            proof_of_concept = proof_of_concept + line + '\n'
                tested_versions = ''
                flag = 0
                for line in all_article_text.splitlines():
                    if flag == 0:
                        if 'Vulnerable / tested versions' in line:
                            flag = 1
                        elif 'Vulnerable / Tested Versions' in line:
                            flag = 1
                        else:
                            flag = 0
                    else:
                        if 'Vendor contact timeline' in line:
                            break
                        else:
                            tested_versions = tested_versions + line + '\n'

                # vendor_contact_timeline ！！！！中间很多空格
                vendor_contact_timeline = ''
                contact_timeline = response.xpath("//section[@class='section section__table']//tbody/tr")
                for timeline in contact_timeline:
                    time1 = self.getValue(timeline,'./td[1]/text()')[0]
                    time1 = str(time1)
                    time = ''
                    for line in time1.splitlines():
                        if line.strip() == "":
                            pass
                        else:
                            time = time + line + '\n'
                    content = self.getValue(timeline,'./td[2]/text()')[0]
                    vendor_contact_timeline = vendor_contact_timeline + str(time) + str(content) + " "

                # section_text部分，Workaround,Solution，Advisory URL
                section_text = response.xpath('//section[@class="section section__text"]/div//text()')
                all_section_text = ''
                for text in section_text:
                    all_section_text = all_section_text + str(text) + "\n"
                # Solution
                section_solution = ''
                flag = 0
                for line in all_section_text.splitlines():
                    if flag == 0:
                        if 'Solution' in line:
                            flag = 1
                        else:
                            flag = 0
                    else:
                        if 'Workaround' in line:
                            break
                        else:
                            section_solution = section_solution + line + '\n'
                # Workaround
                section_workaround = ''
                flag = 0
                for line in all_section_text.splitlines():
                    if flag == 0:
                        if 'Workaround' in line:
                            flag = 1
                        else:
                            flag = 0
                    else:
                        if 'Advisory' in line:
                            break
                        else:
                            section_workaround = section_workaround + line + '\n'
                # advisory_url
                section_advisory_url = ''
                flag = 0
                for line in all_section_text.splitlines():
                    if flag == 0:
                        if 'Advisory' in line:
                            flag = 1
                        else:
                            flag = 0
                    else:
                        if 'EOF' in line:
                            break
                        else:
                            section_advisory_url = section_advisory_url + line + '\n'
            # 其他页面格式——_——
            else:
                b_name = response.xpath("//div[@class='news-detail__top']/h1/text()")[0]
                all_str = ""
                # section_text部分，Workaround,Solution，Advisory URL
                detail_text = response.xpath('//div[@class="news-detail__text"]//text()')
                all_str = ''
                for text in detail_text:
                    all_str = all_str + str(text) + "\n"
                # for line in all_str.splitlines():
                #     print("-----",line)
                # data部分
                # title
                flag = 0
                detail_title = ''
                for line in all_str.splitlines():
                    if flag == 0:
                        if 'title:' in line:
                            flag = 1
                            detail_title = line[7:]
                        else:
                            flag = 0
                    else:
                        if ':' or '=' in line:
                            break
                        else:
                            detail_title = detail_title + line
                # product
                flag = 0
                detail_product = ''
                for line in all_str.splitlines():
                    if flag == 0:
                        # print(line)
                        if 'product:' in line:
                            flag = 1
                            detail_product = line[9:]
                        elif 'Product:' in line:
                            flag = 1
                            detail_product = line[9:]
                        elif 'products:' in line:
                            flag = 1
                            detail_product = line[10:]
                        else:
                            flag = 0
                    else:
                        if '=' in line:
                            break
                        elif ':' in line:
                            break
                        else:
                            detail_product = detail_product + line

                # vulnerable version:
                flag = 0
                detail_vulnerable_version = ''
                for line in all_str.splitlines():
                    if flag == 0:
                        if 'vulnerable version:' in line:
                            flag = 1
                            detail_vulnerable_version = line[20:]
                        else:
                            flag = 0
                    else:
                        if ':' or '=' in line:
                            break
                        else:
                            detail_vulnerable_version = detail_vulnerable_version + line
                # fixed version:
                flag = 0
                detail_fixed_product = ''
                for line in all_str.splitlines():
                    if flag == 0:
                        if 'fixed version:' in line:
                            flag = 1
                            detail_fixed_product = line[15:]
                        else:
                            flag = 0
                    else:
                        if ':' or '=' in line:
                            break
                        else:
                            detail_fixed_product = detail_fixed_product + line
                # CVE number:
                flag = 0
                detail_cve_number = ''
                for line in all_str.splitlines():
                    if flag == 0:
                        if 'CVE number:' in line:
                            flag = 1
                            detail_cve_number = line[12:]
                        else:
                            flag = 0
                    else:
                        if ':' or '=' in line:
                            break
                        else:
                            detail_cve_number = detail_cve_number + line
                # impact:
                flag = 0
                detail_impact = ''
                for line in all_str.splitlines():
                    if flag == 0:
                        if 'impact:' in line:
                            flag = 1
                            detail_impact = line[8:]
                        else:
                            flag = 0
                    else:
                        if ':' or '=' in line:
                            break
                        else:
                            detail_impact = detail_impact + line
                # homepage:
                flag = 0
                detail_homepage = ''
                for line in all_str.splitlines():
                    if flag == 0:
                        if 'homepage:' in line:
                            flag = 1
                            detail_homepage = line[10:]
                        else:
                            flag = 0
                    else:
                        if '=' in line:
                            break
                        elif ':' in line:
                            break
                        else:
                            detail_homepage = detail_homepage + line
                # found:
                flag = 0
                detail_found = ''
                for line in all_str.splitlines():
                    if flag == 0:
                        if 'found:' in line:
                            flag = 1
                            detail_found = line[7:]
                        else:
                            flag = 0
                    else:
                        if '=' in line:
                            break
                        elif ':' in line:
                            break
                        else:
                            detail_found = detail_found + line
                # by
                flag = 0
                detail_by = ''
                for line in all_str.splitlines():
                    if flag == 0:
                        if 'by:' in line:
                            flag = 1
                            detail_by = line[4:]
                        else:
                            flag = 0
                    else:
                        if ':' or '=' in line:
                            # print("----by----",line)
                            break
                        else:
                            detail_by = detail_by + line

                detail_teaser = ''
                # vendor description:
                flag = 0
                vendor_description = ''
                for line in all_str.splitlines():
                    if flag == 0:
                        if 'Vendor description:' in line:
                            flag = 1
                        else:
                            flag = 0
                    else:
                        if 'description:' in line:
                            # print("----by----",line)
                            break
                        elif 'Recommendations:' in line:
                            break
                        elif '---' in line:
                            flag = 1
                        else:
                            vendor_description = vendor_description + line

                # business_recommendation
                business_recommendation = ''
                flag = 0
                for line in all_str.splitlines():
                    if flag == 0:
                        if 'recommendation:' in line:
                            flag = 1
                        else:
                            flag = 0
                    else:
                        if ':' in line:
                            # print("----by----",line)
                            break
                        elif '---' in line:
                            flag = 1
                        else:
                            business_recommendation = business_recommendation + line
                # Vulnerability overview/description:
                vulnerability_overview = ''
                flag = 0
                for line in all_str.splitlines():
                    if flag == 0:
                        if 'Vulnerability overview' in line:
                            flag = 1
                        else:
                            flag = 0
                    else:
                        if 'Proof' in line:
                            # print("----by----",line)
                            break
                        elif '---' in line:
                            flag = 1
                        else:
                            vulnerability_overview = vulnerability_overview + line
                # Proof of concept:
                flag = 0
                proof_of_concept = ''
                for line in all_str.splitlines():
                    if flag == 0:
                        if 'Proof of concept:' in line:
                            flag = 1
                        elif 'Proof Of Concept' in line:
                            flag = 1
                        else:
                            flag = 0
                    else:
                        if ':' in line:
                            # print("----by----",line)
                            break
                        elif '---' in line:
                            flag = 1
                        else:
                            proof_of_concept = proof_of_concept + line
                # tested_versions:
                tested_versions = ''
                flag = 0

                for line in all_str.splitlines():
                    if flag == 0:
                        if 'tested versions' in line:
                            flag = 1
                        else:
                            flag = 0
                    else:
                        if 'timeline:' in line:
                            # print("----by----",line)
                            break
                        elif '---' in line:
                            flag = 1
                        else:
                            tested_versions = tested_versions + line
                # vendor_contact_timeline
                vendor_contact_timeline = ''
                flag = 0
                for line in all_str.splitlines():
                    if flag == 0:
                        if 'Vendor contact timeline:' in line:
                            # print("line")
                            flag = 1
                        else:
                            flag = 0
                    else:
                        if 'Solution:' in line:
                            break
                        elif '---' in line:
                            flag = 1
                        else:
                            vendor_contact_timeline = vendor_contact_timeline + line
                # solution
                flag = 0
                section_solution = ''
                for line in all_str.splitlines():
                    if flag == 0:
                        if 'Solution:' in line:
                            flag = 1
                        else:
                            flag = 0
                    else:
                        if 'Workaround:' in line:
                            break
                        elif '---' in line:
                            flag = 1
                        else:
                            section_solution = section_solution + line
                # workaround
                flag = 0
                section_workaround = ''
                for line in all_str.splitlines():
                    if flag == 0:
                        if 'Workaround:' in line:
                            flag = 1
                        else:
                            flag = 0
                    else:
                        if ':' in line:
                            break
                        elif '---' in line:
                            flag = 1
                        else:
                            section_workaround = section_workaround + line
                # advisory_url
                flag = 0
                section_advisory_url = ''
                for line in all_str.splitlines():
                    if flag == 0:
                        if 'Advisory URL:' in line:
                            flag = 1
                        else:
                            flag = 0
                    else:
                        if '~' in line:
                            break
                        elif '---' in line:
                            flag = 1
                        else:
                            section_advisory_url = section_advisory_url + line

            item = {
                'Name':str(b_name),
                'Title': str(detail_title),
                'Product':str(detail_product),
                'Vulnerable_Version': str(detail_vulnerable_version),
                'Fixed_Product': str(detail_fixed_product),
                'Cve_Number': str(detail_cve_number),
                'Impact': str(detail_impact),
                'Homepage': str(detail_homepage),
                'Found': str(detail_found),
                'By': str(detail_by),
                'teaser': str(detail_teaser),

                'Vendor_Description': str(vendor_description),
                'Business_recommendation': str(business_recommendation),
                # Business_recommendation = scrapy.Field()
                'Vulnerability_Overview': str(vulnerability_overview),
                'Proof_Of_Concept': str(proof_of_concept),
                'Tested_Versions': str(tested_versions),

                'Vendor_Contact_Timeline': str(vendor_contact_timeline),

                'Solution': str(section_solution),
                'Workaround': str(section_workaround),
                'url': str(url)
            }
            with open(os.path.join(self.path, "data.json"), 'a', encoding='UTF-8') as f:
                f.write(str(item))
                f.write('\n')
                f.close()

            insert = [item]
            insert_mongo(self.collection, insert, self.key)

    def dataPreProc(self):
        print(f'----------{self.vulnName} 开始数据预处理----------')
        collection = self.collection
        system = self.system
        # 先把总数据表中对应数据源所有数据删除
        query = {'source': self.vulnName}
        result = system.delete_many(query)
        count = 1
        # print(f"删除了 {result.deleted_count} 条数据。")
        for doc in collection.find():
            item = init_item(self.vulnName)
            item['source_id'] = '未知'
            item['date'] = doc['Found'] if doc['Found'] is not None else 'null'
            item['details'] = doc['Proof_Of_Concept'] if doc['Proof_Of_Concept'] is not None else 'null'
            item['title'] = doc['Title'] if doc['Title'] is not None else 'null'
            item['vul_id'] = f"019_{str(count).zfill(6)}"
            item['cve_id'] = doc['Cve_Number'] if doc['Cve_Number'] is not None else 'null'
            if item['cve_id'] != 'null':
                item['software_version'] = isInDeepin(item['cve_id'])
            item['author'] = doc['By'] if doc['By'] is not None else 'null'
            count += 1
            # 其他字段丢进related
            related_data = {key: doc[key] for key in doc if
                            key not in ['_id', "Found", "Proof_Of_Concept", "Title", "Cve_Number", "By"]}
            # 将所有字段转换为字符串类型
            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data
            # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
            system.insert_one(item)

        print(f'----------{self.vulnName} 数据预处理完成----------')

    def run(self):
        self.collection.drop()
        self.crawlAndstorage()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')


# if __name__ == '__main__':
#     # 获取当前时间
#     start_time = time.time()
#     # 连接 MongoDB 数据库
#     client = MongoClient('localhost', 27017)
#     # 获取指定数据库和集合
#     db = client['306Project']
#     collection = db['sec_consult']

#     system = db['system']
#     agent = Sec_consult('sec_consult', collection, 'url', system)

#     agent.run()

#     client.close()
#     # 获取程序结束时间
#     end_time = time.time()
#     # 计算程序耗时
#     duration = end_time - start_time
#     # 打印程序耗时
#     print(f"程序耗时：{duration} 秒")
