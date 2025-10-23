import os
import random
import time
from urllib.request import Request, urlopen

import pymongo
from fake_headers import Headers
from lxml import etree

from src.dataProceScript.Setting import DATA_PATH, CURRENT_TIME

from src.dataProceScript.spider_base import BaseSpider


class Talos(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.url = 'https://talosintelligence.com/vulnerability_reports'
        header = Headers(browser='chrome',
                         os='win',
                         headers=True).generate()
        self.headers = {
            'User-Agent': header['User-Agent'],
            'cooike':'__cf_bm=B40BQmi81cyIPB2_RQ5LLWlxE2XOj_5HvRyljynhfWc-1714990552-1.0.1.1-cqu2XYS3yDgW5ihwZ9gmuptjn6L7_qwsa0KLVn.fNsNUlAcWiqqrf3KU24lUL4xkWHAY.pPBLFxZYpRpxU4EcA; __cflb=0H28vmoBAedUAhWLS6T78gEQCHuXeepmV6asVLnjoFy; _ga=GA1.2.684312866.1714990555; _gid=GA1.2.753346235.1714990555; _talos_website_session=n%2BVlLRWwiXUQOh%2FH40GbSNAFHTvQVxtK0p6tNCEYNrq3T6UtTC3tOSpP2oN%2FFOg70kWLY8TJXke4MY991fDnQUvsFF%2F%2BUh%2BhgiDhroSEi%2FWfz6b6L6VKjP%2BzoOaJtYj86emmI%2B5HbkhPZox3G9pG07%2F7W91HOIHr39ScGC4L%2BjTYR5C0%2BazCLiUKpcaOzUOGrXm2tjfWqQjfJPtpLNIud57g1T%2B3aFr3ysmIv1sDJhkAyemqWkMnG86Pj%2B%2BXlHxhxEJF%2FAHYp6hEk2Us1f%2BF1wKY587%2F0R156OhZLNl0jFsj2Evqd2hESGE2Pe%2F4c336q3IqGto2tcVe2k4SF87wf4wkIL56h78YF9YV%2FxtCTLAz8OjQqRw02ZaBje31v0MQU6AhuMrzLi6oZ%2FVTUGNz0xtA0YwfQJXcW8DJ3%2B%2FvK88%3D--7Zne2KTn2%2FvGHdxy--0M0ugzjAj7wfMFOw8FwVhA%3D%3D; _ga_RXLPXE1JZM=GS1.2.1714990556.1.1.1714991048.0.0.0'
        }

    def crawlAndMongo(self):
        try:
            request = Request(url=self.url, headers=self.headers)
            response = urlopen(request)
            content = response.read().decode('utf-8')
            tree = etree.HTML(content)
            li_list = tree.xpath('//tr[starts-with(@class,"clickable-row report-row")]/@data-url')
            # print(len(li_list))
            for i in range(len(li_list)):
                new_url = self.url.replace("/vulnerability_reports", "") + li_list[i]
                self.get(new_url, i)
                time.sleep(random.uniform(0.2, 2))
        except Exception as e:
            self.logger.error(f"{self.url}爬取失败，原因：{e}")

    def initial(self):

        vulnerability = {
            # “数据库中字段” : “存入的值”
            "report_id": '',
            'title':'',
            "CVE_number": '',
            "summary": '',
            "CONFIRMED_VULNERABLE_VERSIONS": '',
            "PRODUCT_URLS": '',
            "CVSSV3_SCORE": '',
            "CWE": '',
            "DETAILS": '',
            "Exploit_Proof_of_Concept": '',
            "TIMELINE": '',
        }
        return vulnerability

    def getValue(self,tree,key):
        try:
            res =  tree.xpath(key)[0].text
            # print(res)
        except:
            res = ''
        return res
    def getNextValue(self,tree,key):
        try:
            target = tree.xpath(key)
            next_sibling = target[0].getnext()
            if next_sibling is not None:
                res = etree.tostring(next_sibling, method='text', encoding='unicode')
                res = res.rstrip('\n')
        except Exception as e:
            res =''
        return res
    def whileGetnextvalue(self,tree,key):
        res = ''
        try:
            target = tree.xpath(key)
            next_sibling = target[0].getnext()
            # 循环获取下一个兄弟元素的值，直到下一个元素是h3或h5标签为止
            while next_sibling is not None and next_sibling.tag not in ['h3', 'h5']:
                # 获取下一个兄弟元素的值并拼接到 res 中
                res += etree.tostring(next_sibling, method='text', encoding='unicode') if next_sibling.text else ""
                res = res.rstrip('\n \t')
                # 获取下一个兄弟元素的下一个兄弟元素
                next_sibling = next_sibling.getnext()
        except Exception as e:
            res =''
        return res
    def get(self,new_url, i):
        try:
            request = Request(url=new_url, headers=self.headers)
            responce = urlopen(request)
            content = responce.read().decode('utf-8')
            tree = etree.HTML(content)
            vuln = self.initial()
            vuln['report_id'] = self.getValue(tree,'//h3[@class="report_id"]')
            vuln['title'] = self.getValue(tree,'//*[@id="page_wrapper"]/div[2]/div/div/div/div/h2')
            vuln['CVE_number'] = self.getNextValue(tree,'//h5[contains(text(), "CVE")]')
            vuln['summary'] = self.getNextValue(tree,'//div[@class="col-12 report"]/div/h5[@id="summary"]')
            vuln['CONFIRMED_VULNERABLE_VERSIONS'] = self.getNextValue(tree, '//div[@class="col-12 report"]/div/h5[@id="confirmed-vulnerable-versions"]')
            vuln['PRODUCT_URLS'] = self.getNextValue(tree, '//div[@class="col-12 report"]/div/h5[@id="product-urls"]')
            vuln['CVSSV3_SCORE'] = self.getNextValue(tree, '//div[@class="col-12 report"]/div/h5[@id="cvssv3-score"]')
            vuln['CWE'] = self.getNextValue(tree, '//div[@class="col-12 report"]/div/h5[@id="cwe"]')
            vuln['DETAILS'] = self.whileGetnextvalue(tree,'//div[@class="col-12 report"]/div/h5[@id="details"]')
            # print(vuln['DETAILS'])
            vuln['Exploit_Proof_of_Concept'] = self.whileGetnextvalue(tree, '//div[@class="col-12 report"]/div/h3[@id="exploit-proof-of-concept"]')
            vuln['TIMELINE'] = self.whileGetnextvalue(tree, '//div[@class="col-12 report"]/div/h5[@id="timeline"]')

            self.collection.insert_one(vuln)
            time.sleep(0.2)
            i += 1
        except Exception as e:
            self.logger.error(f"{new_url}爬取失败，原因：{e}")
        #print("以上是第" + str(i) + "条数据")

    # def dataPreProc(self):
    #     print('----------talos开始数据预处理----------')
    #     collection = self.collection
    #     system = self.system
    #     count = 1
    #     # 先把总数据表中对应数据源所有数据删除
    #     query = {'source': self.vulnName}
    #     result = system.delete_many(query)
    #     for doc in collection.find():
    #         item = init_item(self.vulnName)
    #         item['source_id'] = doc['report_id'] if doc['report_id'] is not None else 'null'
    #         item['date'] = doc['TIMELINE'] if doc['TIMELINE'] is not None else 'null'
    #         item['details'] = doc['DETAILS'] if doc['DETAILS'] is not None else 'null'
    #         item['title'] = doc['summary'] if doc['summary'] is not None else 'null'
    #         item['vul_id'] = f"017_{str(count).zfill(6)}"
    #         item['cve_id'] =  doc['CVE_number'] if doc['CVE_number'] is not None else 'null'
    #         if item['cve_id'] != 'null':
    #             item['software_version'] = isInDeepin(item['cve_id'])

    #         count += 1

    #         # 其他字段丢进related
    #         related_data = {key: doc[key] for key in doc if
    #                         key not in ['_id',"report_id", "TIMELINE", "DETAILS", "summary", "CVE_number"]}
    #         # 将所有字段转换为字符串类型
    #         related_data = {key: str(val) for key, val in related_data.items()}
    #         item['related'] = related_data

    #         # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
    #         system.insert_one(item)

    #     print('----------talos数据预处理完成----------')


    def run(self):
        self.collection.drop()  
        self.crawlAndMongo()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')


if __name__ == '__main__':
    # 获取当前时间
    start_time = time.time()
    # 连接数据库，运行程序
    myclient = pymongo.MongoClient('localhost', port=27017)
    db = myclient['306Project']
    collection = db['talos']

    # 每个源数据预处理后存入总数据表，总数据表名称
    system = db['system']

    obj = Talos('talos', collection, 'report_id', system)
    obj.run()
    myclient.close()

    # 获取程序结束时间
    end_time = time.time()
    # 计算程序耗时
    duration = end_time - start_time
    # 打印程序耗时
    print(f"程序耗时：{duration} 秒")
