
import os
import time
import requests
from lxml import etree
from lxml import html
import pymongo
from datetime import datetime
import random
# from src.dataProceScript.Setting import DATA_PATH, CURRENT_TIME
from src.dataProceScript.dataProce import init_item, isInDeepin
from src.dataProceScript.spider_base import BaseSpider

class codevigilant(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }

        self.tr_count = []
        self.urls = []
        self.dic_list = []  # 字典列表
    def get_url(self):
        url1 = 'https://codevigilant.com/category/injection/'
        url2 = 'https://codevigilant.com/category/cross-site-scripting-xss/'
        url3 = 'https://codevigilant.com/category/information-disclosure/'
        url4 = 'https://codevigilant.com/category/local-file-inclusion/'
        url5 = 'https://codevigilant.com/category/ssrf/'
        url6 = 'https://codevigilant.com/category/components-with-known-vulnerabilities/'
        url7 = 'https://codevigilant.com/category/unvalidated-redirects-and-forwards/'
        
        self.urls = [url1, url2, url3, url4, url5, url6, url7]


    # 找到目标url和目录下需要爬取的路径
    def get_content(self):
        global result
        url = 'https://codevigilant.com/'
        vul = 0
        temp_dic = {
            'vul_id': 'null',
            'Plugin Name:': 'null',
            'Effected Version': 'null',
            'Vulnerability': 'null',
            'Minimum Level of Access Required':'null',
            'CVE Number': 'null',
            'Identified by': 'null',
            'Disclosure Timeline': 'null',
            'Technical Details': 'null',
            'PoC Screenshot': 'null',
            'Exploit': 'null'
           
        }
        for i in range(0, 7):
            # print(f'-----------------开始处理第{i+1}个url-----------------')
            self.logger.info(f'-----------------开始处理第{i+1}个url-----------------')
            responses = self.get(url=self.urls[i], headers=self.headers)
            # 假设content是你从响应中获取的HTML内容
            content = responses.text
            # 使用etree解析HTML内容
            t_etree = etree.HTML(content)
            # 获取所有的tbody元素
            td_list = t_etree.xpath('//td[2]/a/@href')
            tbody = t_etree.xpath('//table/tbody')[0]
            self.tr_count.append(len(tbody.xpath('./tr')))
            # 计算每个tbody元素中td标签的数量
            # print(f'-----------------获取了{self.tr_count[i]}个二级链接-----------------')
            self.logger.info(f'-----------------获取了{self.tr_count[i]}个二级链接-----------------')
            # print(f'-----------------开始存储第{i+1}个url下二级链接的粗数据-----------------')
            self.logger.info(f'-----------------开始存储第{i+1}个url下二级链接的粗数据-----------------')
            for num in range(0, self.tr_count[i]):
                # 获取td标签下第二个a标签的内容
                temp_url = url + td_list[num]
                # 响应二级链接
                responses = self.get(url=temp_url, headers=self.headers)
                # 获取所有内容
                time.sleep(random.uniform(0.2, 2))
                c_content = responses.text
                c_etree = etree.HTML(c_content)
                # 填写字典
                vul = vul + 1
                str_vul = str(vul)
                str_six_vul = str_vul.zfill(6)
                temp_dic['vul_id'] = '032_'+str_six_vul
                
                result = c_etree.xpath('/html/body/main/div[1]/a/text()')
                if result:
                    temp_dic['Plugin Name:'] = result[0]

                result = c_etree.xpath('/html/body/main/div[2]/text()')
                if result:
                    temp_dic['Effected Version'] = result[0]

                result = c_etree.xpath('/html/body/main/div[3]/a/text()')
                if result:
                    temp_dic['Vulnerability'] = result[0]

                result = c_etree.xpath('/html/body/main/div[4]/text()')
                if result:
                    temp_dic['Minimum Level of Access Required'] = result[0]

                result = c_etree.xpath('/html/body/main/div[5]/text()')
                if result:
                    cve_number_text = result[0].strip()  # 去除前后空格
                    if cve_number_text.startswith("CVE Number :"):
                        # 从字符串中提取CVE编号
                        extracted_value = cve_number_text.split(":")[1].strip() if ":" in cve_number_text else 'null'
                        temp_dic['CVE Number'] = extracted_value if extracted_value else 'null'  # 检查提取的值是否为空
                    else:
                        temp_dic['CVE Number'] = cve_number_text
                else:
                    temp_dic['CVE Number'] = 'null'

                result = c_etree.xpath('/html/body/main/div[6]/a/text()')
                if result:
                    temp_dic['Identified by'] = result[0]

                result = c_etree.xpath('/html/body/main/ul/li[1]/div/text()')
                if result:
                    disclosure_timeline_text = result[0].strip()  # 去除前后空格
                    # 提取日期部分
                    date_str = disclosure_timeline_text.split(":")[0] if ":" in disclosure_timeline_text else 'null'
                    # 将日期字符串格式化为 "YYYY-MM-DD"
                    try:
                        # 假设日期格式为 "Month Day, Year"（如 "June 15, 2021"）
                        date_formatted = datetime.strptime(date_str, '%B %d, %Y').strftime('%Y-%m-%d')
                        temp_dic['Disclosure Timeline'] = date_formatted
                    except ValueError:
                        # 如果日期格式不符合预期
                        temp_dic['Disclosure Timeline'] = 'null'
                else:
                    temp_dic['Disclosure Timeline'] = 'null'
                    
                # Technical Details，有多个P标签，且P标签下还有<code>标签，需要处理一下
                result = c_etree.xpath('/html/body/main/p//text()')
                if result:
                    temp_dic['Technical Details'] = ' '.join(result).strip()

                result = c_etree.xpath('//body//p//img/@src')
                if result:
                    temp_dic['PoC Screenshot'] = result[0]

                result = c_etree.xpath('/html/body/main/pre[2]/code/text()')
                if result:
                    temp_dic['Exploit'] = result[0]

                self.dic_list.append(temp_dic)
                # self.collection.insert_one(self.dic_list[num])
                query = {'vul_id': temp_dic['vul_id']}
                self.collection.update_one(query, {'$set': temp_dic}, upsert=True)
                # print("存储成功第"+str(num+1)+"条")
            # print(f'-----------------存储成功第{i+1}个url-----------------')
        # print(f'-----------------共计存储{vul}条数据-----------------')

    def dataPreProc(self):
        print(f'----------{self.vulnName}开始数据预处理----------')
        collection = self.collection
        system = self.system
        for doc in collection.find():
            item = init_item(self.vulnName)
            item['vul_id'] = doc['vul_id'] if doc['vul_id'] is not None else 'null'
            item['author'] = doc['Identified by'] if doc['Identified by'] is not None else 'null'
            item['cve_id'] = doc['CVE Number'] if doc['CVE Number'] is not None else 'null'
            item['details'] = doc['Technical Details'] if doc['Technical Details'] is not None else 'null'
            item['date'] = doc['Disclosure Timeline'] if doc['Disclosure Timeline'] is not None else 'null'
            item['platform'] = 'null'
            item['title'] = doc['Plugin Name:'] if doc['Plugin Name:'] is not None else 'null'
            item['source'] = 'Code Vigilant'
            item['source_id'] = 'null'
            item['type'] = doc['Vulnerability'] if doc['Vulnerability'] is not None else 'null'
            # # 提取 'Effected Version' 对应的值，并移除前面的 'Effected Version:' 部分
            # software_version_value = doc.get('Effected Version','')
            # # 移除前缀并赋值给 item['software_version']
            # if software_version_value.startswith('Effected Version : '):
            #     item['software_version'] = software_version_value[len('Effected Version : '):] if doc['Effected Version'] is not None else 'null'

            if item['cve_id'] != 'null':
                item['software_version'] = isInDeepin(item['cve_id'],self.deepin23beta3,self.tx)  
                # 其他字段丢进related
            related_data = {key: doc[key] for key in doc if
                            key not in ['_id', 'vul_id', 'Identified by', 'CVE Number', 'Technical Details',
                                        'Disclosure Timeline', 'Vulnerability', 'Plugin Name:']}
            # 将所有字段转换为字符串类型
            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data
            # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
            system.insert_one(item)
        print(f'----------{self.vulnName} 数据预处理完成----------')

    def crawl(self):
        self.get_url()
        self.get_content()

    def run(self):
        self.collection.drop()
        self.crawl()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')



# if __name__ == '__main__':
#     # 获取当前时间
#     start_time = time.time()

#     # 连接数据库，运行程序
#     client = pymongo.MongoClient('localhost', port=27017)
#     db = client['306Project']
#     collection = db['vigilant']
#     # 每个源数据预处理后存入总数据表，总数据表名称
#     system = db['system']

#     obj = CodeVigilant('CODE_VIGILANT', collection, 'url', system)
#     obj.run()
#     client.close()

#     # 获取程序结束时间
#     end_time = time.time()
#     # 计算程序耗时
#     duration = end_time - start_time
#     # 打印程序耗时
#     print(f"程序耗时：{duration} 秒")
