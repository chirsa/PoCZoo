import os
import time
import re
import pandas as pd
import requests
from lxml import etree
import pymongo
from src.dataProceScript.spider_base import BaseSpider
# from src.dataProceScript.dataProce import init_item


class bugzilla(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        self.urls = []
        self.url = 'https://bugzilla.mozilla.org'

    def get_url(self):
        # 下载csv文件的URL
        csv_url = 'https://bugzilla.mozilla.org/buglist.cgi?classification=Client%20Software&classification=Developer%20Infrastructure&classification=Components&classification=Server%20Software&classification=Other&query_format=advanced&resolution=---&ctype=csv&human=1'
        
        # 保存csv文件的路径
        csv_path = "src/refe_file/bugzilla_mozilla.csv"
        
        try:
            # 下载csv文件
            response = requests.get(csv_url, headers=self.headers)
            response.raise_for_status()
            os.makedirs(os.path.dirname(csv_path), exist_ok=True)
            # 保存csv文件
            with open(csv_path, 'wb') as f:
                f.write(response.content)
                
            # 读取csv文件
            df = pd.read_csv(csv_path)
            
            # 提取Bug ID并生成URL
            for bug_id in df['Bug ID']:
                url = f'https://bugzilla.mozilla.org/show_bug.cgi?id={bug_id}'
                self.urls.append(url)
                
            self.logger.info(f'成功读取{len(self.urls)}个url')
        except Exception as e:
            self.logger.error(f'获取URL失败: {e}')

    def get_content(self):
        temp_dic = {
            'vul_id': 'null',
            'Url': 'null',
            'Bug ID': 'null',
            'Name': 'null',
            'CVE': 'null',
            'Date': 'null',
            'Product': 'null',
            'Type': 'null',
            'Component': 'null',
            'Priority': 'null',
            'Severity': 'null',
            'Platform': 'null',
            'Status': 'null',
            'Assignee': 'null',
            'Reporter': 'null',
            'Triage Owner': 'null',
            'CC': 'null',
            'References': 'null',
            'Keywords': 'null',
            'Whiteboard': 'null',
            'Votes': 'null',
            'Bug Flags': 'null',
            'Attachments': 'null',
            'Description': 'null'
        }
        num = len(self.urls)
        vul = 0
        for i in range(0, num):
            self.logger.info(f'开始处理第{i + 1}个url')
            url = self.urls[i]
            # 获取网页内容
            response = requests.get(url, headers=self.headers)
            response.encoding = 'utf-8'
            content = response.text
            t_etree = etree.HTML(content)

            # temp_dic['Text'] = content

            vul = vul + 1
            str_vul = str(vul)
            str_six_vul = str_vul.zfill(6)
            temp_dic['vul_id'] = '042_' + str_six_vul
            temp_dic['Url'] = url

            result = t_etree.xpath('//main/div/section[1]/div/div/div[1]/div/span/span[2]/a/text()')
            if result:
                temp_dic['Bug ID'] = result[0]

            result = t_etree.xpath('//main/div/section[1]/div/div/div[2]/div/h1//text()')
            if result:
                name_content = ''.join([keyword.strip() for keyword in result])
                temp_dic['Name'] = name_content

            result = t_etree.xpath('/html/body/div/main/div/section[1]/div/div/div[1]/div/span/span[2]/span/text()')
            if result:
                temp_dic['CVE'] = result[0] 

            result = t_etree.xpath(
                '/html/body/div/main/div/section[1]/div/div/div[1]/div/span/span[3]/span[2]/span/@title')
            if result:
                full_time = result[0]
                temp_dic['Date'] = full_time.split(' ')[0]

            result = t_etree.xpath('//main/div/section[2]/div/div[1]/div[1]/div[2]/span/div/aside/header/div[1]/text()')
            if result:
                temp_dic['Product'] = result[0]

            result = t_etree.xpath('//main/div/section[2]/div/div[2]/div[1]/div[2]/span/span//text()')
            if result:
                content = ''.join([keyword.strip() for keyword in result])
                temp_dic['Type'] = content

            result = t_etree.xpath('//main/div/section[2]/div/div[1]/div[2]/div[2]/span/div/span/text()')
            if result:
                temp_dic['Component'] = result[0]

            result = t_etree.xpath('//main/div/section[2]/div/div[2]/div[2]/div/span/div[1]/div[2]/span//text()')
            if result:
                content = ''.join([keyword.strip() for keyword in result])
                temp_dic['Priority'] = content

            result = t_etree.xpath('//main/div/section[2]/div/div[2]/div[2]/div/span/div[2]/div[2]/span//text()')
            if result:
                content = ''.join([keyword.strip() for keyword in result])
                temp_dic['Severity'] = content

            # result = t_etree.xpath('//main/div/section[2]/div/div[1]/div[4]/div[2]//text()')
            # if result:
            #     content = ' '.join([keyword.strip() for keyword in result])
            #     content = content.strip()
            #     temp_dic['Platform'] = content
            # 获取 Platform 内容
            platform_result = t_etree.xpath('//div[@id="field-rep_platform"]//span[@id="field-value-rep_platform"]//text()')
            if platform_result:
                platform_content = ''.join(platform_result).strip()  # 合并文本并去除多余空格
            else:
                platform_content = ''  # 如果没有找到Platform，则设为空
            # 获取 Operating System 内容
            os_result = t_etree.xpath('//div[@id="field-op_sys"]//span[@id="field-value-op_sys"]//text()')
            if os_result:
                 os_content = ''.join(os_result).strip()  # 合并文本并去除多余空格
            else:
                os_content = ''  # 如果没有找到Operating System，则设为空
            # 合并 Platform 和 Operating System 内容
            temp_dic['Platform'] = platform_content +','+ os_content
            



            result = t_etree.xpath('//main/div/section[3]/div/div[1]/div[1]/div[2]/span/text()')
            if result:
                temp_dic['Status'] = result[0]

            result = t_etree.xpath('//main/div/section[4]/div/div[1]/div[1]/div[2]/span/div/a/span/text()')
            if result:
                temp_dic['Assignee'] = result[0]

            result = t_etree.xpath('//main/div/section[4]/div/div[2]/div[1]/div[2]/span/div/a/span//text()')
            if result:
                content = ''.join([keyword.strip() for keyword in result])
                temp_dic['Reporter'] = content

            result = t_etree.xpath('//main/div/section[4]/div/div[2]/div[2]/div[2]/span/div/a/span//text()')
            if result:
                content = ''.join([keyword.strip() for keyword in result])
                temp_dic['Triage Owner'] = content
                

            result = t_etree.xpath('//main/div/section[4]/div/div[2]/div[3]/div[2]/span/span/text()')
            if result:
                temp_dic['CC'] = result[0]

            result = t_etree.xpath('/html/body/div/main/div/section[5]/div/div[1]/div[5]//text()')
            if result:
                text_content = ''  # 初始化一个空字符串
                for text in result:
                    stripped_text = text.strip()  # 去除前后空白
                    if stripped_text:  # 检查是否为空
                        text_content += stripped_text + ' '  # 添加到字符串中，并加入一个空格分隔
                text_content = text_content.strip()  # 去除字符串末尾的空格
                temp_dic['References'] = text_content

            result = t_etree.xpath('//main/div/section[6]/div/div[1]/div[2]/div[2]/span/a//text()')
            if result:
                # 将文本内容合并为一个字符串并去除空白
                keywords_content = ', '.join([keyword.strip() for keyword in result])
                temp_dic['Keywords'] = keywords_content

            result = t_etree.xpath('//main/div/section[6]/div/div[1]/div[3]/div[2]/span/text()')
            if result:
                temp_dic['Whiteboard'] = result[0]

            result = t_etree.xpath('//main/div/section[6]/div/div[1]/div[7]/div[2]/span/text()')
            if result:
                temp_dic['Votes'] = result[0]

           
            result1 = t_etree.xpath('//tbody[contains(@class, "edit-hide")]//text()')

            # 清理和合并结果
            cleaned_texts = [text.strip() for text in result1 if text.strip()]  # 去除空白和空文本
            if cleaned_texts:
                temp_dic['Bug Flags'] = cleaned_texts

            result =t_etree.xpath('//td[@class="attach-desc-td"]/div/text() | //td[@class="attach-desc-td"]/div/*/text()')
            # 清理和合并结果
            all_div_texts = '\n'.join(text.strip() for text in result if text.strip())
            if all_div_texts:
                temp_dic['Attachments'] = all_div_texts


            result = t_etree.xpath('//div[@class="change-set" and @id="c0"]//text()')
            # 清理和合并结果
            all_div_texts = '\n'.join(text.strip() for text in result if text.strip())
            if all_div_texts:
                temp_dic['Description'] = all_div_texts

            query = {'vul_id': temp_dic['vul_id']}
            self.collection.update_one(query, {'$set': temp_dic}, upsert=True)
            self.logger.info(f'存储成功第{i + 1}条数据')
            self.logger.info(f'存储成功第{i + 1}个url')

        self.logger.info(f'共计存储{vul}条数据')

    def crawl(self):
        self.get_url()
        self.get_content()

    # def dataProPre(self):
    #     self.logger.info(f'{self.vulnName}开始数据预处理')
    #     collection = self.collection
    #     system = self.system
    #     for doc in collection.find():
    #         item = init_item(self.vulnName)
    #         item['vul_id'] = doc['vul_id'] if doc['vul_id'] is not None else 'null'
    #         item['author'] = doc['Reporter'] if doc['Reporter'] is not None else 'null'
    #         item['cve_id'] = doc['CVE'] if doc['CVE'] is not None else 'null'
    #         item['details'] = doc['Description'] if doc['Description'] is not None else 'null'
    #         item['date'] = doc['Date'] if doc['Date'] is not None else 'null'
    #         item['platform'] = doc['Platform'] if doc['Platform'] is not None else 'null'
    #         item['title'] = doc['Name'] if doc['Name'] is not None else 'null'
    #         item['source'] = 'bugzilla'
    #         item['source_id'] = doc['Bug ID'] if doc['Bug ID'] is not None else 'null'
    #         item['type'] = doc['Type'] if doc['Type'] is not None else 'null'



    #         related_data = {key: doc[key] for key in doc if
    #                         key not in ['_id', 'vul_id', 'Reporter', 'CVE', 'Keywords',
    #                                     'Date', 'Platform', 'Name', 'Url', 'Type', 'Description','Bug ID']}
    #         # 将所有字段转换为字符串类型
    #         related_data = {key: str(val) for key, val in related_data.items()}
    #         item['related'] = related_data
    #         # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
    #         system.insert_one(item)
    #     self.logger.info(f'{self.vulnName} 数据预处理完成')

    def run(self):
        self.collection.drop()
        self.crawl()
        # queryrepeat(self.vulnName, self.collection, self.key)
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')
        # self.dataProPre()


# if __name__ == '__main__':
#     # 获取当前时间
#     start_time = time.time()

#     # 连接数据库，运行程序
#     client = pymongo.MongoClient('localhost', port=27017)
#     db = client['306Project']
#     collection = db['bugzilla']
#     # 每个源数据预处理后存入总数据表，总数据表名称
#     system = db['system']

#     obj = bugzilla('bugzilla', collection, 'url', system)
#     obj.run()
#     client.close()

#     # 获取程序结束时间
#     end_time = time.time()
#     # 计算程序耗时
#     duration = end_time - start_time
#     # 打印程序耗时
#     self.logger.info(f"程序耗时：{duration} 秒")
