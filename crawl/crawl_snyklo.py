import json
import os
import time
import re
import pymongo
import requests
from requests.adapters import HTTPAdapter
import bs4 as soup
import logging

from src.dataProceScript.Setting import DATA_PATH, CURRENT_TIME
from src.dataProceScript.dataProce import insert_mongo, getVulid, init_item, getDeepin, isInDeepin
from src.dataProceScript.spider_base import BaseSpider


class snyklo(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.key = 'url'
        # self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        # if not os.path.exists(self.path):
        #     os.makedirs(self.path)
        # self.deepin23beta3, self.deepin2404 = getDeepin()

    def initialize(self):
        return {
            "name": "",
            "type": "",
            "package": "",
            "range": [],
            "fix": "",
            "overview": "",
            "references": [],
            "introduced_time": "",
            "cve_id": "",
            "cwe_id": "",
            "cvss_score": "",
            "severity_badge": "",
            "epss": "",
            "snyk_id": ""
        }


    def typeGetpageUrl(self):
        typeList = ['cargo', 'cocoapods', 'composer', 'golang', 'hex', 'maven', 'npm', 'nuget', 'pip',
                    'rubygems', 'swift', 'unmanaged', 'alpine', 'amzn', 'centos', 'debian', 'oracle',
                    'rhel', 'rocky', 'sles', 'ubuntu', 'wolfi', 'chainguard']
        # typeList = ['cargo']

        for type in typeList:
            # print(f"----------------------{type}----------------------")
            count = 1
            isExist = True
            while True:
                if isExist == False:
                    break
                # print("{}类型，第{}页".format(type, count))
                url = 'https://security.snyk.io/vuln/' + type + "/" + str(count)
                isExist = self.listGetVulnURL(url)
                count += 1

    def listGetVulnURL(self, page_url):
        o = requests.Session()
        o.mount('http://', HTTPAdapter(max_retries=3))
        count = 1
        isExist = False
        try:
            res = o.get(page_url, timeout=5)
            res.raise_for_status()
            html = res.content.decode()
            s = soup.BeautifulSoup(html, "html.parser")
            # 先判断该类型漏洞这页是否存在
            # if isPageExist(s):
            tbody = s.find_all(attrs={'class': 'table__tbody'})
            # 获取该页的漏洞列表
            vul_list = tbody[0].find_all(attrs={'class': 'table__row'})
            isExist = True
            for t in vul_list:

                # print(count)
                count = count + 1
                vul_name = t.find_all(attrs={'class': 'anchor'})
                name = vul_name[0].text.strip()
                url = "https://security.snyk.io/" + vul_name[0].attrs['href']
                # print(name, url)
                try:
                    self.getVulnInformation(url)

                except Exception as e1:
                    # print(e1, e1.__traceback__.tb_lineno)
                    self.logger.error(f"第{count}个漏洞{name}获取失败，原因：{e1}")

        except Exception as e:
            # print(e, e.__traceback__.tb_lineno)
            self.logger.error(f"{page_url}获取失败，原因：{e}")
        return isExist

    def isPageExist(self, html):
        return False
    

    def getVulnInformation(self, url):
        # print(url)
        vuln_detail = self.initialize()
        o = requests.Session()
        o.mount('http://', HTTPAdapter(max_retries=3))
        res = o.get(url, timeout=5)
        res.raise_for_status()
        html = res.content.decode()
        s = soup.BeautifulSoup(html, "html.parser")

        '''
        第一部分，title_info，包含漏洞名称、受影响的包、受影响的包版本范围、漏洞类型
        '''
        # print("-----第一部分，title_info------")
        title = s.find_all(attrs={'class': 'heading'})
        info_str = ' '.join([text.strip() for text in title[0].stripped_strings]) 
        pattern = r"""
            ^(.+?)\s+                # 漏洞名称（非贪婪匹配到第一个关键词前）
            (?:Affecting|in|:)\s+    # 分隔符
            (.+?)\s+                 # 包名称
            (?:package, versions|version:|versions|,)\s*
            (.+)$                    # 版本范围
        """

        match = re.search(pattern, info_str, re.VERBOSE | re.IGNORECASE)
        if match:
            vuln_detail["name"] = match.group(1).strip()
            vuln_detail["package"] = match.group(2).strip().replace('package', '').strip()
            
            # 处理多版本范围（用逗号分隔）
            version_ranges = [v.strip() for v in match.group(3).split(',')]
            vuln_detail["range"] = version_ranges
            
        else:
            # 添加错误处理
            logging.warning(f"Failed to parse vulnerability info: {info_str}")
            vuln_detail["name"] = info_str  # 原始信息回退

        # vuln_detail["type"] = s.find_all(attrs={'class': 'vue--breadcrumbs__list-item'})[1].text  # 漏洞类型

        '''
        第二部分，fix_info,包含修复建议、概述、参考链接
        '''
        # print("-----第二部分，fix_info------")
        fix_info = s.find_all(attrs={'class': "markdown-section"})

        for fi in fix_info:
            title = fi.find("h2").text.strip()
            if title == "How to fix?":
                vuln_detail["fix"] = fi.find(attrs={'class': 'prose'}).text.strip()

            if title == "PoC":
                vuln_detail["PoC"] = fi.find(attrs={'class': 'prose'}).text.strip()

            if title == "Details":
                vuln_detail["Details"] = fi.find(attrs={'class': 'prose'}).text.strip()

            if title == "Overview":
                vuln_detail["overview"] = fi.find(attrs={'class': 'prose'}).text.strip()

            if title == "References":
                references = fi.find(attrs={'class': 'prose'}).find_all("a")
                for refer in references:
                    references_href = refer.attrs['href']
                    references_name = refer.text
                    dict = {"references_name": references_name, "references_href": references_href}
                    vuln_detail["references"].append(dict)


        '''
        第三部分，cve_info，包含CVE_id、CWE_id、引入时间
        '''
        # print("-----第三部分，cve_info-------")
        cve_info = s.find_all(attrs={"class": "vuln-info-block"})
        introduced_time = cve_info[0].find_all(attrs={"class": "heading"})[0].text
        vuln_detail["introduced_time"] = introduced_time.split(':')[1].strip()
        cveAndcwe = cve_info[0].find_all(attrs={"class": "anchor"})
        '''synk给出了cve_id的链接，这里并没有爬取链接，cve和cwe的链接都是url+cve_id形式，如：https://www.cve.org/CVERecord?id=CVE-2023-26987
            之后需要链接地址，只需一行代码url+cve_id，就不需要数据库存储链接，只需获取cve_id即可。
        '''

        for b in cveAndcwe:
            temp = b.text.strip().split("\n")[0]
            if temp.startswith('CVE'):
                vuln_detail["cve_id"] = temp
                continue
            if temp.startswith('CWE'):
                vuln_detail["cwe_id"] = temp
                continue
        # print(vuln_detail.introduced_time + "\n" + vuln_detail.cve_id + "\n" + vuln_detail.cwe_id)

        '''第四部分，synk_cvss_info,包含cvss_score,severity_badge

            Attack Complexity,Confidentiality,Integrity,Availability,
            Attack Vector,Privileges Required,User Interaction,scope(这八个没有爬取)
        '''
        # print("-----第四部分，synk_cvss_info-------")
        severity_badge = s.find('span', class_='badge badge--medium-severity badge--uppercase badge--small vendorcvss__badge')  # 根据实际等级调整 class
        if severity_badge:
            # 使用正则表达式提取数值和等级
            badge_text = severity_badge.get_text(strip=True)
            match = re.match(r'(\d+\.\d+)\s*([a-zA-Z]+)', badge_text)
            if match:
                vuln_detail["cvss_score"] = match.group(1)  # 6.9
                vuln_detail["severity_badge"] = match.group(2).lower()  # medium
            else:
                # 回退方案：分割处理
                parts = badge_text.split()
                if len(parts) >= 2:
                    vuln_detail["cvss_score"] = parts[0]
                    vuln_detail["severity_badge"] = ' '.join(parts[1:]).lower()

        # 在 getVulnInformation 方法中添加以下代码（放在处理 severity_badge 的部分之后）
        cvss_details = {}
        cvss_container = s.find('div', class_='vendorcvss__container')
        if cvss_container:
            # 获取所有指标分类列表（基础指标/时序指标/环境指标等）
            cvss_lists = cvss_container.find_all('ul', class_='vendorcvss__list')
            
            for cvss_list in cvss_lists:
                # 提取分类标题（如"Base Score"、"Exploitability"等）
                category = cvss_list.find_previous('h3').get_text(strip=True)
                
                for item in cvss_list.find_all('li', class_='vendorcvss__list_item'):
                    try:
                        # 提取字段名称（包含分类前缀）
                        label = item.find('span', class_='tooltip-trigger').get_text(strip=True)
                        clean_label = f"{category}_{re.sub(r'\s*\(.*?\)', '', label)}"
                        
                        # 提取字段值并标准化
                        value = item.find('strong').get_text(strip=True).lower()
                        value = {'n':'none', 'h':'high', 'l':'low'}.get(value[0], value)
                        
                        cvss_details[clean_label.lower().replace(' ', '_')] = value
                        
                    except Exception as e:
                        logging.warning(f"CVSS字段解析失败: {str(e)}")

        # 将结果合并到漏洞详情中
        vuln_detail["cvss_details"] = cvss_details       
        # print(cvss_details)

        

        '''
        第五部分，other_info,包括，EPSS,Snyk ID
        '''
        # print("-----第五部分，other_info-------")

        
        try:
            # 通过 data-snyk-test 属性精准定位
            snyk_item = s.find('li', attrs={"data-snyk-test": "vuln detailsbox item"})
            
            # 组合定位：同时匹配标签名和文本内容
            label_span = snyk_item.find('span', class_='credits__label', text='Snyk ID')
            
            if label_span:
                vuln_detail["snyk_id"] = label_span.find_next('strong').get_text(strip=True)
            else:
                vuln_detail["snyk_id"] = "N/A"
                logging.warning(f"Snyk ID not found in: {snyk_item}")
                
        except (AttributeError, IndexError) as e:
            vuln_detail["snyk_id"] = "N/A"
            logging.warning(f"Snyk ID extraction failed: {str(e)}")

        '''
        转为json格式，存入mongoDB
        '''

        insert_content = {'name': vuln_detail["name"], "url": url, 'details': vuln_detail}
        # print(insert_content)
        insert = [insert_content]
        insert_mongo(self.collection, insert, 'url')
        # with open(os.path.join(self.path, 'snyk_data.json'), 'a') as f:
        #     json_str = json.dumps(vuln_detail)
        #     f.write(json_str)
        #     f.close()

        time.sleep(0.2)


    def dataPreProc(self):
        print('----------synk 开始数据预处理----------')
        collection = self.collection
        system = self.system
        count = 1
        # 先把总数据表中对应数据源所有数据删除
        query = {'source': self.vulnName}
        result = system.delete_many(query)
        # print(f"删除了 {result.deleted_count} 条数据。")
        for doc in collection.find():
            item = init_item(self.vulnName)
            item['source_id'] = doc['details']['snyk_id'] if doc['details']['snyk_id'] is not None else 'null'
            item['date'] = doc['details']['introduced_time'] if doc['details'][
                                                                    'introduced_time'] is not None else 'null'
            item['details'] = doc['details']['overview'] if doc['details']['overview'] is not None else 'null'
            item['title'] = doc['name'] if doc['name'] is not None else 'null'
            item['cve_id'] = doc['details']['cve_id'] if doc['details']['cve_id'] is not None else 'null'
            if item['cve_id'] != 'null':
                item['software_version'] = isInDeepin(item['cve_id'], self.deepin23beta3, self.deepin2404)

            item['type'] = doc['details']['type'] if doc['details']['type'] is not None else 'null'

            item['vul_id'] = f"020_{str(count).zfill(6)}"
            count += 1
            # 其他字段丢进related
            related_data = {key: doc[key] for key in doc if key not in ['_id', "name"]}

            related_data = {key: doc[key] for key in doc if key not in ['_id', "name", "details"]}
            related_data1 = {key: doc['details'][key] for key in doc['details'] if
                             key not in ['snyk_id', 'overview', 'type', 'cve_id', 'introduced_time']}
            related_data.update(related_data1)
            # 将所有字段转换为字符串类型
            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data

            # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
            system.insert_one(item)

        print('----------synk 数据预处理完成----------')

    def run(self):
        self.collection.drop()
        self.typeGetpageUrl()
        self.count = self.collection.count_documents({})
        self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')
        # self.dataPreProc()


# if __name__ == '__main__':
#     # 获取当前时间
#     start_time = time.time()

#     # 连接数据库，运行程序
#     client = pymongo.MongoClient("localhost", port=27017)
#     local_vulnerability = client['306Project']
#     collection = local_vulnerability['snyk1']

#     # 每个源数据预处理后存入总数据表，总数据表名称
#     system = local_vulnerability['system']

#     obj = SNYK('snyk', collection, 'url', system)
#     obj.run()
#     client.close()

#     # 获取程序结束时间
#     end_time = time.time()
#     # 计算程序耗时
#     duration = end_time - start_time
#     # 打印程序耗时
#     print(f"程序耗时：{duration} 秒")