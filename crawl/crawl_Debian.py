import json
import subprocess
import re
import time

from pymongo import MongoClient

from src.dataProceScript.dataProce import queryrepeat, insert_mongo, init_item, fieldToValue, isInDeepin, run_command
from src.dataProceScript.Setting import *
from src.dataProceScript.spider_base import BaseSpider

class Debian(BaseSpider):
    def __init__(self, db, vulnName):
        super().__init__(db, vulnName)
        self.key = 'dsaID'
        # # windows
        # self.path = f'{DATA_PATH}/{CURRENT_TIME}/debian'
        # linux
        self.path = f'{DATA_PATH}/{CURRENT_TIME}/{vulnName}'
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        self.dsa_jsonfile = f'{DATA_PATH}/{CURRENT_TIME}/Debian/dsa_data.json'
        self.cve_jsonfile = f'{DATA_PATH}/{CURRENT_TIME}/Debian/cve_data.json'

    def clone(self):
            if os.listdir(self.path):
                self.logger.info(f'----------{self.vulnName} 文件夹已有数据，不再下载！----------')
                return 1

            url = 'https://salsa.debian.org/security-tracker-team/security-tracker.git'
            try:
                self.logger.info(f"准备克隆仓库：{url}")
                run_command(f"cd {self.path} && rm -rf ./* && git clone --depth 1 {url}", self.path)
                self.logger.info(f'----------{self.vulnName} 下载完成----------')
                if os.listdir(self.path):
                    return 1
                else:
                    raise Exception("未成功下载！！！")
            except Exception as e:
                self.logger.error(f"发生了异常：{e}")
                return 0

    def dsaToMongo(self,file):

        with open(file, 'r') as f:
            debianData = json.load(f)
        insert_mongo(self.collection, debianData, self.key)

        # 查重
        queryrepeat(self.vulnName, self.collection, self.key)

    def dataPreProc(self):
        print(f'----------{self.vulnName} 开始数据预处理----------')
        collection = self.collection
        system = self.system
        # 先把总数据表中对应数据源所有数据删除
        query = {'source': self.vulnName}
        result = system.delete_many(query)
        # print(f"删除了 {result.deleted_count} 条数据。")
        count = 1
        for doc in collection.find():
            item = init_item(self.vulnName)
            item['source_id'] = doc['dsaID'] if doc['dsaID'] is not None else 'null'
            item['date'] = doc['time'] if doc['time'] is not None else 'null'
            item['details'] = '未知'
            item['title'] = doc['dsaID'] if doc['dsaID'] is not None else 'null'
            item['vul_id'] = f"004_{str(count).zfill(6)}"
            count += 1

            # 关联的cve有多个时，只保留第一个
            for cve in fieldToValue(doc,'cvsIDs'):
                # print(cve)
                item['cve_id'] = cve
                break

            if item['cve_id'] != 'null':
                item['software_version'] = isInDeepin(item['cve_id'])
            # 其他字段丢进related
            related_data = {key: doc[key] for key in doc if
                            key not in ['_id',"dsaID", "time", "description", "title", "cves"]}
            # 将所有字段转换为字符串类型
            related_data = {key: str(val) for key, val in related_data.items()}
            item['related'] = related_data
            # 数据预处理前存入的数据库以及做过去重，这里可以直接存进
            system.insert_one(item)
        self.logger.info(f'----------{self.vulnName} 数据预处理完成----------')

    def run(self):
        # self.dataPreProc()
        self.collection.drop()
        notDownload = True
        while notDownload:
            isExist = self.clone()
            if isExist:
                notDownload = False
                dsa = DSA(self.path)
                dsa.fetch_list()
                self.dsaToMongo(self.dsa_jsonfile)
                self.count = self.collection.count_documents({})
                self.logger.info(f'{self.vulnName}共计爬取{self.count}条数据')
            else:
                self.logger.info(f'{self.vulnName}异常，重新尝试下载')
                break
                # self.dataPreProc()

            # debian = debianCVE(self.path)
            # debian.fetch_list()
            # self.dsaToMongo(self.cve_jsonfile)


class DSA():
    def __init__(self,path):
        self.jsonfile = f'{path}/dsa_data.json'
        self.listfile = f'{path}/security-tracker/data/DSA/list'
    def initialize(self):

        time = ''
        dsaID = ''
        cvsIDs = []
        package = ''
        probInfo = ''
        updateInfo = []
        dsaInfo = {}

        return dsaID, cvsIDs, package, probInfo, time, updateInfo, dsaInfo

    def isTime(self,line):

        # 定义正则表达式模式
        pattern = r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"

        # 使用findall函数从字符串中提取所有匹配项，并将其存储在matches列表中。
        matches = re.findall(pattern, line)

        if any(i in line for i in ['February', 'Feb 15th']):
            return False
        elif matches:
            return True
        else:
            return False
    def fetch_list(self):
        data = []

        with open(self.listfile, 'r') as f:
            lines = f.readlines()
            i = 0
            isStart = False
            line = ''
            while i < len(lines):
                line += lines[i].strip()
                if i < len(lines) - 1:
                    if self.isTime(lines[i + 1].strip()):
                        i += 1
                        self.match(line, data)
                        line = ''
                    else:
                        i += 1
                        continue

                elif i == len(lines) - 1:
                    i += 1
                    self.match(line, data)
                    line = ''
                else:
                    i += 1
                    continue
        # print(data)
        with open(self.jsonfile, 'w') as f:
            json.dump(data, f, indent=4)

    def match(self, line, data):
        # print(line)
        isStop = False
        dsaID, cvsIDs, package, probInfo, time, updateInfo, dsaInfo = self.initialize()
        time_pattern = re.compile(r'\[(.*?)\]')
        time_match = time_pattern.search(line)
        if time_match and self.isTime(line):
            time = time_match.group(1)

        line1 = line[line.index("]") + 2:]

        if line1.startswith('DSA-'):

            dsaID = line1[:line1.index(" ")]

            line1 = line1[line1.index(" ") + 1:]
            # print(line1)
            package = line1[:line1.index(" ")]
            if '{' in line1:
                probInfo = line1[line1.index("- ") + 2:line1.index("{")]

                line1 = line1[line1.index("{"):]
                cvsIDs = line1[line1.index("{") + 1:line1.index("}")].split()
                if 'NOTE' in line1:
                    if not '[' in line1:
                        line1 = ''
                        # print(dsaID)
                    else:
                        line1 = line1[line1.index("["):]
                else:
                    line1 = line1[line1.index("}") + 1:]
                if not '[' in line1:
                    isStop = True
            elif any(i in line1 for i in ['NOTE', 'PGP/GPG', 'end-of-life', 'end of life']):
                probInfo = line1[line1.index(" ") + 1:]
                isStop = True
            else:
                if '[' in line1:
                    probInfo = line1[line1.index("- ") + 2:line1.index("[")]
                    line1 = line1[line1.index("["):]
                else:
                    probInfo = line1[line1.index("- ") + 2:]
                    isStop = True

            while not isStop:
                if line1.startswith('['):
                    appliSys = line1[line1.index("[") + 1:line1.index("]")]
                    line1 = line1[line1.index("]") + 1:]
                    if '[' in line1:
                        versioned = line1[line1.index("- ") + 2:line1.index("[")]
                        line1 = line1[line1.index("["):]
                    else:
                        versioned = line1[line1.index("- ") + 2:]
                        isStop = True
                    dict = {'appliSys': appliSys, 'versioned': versioned}
                    updateInfo.append(dict)
            dsaInfo['dsaID'] = dsaID
            dsaInfo["cvsIDs"] = cvsIDs
            dsaInfo['time'] = time
            dsaInfo['package'] = package
            dsaInfo['probInfo'] = probInfo
            dsaInfo['updateInfo'] = updateInfo
            data.append(dsaInfo)

class debianCVE():
    def __init__(self,path):
        self.jsonfile = f'{path}/cve_data.json'
        self.listfile = f'{path}/security-tracker/data/CVE/list'

    def fetch_list(self):
        data = []
        with open(self.listfile, 'r') as f:
            lines = f.readlines()
            i = 0
            pattern1 = r'\((.*?)\.\.\.\)'
            pattern2 = r"\[([^\]]*)\]"
            cve_info, cve_id, alias, cve_description, impact, reference, impact_system, status = self.initialize()
            while i < len(lines):

                line = lines[i].strip()
                if line.startswith('CVE-'):
                    if i > 1:
                        cve_info['cve_id'] = cve_id if cve_id else 'None'
                        cve_info['alias'] = alias if alias else 'None'
                        cve_info['cve_description'] = cve_description if cve_description else 'None'
                        cve_info['package/version'] = impact if impact else 'None'
                        cve_info['reference'] = reference if reference else 'None'
                        cve_info['impact_system'] = impact_system if impact_system else 'None'
                        cve_info['status'] = status if status else 'None'
                        data.append(cve_info)
                        cve_info, cve_id, alias, cve_description, impact, reference, impact_system, status = self.initialize()
                    if re.findall(pattern1, line):
                        cve_id = line.split('(')[0].strip()
                        cve_description = re.findall(pattern1, line)[0]
                    elif re.findall(pattern2, line):
                        cve_id = line.split('[')[0].strip()
                        cve_description = re.findall(pattern2, line)[0]
                    else:
                        cve_id = line
                        cve_description = 'None'
                else:
                    if line.startswith('{'):
                        alias = ''
                        alias = line.strip()
                    elif line.strip().startswith('-'):
                        if not len(impact):
                            impact = []
                        impact.append(line.strip())
                    elif line.strip().startswith('NOTE'):
                        if not len(reference):
                            reference = []
                        reference.append(line.strip())
                    elif line.strip().startswith('['):
                        if not len(impact_system):
                            impact_system = []
                        impact_system.append(line.strip())
                    else:
                        status = line.strip()
                i += 1
        with open(self.jsonfile, 'w') as f:
            json.dump(data, f, indent=4)


    def initialize(self):
        cve_info = {}
        cve_id = ''
        alias = ''
        cve_description = ''
        impact = []
        reference = []
        impact_system = []
        status = ''
        return cve_info, cve_id, alias, cve_description, impact, reference, impact_system, status


if __name__ == '__main__':
    # 获取当前时间
    start_time = time.time()
    # 连接 MongoDB 数据库
    client = MongoClient('localhost', 27017)
    # 获取指定数据库和集合
    db = client['306Project']
    collection = db['dsa']

    # 每个源数据预处理后存入总数据表，总数据表名称
    system = db['system']  # 先把总数据表中对应数据源所有数据删除

    obj = Debian('dsa',collection,'dsaID',system)
    obj.run()

    '''
    debian有cve列表，如需要，运行下面脚本，并记得修改run中脚本
    '''
    # # 连接 MongoDB 数据库
    # client = MongoClient('localhost', 27017)
    # # 获取指定数据库和集合
    # db = client['306Project']
    # collection = db['debianCVE']
    # obj = Debian('debianCVE', collection, 'cve_id')
    # obj.run()

    client.close()
    # 获取程序结束时间
    end_time = time.time()
    # 计算程序耗时
    duration = end_time - start_time
    # 打印程序耗时
    print(f"程序耗时：{duration} 秒")