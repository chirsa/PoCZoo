from pymongo import MongoClient
import json
import os
import re

# 连接到 MongoDB 服务器
client = MongoClient('localhost', 27017)

# 选择源数据库
source_db = client['20250317']

# 获取数据库中所有集合名称
collections = source_db.list_collection_names()

# 创建一个用于存放导出 JSON 文件的目录（如果不存在的话）
export_dir = 'exported_docs'
os.makedirs(export_dir, exist_ok=True)

# 定义包含多种 “poc” 写法的正则表达式，并指定不区分大小写的标志
poc_patterns = re.compile(r'\b(?:Proof of Concept|POC|Proof-of-Concept|ProofConcept|poc|proof of concept|proof-of-concept|proofconcept)\b', re.IGNORECASE)

# 定义包含 cve 列表中任意一个 cve 的正则表达式，并指定不区分大小写的标志
cve_list = [
    'CVE-2020-13537', 'CVE-2021-0229', 'CVE-2021-0256', 'CVE-2021-28166',
    'CVE-2021-28825', 'CVE-2021-28826', 'CVE-2021-34431', 'CVE-2021-34432',
    'CVE-2021-34434', 'CVE-2021-41039', 'CVE-2023-0809', 'CVE-2023-28366',
    'CVE-2023-3592', 'CVE-2023-5632', 'CVE-2024-8376', 'CVE-2024-10525',
    'CVE-2024-3935'
]
cve_patterns = re.compile(r'\b(?:' + '|'.join(cve_list) + r')\b', re.IGNORECASE)

# 递归查找文档中的字符串字段是否包含特定关键字
def recursive_search(doc, keyword_pattern):
    if isinstance(doc, dict):
        for key, value in doc.items():
            if recursive_search(value, keyword_pattern):
                return True
    elif isinstance(doc, list):
        for item in doc:
            if recursive_search(item, keyword_pattern):
                return True
    elif isinstance(doc, str):
        # 使用预编译的正则表达式进行匹配
        if keyword_pattern.search(doc):
            return True
    return False

# 遍历每个集合
for collection_name in collections:
    collection = source_db[collection_name]
    
    # 初始化一个列表，用于存储符合条件的文档
    matching_docs = []
    
    # 遍历集合中的每个文档
    for doc in collection.find():
        # 检查文档是否同时包含 cve列表中任意一个 cve 和 “poc” 相关的关键字
        has_cve = recursive_search(doc, cve_patterns)
        has_poc = recursive_search(doc, poc_patterns)
        
        if has_cve and has_poc:
            # 将 ObjectId 转换为字符串，因为 JSON 不支持 ObjectId
            doc['_id'] = str(doc['_id'])
            matching_docs.append(doc)
    
    # 将符合条件的文档导出到 JSON 文件
    if matching_docs:
        export_file_path = os.path.join(export_dir, f'{collection_name}.json')
        with open(export_file_path, 'w', encoding='utf-8') as f:
            json.dump(matching_docs, f, ensure_ascii=False, indent=4)
        print(f"Exported {len(matching_docs)} documents from collection '{collection_name}' to {export_file_path}")
    else:
        print(f"No documents found in collection '{collection_name}' matching the criteria")

print("Export process completed.")