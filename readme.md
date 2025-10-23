## 这是个关于该代码库的详细说明文档

### 目录结构

```
.
├── .venv
├── 备用代码
├── 文档
├── logs
├── reports
├── src
│   ├── 问题代码
│   ├── crawl
│   │   ├── crawl_XXX.py
│   │   ├── crawl_XXX.py
│   ├── dataProceScript
│   ├── refe_file
└── .gitignore
├── config.ini
├── requirements.txt
├── run.sh
└── test.py
```

#### 详细解释

* `.venv`：虚拟环境目录，用于隔离项目依赖，防止不同项目之间造成干扰。激活虚拟环境方式：`source.venv/bin/activate`。注意在`.venv/lib/python3.12/site-packages/local.pth`中添加项目绝对路径，例如：`/home/ymy/306_crawl`

* `备用代码`：一些爬虫有多个代码，不确定哪个代码能用时，放置该文件夹备用，或者要对代码进行修改，可以先复制一份备份。注意写好备用说明。

* `文档`：该文件夹存放一些说明文档，每次对代码进行更新都应该在说明文档中详细说明。

* `logs`：该文件夹存放爬虫运行日志，方便追踪爬虫运行情况。`.txt`是每次运行控制台的输出，`.log`是爬虫的日志。

* `reports`：该文件夹存放每次爬虫运行报告。

* `src`：该文件夹存放爬虫代码。其中问题代码是确认有问题，需要修改的代码，crawl文件夹存放可以运行的爬虫代码，`dataProceScript`文件夹存放数据处理脚本，`refe_file`文件夹存放一些爬虫代码依赖的文件。

* `.gitignore`：该文件用于配置Git忽略哪些文件。

* `config.ini`：该文件用于配置爬虫参数，主要是要运行的爬虫代码名称，后期会把数据对齐的配置参数也放在这里。

* `requirements.txt`：该文件用于配置项目依赖，部署时运行`pip install -r requirements.txt`即可安装依赖。

* `run.sh`时爬虫运行脚本，运行前注意配置`config.ini`

* `test.py`测试demo。

### 运行方式

#### 1. clone项目

http:

```
https://gitee.com/ymymymymy/306_crawl.git
```

ssh:
注意ssh需要把公钥传到gitee上

```
git@gitee.com:ymymymymy/306_crawl.git
```

#### 2. 安装依赖

最好在虚拟环境中安装依赖，防止不同项目之间造成干扰。

```
pip install -r requirements.txt
```

在电脑中安装mongdb，推荐在vscode安装mongdb的官方插件，连接方式：`localhost:27017`

#### 3. 配置config.ini

目前config.ini只配置了爬虫类名，例如：

```
[SpiderClasses]
zeroscience=zeroscience
CNVD=CNVD
wpscan=wpscan
```

#### 4. 运行爬虫

平时开发和调试代码时，运行爬虫脚本`run.sh`即可，也可运行`run_all_mutithread`脚本。区别是前者把控制台输出重定向到了日志文件中方便查看。也可以在特定爬虫代码中运行和调试，但需要在代码中自己写类的调用，并填入相应参数，不推荐。

注意：由于部分代码逻辑是把数据存贮到json文件中，再存入数据库，而运行脚本每次运行后都会把存放在json文件中的数据清空，防止数据丢失，==不要同时运行多个`run.sh`==。存储文件的路径为：`306_crawl/../306data`,即和`306_crawl`同级目录下的`306data`文件夹。

```
./run.sh
```

#### 5. 运行报告

XXX_log.txt是控制台输出，XXX.log是爬虫日志，XXX.csv是爬虫的最终结果。如果爬虫失败，可以根据类名去爬虫日志和.txt中查看。

### 数据处理脚本说明

该文件夹存放数据处理脚本，主要是对爬虫爬取的数据进行格式换成，导入导出操作

#### data_format_trans.py

该脚本用于把目标数据库中的所有集合通过转换格式表`data_format.xlsx`把数据转换成探寻所给的数据格式。
关键参数：

* `old_collection = connect_mongodb('XXXX', header)`：XXXX替换成被转换的数据库名称

* `data_path = f"{PRO_PATH}/refe_file/XXXX.xlsx"`：数据转换表的文件路径

* `create_db_name = current_date.strftime('%Y%m%d')`: 转换后的数据库名称,设成了转换时候的日期

* 运行后在reports文件夹下会生成一个`problem_dict_keys_counter.json`,统计了转换过程中有问题的字段，这些字段可能是因为格式转换表中写错了格式，例如：`containers*adp*0*title`写成了`containers*adp*title`，或者有错字。也可能是因为在对应集合中，这些字段只存在于一部分`document`
  后续需要把这些关键参数放置在ini配置文件中，方便配置。此外还需修改`header`参数，在ini中配置该参数使得脚本可以指定需要转换的集合,而不是转换格式转换表中所有的集合。

#### dataProce.py

这个脚本是代码重构前爬虫脚本经常需要调用的一些函数，尽量少用里面的函数，如果有多个爬虫需要使用的函数，可以在`spider_base.py`实现。

#### export_data.py

该脚本用于把目标数据库中的所有集合导出到json文件中。
关键参数：

* `client = MongoClient('localhost', 27017)`：连接client

* `target_databases = [name for name in database_names if name.startswith('20250319')]`: 根据条件筛选数据库，这里筛选日期为20250319的数据库

* `export_dir =os.path.join(os.path.dirname(__file__), '..', '..', '..', 'exportdata')`: 存放的数据库位置，这里是存放在和`306_crawl`同级目录下的`exportdata`文件夹

同理，后续需要把这些关键参数放置在ini配置文件中，方便配置。

#### import_data.py

该脚本用于把json文件中的数据导入到目标数据库中。
关键参数：

* `client = MongoClient('mongodb://localhost:27017/')`：连接client

* `db = client['20250319'] `: 目标数据库名称，这里是20250319

* `json_files_directory = "C:/Users/20759/Desktop/data/data`: 存放json文件的目录，脚本会把这个目录下所有的json文件导入到目标数据库中。
  数据库中集合命名代码如下，请按需修改：

```python
# 获取集合名称（去掉文件扩展名）
        collection_name = os.path.splitext(filename)[0]
        # 去掉前缀20250314.
        if collection_name.startswith("20250314."):
            collection_name = collection_name[9:]
        collection = db[collection_name]
```

同理，后续需要把这些关键参数放置在ini配置文件中，方便配置。

#### match_cve_id.py

根据对应的`XXX_cve_id`集合，在爬取的数据库中做匹配，把`cve_id`相匹配并且含有poc信息的文档导入到`XXX_poc`集合中。目前设定是这两个集合都在同一个数据库里，后续要分开放。该脚本还打印匹配到的cve_id次数和匹配到的唯一 CVE ID 数量。并把每个数据集的匹配的唯一`CVE ID`写入`{key}_matched_cves.json`中
关键参数：

* `cve_id_db = client['cve_id']`：存放`XXX_cve_id`和`XXX_poc`集合的数据库名称

* `target_db = client['20250319']`: 被匹配的爬虫数据库名称

* `{key}_matched_cves.json`: 存放每个数据集的匹配的唯一`CVE ID`的文件名

同理，后续需要把这些关键参数放置在ini配置文件中，方便配置

#### run_all_mutithread.py

运行所有爬虫脚本，并使用多线程提高效率。一般调试的时候用，运行时候用`run.sh`脚本。每次爬虫完成后都会删除`DATA_PATH`文件夹防止占用存储，目前该路径是和`306_crawl`同级目录下的`306data`文件夹。
该脚本关键参数都在ini配置文件中。
`run_all.py`脚本是它的备份，代码稳定后可以删除。

#### Setting.py

目前主要任务是提供`CURRENT_TIME`和`DATA_PATH`两个全局变量，方便其他脚本调用。
尽量别用，建议爬虫脚本使用基类`spider_base`的变量，非爬虫脚本可以在ini中配置全局变量。

#### spider_base.py

爬虫基类，目前主要是提供日志服务和更加安全的requests请求。
推荐使用`self.get`和`self.post`方法替代`requests.get`和`requests.post`，增加请求失败重试，自动处理异常，并记录日志。其参数和`requests`相同。也可根据spider_base自定义。注意，`self.get`和`self.post`方法返回：请求成功会返回`response`对象，==请求失败==会返回`None`。注意使用时处理失败的情况！！！
后续有公共方法可以在基类中实现。

### 编写规范

1. 爬虫代码必须有run函数，用于运行爬虫。run函数的编写可参照其他规范爬虫代码。

2. 爬虫代码调试信息尽量用logging模块，而不是print，只记录关键日志，例如异常、错误、警告，以及其他重要信息，例如XX爬虫运行结束，共计爬取XX条数据。

3. 爬虫代码必须继承基类。

4. 所有异常都要处理，否则会中断爬虫，异常最好有日志记录。`self.get`和`self.post`不会抛出异常，但在发生异常时会返回`None`，需要考虑返回值为`None`。

5. 所有更改应该在项目进度文档中详细说明，并在提交时说明。

6. 代码分支冲突：手动合并`git merge origin/master`，将远程`master`分支的更改合并到本地`master`分支。若有冲突，`Git`会提示冲突文件。



