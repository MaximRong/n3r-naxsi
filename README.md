n3r-naxsi
================

Naxsi 是什么?
-----------------

  Naxsi 是一种专业的网络防火墙，主要用于防止XSS攻击和SQL注入等一系列网络攻击。
  Naxsi的github地址. [https://github.com/nbs-system/naxsi](https://github.com/nbs-system/naxsi)


使用Naxsi官方提供的nx_util.py生成白名单脚本?
------------------------------------------------
<pre>
  python nx_util.py -l error.log -o -c /Users/bingoohuang/Downloads/naxsi-0.52/nx_util/nx_util.conf -p 1
</pre>

解决脚本输出中文乱码问题
----------------------------

<b>nx_util.py</b>
<pre>
  #1 在页面头引入import codecs #用于提供特殊的codecs.BOM_UTF8
  
  #2 在122行将print r 替换成 print r.replace(codecs.BOM_UTF8, '').decode('utf-8')
  #第一个replace试将某些特殊字符(比如IDE或者UE生成的占位字符替换) decode是为了用中文输出
</pre>


```python
#!/usr/bin/env python

from optparse import OptionParser
import os
from nx_lib.nx_imports import NxReader, NxInject 
from nx_lib.SQLWrapper import SQLWrapper, SQLWrapperException
from nx_lib.nx_whitelists import NxWhitelistExtractor
from nx_lib.nx_report import NxReportGen
from nx_lib.nx_tools import NxConfig
import sys
import logging
# 头文件引用
import codecs


	if options.output_whitelist is not False:
		wl = NxWhitelistExtractor(sql, config.core_rules, pages_hit=options.wl_plimit, rules_hit=options.wl_rlimit)
		wl.gen_basic_rules()
		base_rules, opti_rules = wl.opti_rules_back()
		opti_rules.sort(lambda a,b: (b['hratio']+(b['pratio']*3)) < (a['hratio']+(a['pratio']*3)))
		r = wl.format_rules_output(wl.final_rules)
	# 增加去掉特殊字符以及转码的decode
        print r.replace(codecs.BOM_UTF8, '').decode('utf-8')
	if options.dst_file is not None:
		logging.info("Outputing HTML report to ["+options.dst_file+"]")
		report = NxReportGen(options.dst_file, config.data_dir, sql)
		report.write()
		logging.info("Finished HTML report generation")
```

<b>nx_imports.py</b>
<pre>
  #1 在页面头引入 import os  和 from urllib import unquote
  # 用于输出和解析url
  
  #2 在486行(line = line.rstrip('\n'))后增加 line = unquote(line).decode('utf-8')
  # 用于解析log文件后转码
  
  #注意： python特殊注重缩进格式，有些报错很可能是空格和tab使用不规范造成的/
</pre>

```python
import urlparse
import string
import itertools
import datetime
import time
import pprint
import gzip
import bz2
import glob
import logging
import sys
from select import select
import re
import os
# 头文件引入
from urllib import unquote


# returns an array of [success, discarded, bad_line] events counters
def acquire_nxline(self, line, date_format='%Y/%m/%d %H:%M:%S',
	       sod_marker=[' [error] ', ' [debug] '], eod_marker=[', client: ', '']):
success = 0
discard = 0
bad_line = 0

line = line.rstrip('\n')
# 此处增加转码
line = unquote(line).decode('utf-8')
for mark in sod_marker:
    date_end = line.find(mark)
    if date_end != -1:
	break
for mark in eod_marker:
    if mark == '':
	data_end = len(line)
	break
    data_end = line.find(mark)
    if data_end != -1:
	break
if date_end == -1 or data_end == 1:
    bad_line += 1
    return [success, discard, bad_line, self.fragmented_lines, self.reunited_lines]
date = self.date_unify(line[:date_end])
chunk = line[date_end:data_end]
```

AOP平台试运行Naxsi的白名单和对应说明 :
-----------------------------------------


<b>规则 1015 (,) 逗号规则: </b>
<pre>
# total_count:1 (50.0%), peer_count:1 (100.0%) | , in stuff ","逗号规则，仅仅针对url为/aop/aopservlet并且post请求参数为msg
BasicRule wl:1015 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";
# total_count:305 (38.03%), peer_count:15 (88.24%) | , in stuff ","逗号规则，仅仅针对url为/aop/aopservlet并且get请求参数为msg
BasicRule wl:1015 "mz:$URL:/aop/aopservlet|$ARGS_VAR:msg";
# 最近一次统计发现有超过参数为msg的url中含有逗号
BasicRule wl:1015 "mz:$URL:/aop/aopservlet|ARGS";

#exemple (from exlog) : '{appkey:mall.sub,apptx:131106000001238410,method:ecaop.trades.query.comm.snres.chg,msg:{"channelId":"34a2030",
"channelType":"1030100","city":"340","district":"340336","operatorId":"A0005626","province":"34","resourcesInfo":[{"acceptChannelTag":"
1","certNum":"21312312312312","certType":"08","contactNum":"","custName":"","developPersonTag":"0","keyChangeTag":"0","occupiedFlag":"3
","occupiedTime":"20591231235959","oldKey":"3912032203318256","oldResourcesCode":"18651844616","preOrderTag":"1","proKey":"391203220331
8256","proKeyMode":"1","recomPersonId":"A0005626","remark":"","resourcesCode":"18651880194","resourcesType":"02","snChangeTag":"1"}]},t
imestamp:2013-11-06'
</pre>

<b>规则 1001 (") 双引号规则: </b>
<pre>
# total_count:1 (50.0%), peer_count:1 (100.0%) | double quote """ 引号规则，仅仅针对url为/aop/aopservlet并且post请求参数为msg
BasicRule wl:1001 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";
# total_count:1 (0.12%), peer_count:1 (5.88%) | double quote """ 引号规则，仅仅针对url为/aop/aopservlet并且get请求参数为apptx
BasicRule wl:1001 "mz:$URL:/aop/aopservlet|$ARGS_VAR:apptx";
# total_count:305 (38.03%), peer_count:15 (88.24%) | double quote """ 引号规则，仅仅针对url为/aop/aopservlet并且get请求参数为msg
BasicRule wl:1001 "mz:$URL:/aop/aopservlet|$ARGS_VAR:msg";
# 最近一次统计发现有超过参数为msg的url中含有引号
BasicRule wl:1001 "mz:$URL:/aop/aopservlet|ARGS";

#exemple (from exlog) : '{appkey:mall.sub,apptx:131106000001238410,method:ecaop.trades.query.comm.snres.chg,msg:{"channelId":"34a2030",
"channelType":"1030100","city":"340","district":"340336","operatorId":"A0005626","province":"34","resourcesInfo":[{"acceptChannelTag":"
1","certNum":"21312312312312","certType":"08","contactNum":"","custName":"","developPersonTag":"0","keyChangeTag":"0","occupiedFlag":"3
","occupiedTime":"20591231235959","oldKey":"3912032203318256","oldResourcesCode":"18651844616","preOrderTag":"1","proKey":"391203220331
8256","proKeyMode":"1","recomPersonId":"A0005626","remark":"","resourcesCode":"18651880194","resourcesType":"02","snChangeTag":"1"}]},t
imestamp:2013-11-06'
</pre>

<b>规则 1005 (|) 管道符规则: </b>
<pre>
# total_count:45 (5.61%), peer_count:10 (58.82%) | mysql keyword (|) 管道符规则，仅仅针对url为/aop/aopservlet并且get请求参数为msg
BasicRule wl:1005 "mz:$URL:/aop/aopservlet|$ARGS_VAR:msg";
# total_count:40 (4.99%), peer_count:1 (5.88%) | mysql keyword (|) 管道符规则，仅仅针对url为/aop/aopservlet并且post请求参数为msg
BasicRule wl:1005 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";
</pre>

<b>规则 1009 (=) 等号规则: </b>
<pre>
# total_count:40 (4.99%), peer_count:1 (5.88%) | equal in var, probable sql/xss "=" 等号规则，仅仅针对url为/aop/aopservlet并且post请求参数为sign
BasicRule wl:1009 "mz:$URL:/aop/aopservlet|$BODY_VAR:sign";
# total_count:2 (0.25%), peer_count:2 (11.76%) | equal in var, probable sql/xss "=" 等号规则，仅仅针对url为/aop/aopservlet并且get请求参数为msg
BasicRule wl:1009 "mz:$URL:/aop/aopservlet|$ARGS_VAR:msg";
# total_count:7 (3.47%), peer_count:2 (66.67%) | equal in var, probable sql/xss
BasicRule wl:1009 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";

#exemple (from exlog) : 'gSZd8eWsqAh/CENgrdGTaw=='

#exemple (from exlog) : '{"channelId":"11a0267","channelType":"1010300","city":"110","district":"11a01s","operatorId":"chengjy10","prov
ince":"11","resourcesInfo":[{"acceptChannelTag":"1","certNum":"QTY9E32jGaU1ye4zKeuOyA==","certType":"04","contactNum":"15277655544","cu
stName":"测试","developPersonTag":"0","keyChangeTag":"0","occupiedFlag":"2","occupiedTime":"20131107230000","preOrderTag":"1","proKey":
"1213041703423756","proKeyMode":"1","recomPersonId":"chengjy10","remark":"","resourcesCode":"15652221543","resourcesType":"02","snChang
eTag":"0"}]}'

#exemple (from exlog) : '{"certNum":"wXUMEHP/94PFKEuk46nJ7g==","certType":"09","checkType":"0","city":"340","operatorId":"A0000LY0","pr
ovince":"34","serType":"1"}'
</pre>



<b>规则 1402 导航规则: </b>
<pre>
# total_count:60 (7.48%), peer_count:3 (17.65%) | Content is neither mulipart/x-www-form.. 导航规则，内容不是mulipart/x-www-form
BasicRule wl:1402 "mz:$URL:/aop/aopservlet|$HEADERS_VAR:content-type";

#exemple (from exlog) : 'text/plain'
</pre>


<b>规则 1100 含有字符串http://: </b>
<pre>
# total_count:2 (0.25%), peer_count:2 (11.76%) | http:// scheme "http://" 含有字符串http://， 仅仅针对url为/aop/aopservlet并且get请求参数为msg
BasicRule wl:1100 "mz:$URL:/aop/aopservlet|$ARGS_VAR:msg";
</pre>


<b>规则 1311 含有字符串"]": </b>
<pre>
# total_count:12 (1.36%), peer_count:2 (9.52%) | ], possible js 含有字符串"]",  仅仅针对url为/aop/aopservlet并且get请求参数为msg
BasicRule wl:1311 "mz:$URL:/aop/aopservlet|$ARGS_VAR:msg";
# total_count:1 (0.12%), peer_count:1 (5.88%) | ], possible js ] 含有字符串"]",  仅仅针对url为/aop/aopservlet并且post请求参数为msg
BasicRule wl:1311 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";
# total_count:1 (0.12%), peer_count:1 (5.88%) | ], possible js ] 含有字符串"]",  针对所有参数
BasicRule wl:1311 "mz:$URL:/aop/aopservlet|ARGS";

#exemple (from exlog) : '{"channelId":"34a0513","channelType":"1010300","city":"340","operatorId":"A0000LY0","province":"34","resources
Info":[{"contactNum":"","custName":"","keyChangeTag":"0","occupiedFlag":"1","occupiedTime":"20131112182431","proKey":"2412070903325466"
,"proKeyMode":"1","remark":"","resourcesCode":"18610035192","resourcesType":"02","snChangeTag":"0"}]}'

#exemple (from exlog) : '{appkey:mall.sub,apptx:131106000001238410,method:ecaop.trades.query.comm.snres.chg,msg:{"channelId":"34a2030",
"channelType":"1030100","city":"340","district":"340336","operatorId":"A0005626","province":"34","resourcesInfo":[{"acceptChannelTag":"
1","certNum":"21312312312312","certType":"08","contactNum":"","custName":"","developPersonTag":"0","keyChangeTag":"0","occupiedFlag":"3
","occupiedTime":"20591231235959","oldKey":"3912032203318256","oldResourcesCode":"18651844616","preOrderTag":"1","proKey":"391203220331
8256","proKeyMode":"1","recomPersonId":"A0005626","remark":"","resourcesCode":"18651880194","resourcesType":"02","snChangeTag":"1"}]},t
imestamp:2013-11-06'
</pre>


<b>规则 1310 含有字符串"[": </b>
<pre>
# total_count:12 (1.36%), peer_count:2 (9.52%) | [, possible js 含有字符串"[",  仅仅针对url为/aop/aopservlet并且get请求参数为msg
BasicRule wl:1310 "mz:$URL:/aop/aopservlet|$ARGS_VAR:msg";
# total_count:1 (0.12%), peer_count:1 (5.88%) | [, possible js 含有字符串"[",  仅仅针对url为/aop/aopservlet并且post请求参数为msg
BasicRule wl:1310 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";
# total_count:2 (0.21%), peer_count:1 (20.0%) | [, possible js
BasicRule wl:1310 "mz:$URL:/aop/aopservlet|ARGS";

#exemple (from exlog) : '{appkey:mall.sub,apptx:131106000001238410,method:ecaop.trades.query.comm.snres.chg,msg:{"channelId":"34a2030",
"channelType":"1030100","city":"340","district":"340336","operatorId":"A0005626","province":"34","resourcesInfo":[{"acceptChannelTag":"
1","certNum":"21312312312312","certType":"08","contactNum":"","custName":"","developPersonTag":"0","keyChangeTag":"0","occupiedFlag":"3
","occupiedTime":"20591231235959","oldKey":"3912032203318256","oldResourcesCode":"18651844616","preOrderTag":"1","proKey":"391203220331
8256","proKeyMode":"1","recomPersonId":"A0005626","remark":"","resourcesCode":"18651880194","resourcesType":"02","snChangeTag":"1"}]},t
imestamp:2013-11-06'
</pre>


<b>规则 1016 (#) 井号规则: </b>
<pre>
# total_count:4 (0.45%), peer_count:2 (9.52%) | mysql comment (#) 井号规则，仅仅针对url为/aop/aopservlet并且post请求参数为msg
BasicRule wl:1016 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";
</pre>

<b>规则 1008 (#) 井号规则: </b>
<pre>
# total_count:1 (100.0%), peer_count:1 (100.0%) | ; in stuf 分号规则，仅仅针对url为/aop/aopservlet并且post请求参数为msg
BasicRule wl:1008 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";
</pre>



<b>规则 1315 rx:%[2|3].规则 (double encoding): </b>
<pre>
BasicRule wl:1315 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";
</pre>

<b>规则 1002 (0x) 0x规则: </b>
<pre>
BasicRule wl:1002 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";

#exemple (from exlog) : '{"certNum":"dR0xnyhFTU8OqYBC5JwdoQ==","certType":"04","checkType":"0","city":"340","operatorId":"A0000LY0","pr
ovince":"34","serType":"1"}'
</pre>


<b>规则 1010 (() 左括号规则: </b>
<pre>
# total_count:32 (3.29%), peer_count:1 (20.0%) | parenthesis, probable sql/xss
BasicRule wl:1010 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";

#exemple (from exlog) : '{"accessMode":"","accessType":"01","addressCode":"182746274","areaCode":"025","channelId":"34a0513","channelTy
pe":"1010300","city":"340","exchCode":"180008295","installAddress":"南京市高淳区淳溪镇淳南路109号玲珑湾小区(共享)(KDXQ)3栋3单元","opera
torId":"A0000LY0","productCode":["34000021"],"province":"34","queryMode":"0","serviceCode":"138","speedLevel":"4"}'
</pre>

<b>规则 1011 ()) 右括号规则: </b>
<pre>
BasicRule wl:1011 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";

#exemple (from exlog) : '{"accessMode":"","accessType":"01","addressCode":"182746274","areaCode":"025","channelId":"34a0513","channelTy
pe":"1010300","city":"340","exchCode":"180008295","installAddress":"南京市高淳区淳溪镇淳南路109号玲珑湾小区(共享)(KDXQ)3栋3单元","opera
torId":"A0000LY0","productCode":["34000021"],"province":"34","queryMode":"0","serviceCode":"138","speedLevel":"4"}'
</pre>

<b>规则 1205 (\\) 双斜杠规则: </b>
<pre>
# total_count:20 (2.06%), peer_count:1 (20.0%) | backslash
BasicRule wl:1205 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";

#exemple (from exlog) : '{"userInfo":[{"serType":"2","payInfo":{"payType":"10"},"userType":"1","bipType":"1","is3G":"1","packageTag":"0
","firstMonBillMode":"01","userPwd":"900046","product":[{"productId":"99104722","productMode":"1"}],"activityInfo":[{"actPlanId":"20120
412112233000006"}]}],"operatorId":"Y32837","province":"31","city":"310","district":"312524","channelId":"31a0130","channelType":"101030
0","ordersId":"000011000","numId":[{"serialNumber":"18601623097","proKey":"EAOP"}],"customerInfo":[{"authTag":"0","realNameType":"0","c
ustType":"0","newCustomerInfo":[{"custType":"01","certType":"04","certNum":"1234345654","certAdress":"上海市徐汇区钦江路333号","custome
rName":"留着","certExpireDate":"20151030","contactPerson":"留着","contactPhone":"24545667768\t","contactAddress":"上海"}]}],"acctInfo":
[{"createOrExtendsAcct":"0","accountPayType":"10"}],"recomPersonId":"3101568013","recomPersonName":"wewerwer1234234"} '
</pre>
  
  
