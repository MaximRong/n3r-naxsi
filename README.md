n3r-naxsi
================

Naxsi 是什么?
-----------------

  Naxsi 是一种专业的网络防火墙，主要用于防止XSS攻击和SQL注入等一系列网络攻击。
  Naxsi的github地址. [https://github.com/nbs-system/naxsi](https://github.com/nbs-system/naxsi)


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
<pre>

<b>规则 1009 (=) 等号规则: </b>
<pre>
# total_count:40 (4.99%), peer_count:1 (5.88%) | equal in var, probable sql/xss "=" 等号规则，仅仅针对url为/aop/aopservlet并且post请求参数为sign
#BasicRule wl:1009 "mz:$URL:/aop/aopservlet|$BODY_VAR:sign";
# total_count:2 (0.25%), peer_count:2 (11.76%) | equal in var, probable sql/xss "=" 等号规则，仅仅针对url为/aop/aopservlet并且get请求参数为msg
#BasicRule wl:1009 "mz:$URL:/aop/aopservlet|$ARGS_VAR:msg";

#exemple (from exlog) : 'gSZd8eWsqAh/CENgrdGTaw=='

#exemple (from exlog) : '{"channelId":"11a0267","channelType":"1010300","city":"110","district":"11a01s","operatorId":"chengjy10","prov
ince":"11","resourcesInfo":[{"acceptChannelTag":"1","certNum":"QTY9E32jGaU1ye4zKeuOyA==","certType":"04","contactNum":"15277655544","cu
stName":"测试","developPersonTag":"0","keyChangeTag":"0","occupiedFlag":"2","occupiedTime":"20131107230000","preOrderTag":"1","proKey":
"1213041703423756","proKeyMode":"1","recomPersonId":"chengjy10","remark":"","resourcesCode":"15652221543","resourcesType":"02","snChang
eTag":"0"}]}'
</pre>



<b>规则 1402 导航规则: </b>
<pre>
# total_count:60 (7.48%), peer_count:3 (17.65%) | Content is neither mulipart/x-www-form.. 导航规则，内容不是mulipart/x-www-form
#BasicRule wl:1402 "mz:$URL:/aop/aopservlet|$HEADERS_VAR:content-type";

#exemple (from exlog) : 'text/plain'
</pre>


<b>规则 1100 含有字符串http://: </b>
<pre>
# total_count:2 (0.25%), peer_count:2 (11.76%) | http:// scheme "http://" 含有字符串http://， 仅仅针对url为/aop/aopservlet并且get请求参数为msg
#BasicRule wl:1100 "mz:$URL:/aop/aopservlet|$ARGS_VAR:msg";






# total_count:12 (1.36%), peer_count:2 (9.52%) | ], possible js 含有字符串"]",  仅仅针对url为/aop/aopservlet并且get请求参数为msg
#BasicRule wl:1311 "mz:$URL:/aop/aopservlet|$ARGS_VAR:msg";
# total_count:1 (0.12%), peer_count:1 (5.88%) | ], possible js ] 含有字符串"]",  仅仅针对url为/aop/aopservlet并且post请求参数为msg
#BasicRule wl:1311 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";

# total_count:12 (1.36%), peer_count:2 (9.52%) | [, possible js 含有字符串"[",  仅仅针对url为/aop/aopservlet并且get请求参数为msg
BasicRule wl:1310 "mz:$URL:/aop/aopservlet|$ARGS_VAR:msg";
# total_count:1 (0.12%), peer_count:1 (5.88%) | [, possible js 含有字符串"[",  仅仅针对url为/aop/aopservlet并且post请求参数为msg
BasicRule wl:1310 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";

# total_count:4 (0.45%), peer_count:2 (9.52%) | mysql comment (#) 井号规则，仅仅针对url为/aop/aopservlet并且post请求参数为msg
BasicRule wl:1016 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";
# total_count:1 (100.0%), peer_count:1 (100.0%) | ; in stuf 分号规则，仅仅针对url为/aop/aopservlet并且post请求参数为msg
BasicRule wl:1008 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";

BasicRule wl:1011 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";
BasicRule wl:1315 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";
BasicRule wl:1002 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";

# total_count:32 (3.29%), peer_count:1 (20.0%) | parenthesis, probable sql/xss
BasicRule wl:1010 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";

# total_count:20 (2.06%), peer_count:1 (20.0%) | backslash
BasicRule wl:1205 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";

# total_count:2 (0.21%), peer_count:1 (20.0%) | , in stuff
BasicRule wl:1310 "mz:$URL:/aop/aopservlet|ARGS";

# total_count:2 (0.21%), peer_count:1 (20.0%) | double quote
BasicRule wl:1001 "mz:$URL:/aop/aopservlet|ARGS";
  
  
