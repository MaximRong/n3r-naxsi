n3r-naxsi
================

Naxsi 是什么?
-----------------

  Naxsi 是一种专业的网络防火墙，主要用于防止XSS攻击和SQL注入等一系列网络攻击。
  Naxsi的github地址. [https://github.com/nbs-system/naxsi](https://github.com/nbs-system/naxsi)


AOP平台试运行Naxsi的白名单和对应说明 :
-----------------------------------------
<pre>
#### Optimized Rules Suggestion ####
# total_count:1 (50.0%), peer_count:1 (100.0%) | , in stuff ","逗号规则，仅仅针对url为/aop/aopservlet并且post请求参数为msg
BasicRule wl:1015 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";
# total_count:305 (38.03%), peer_count:15 (88.24%) | , in stuff ","逗号规则，仅仅针对url为/aop/aopservlet并且get请求参数为msg
BasicRule wl:1015 "mz:$URL:/aop/aopservlet|$ARGS_VAR:msg";

# total_count:1 (50.0%), peer_count:1 (100.0%) | double quote """ 引号规则，仅仅针对url为/aop/aopservlet并且post请求参数为msg
BasicRule wl:1001 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";
# total_count:1 (0.12%), peer_count:1 (5.88%) | double quote """ 引号规则，仅仅针对url为/aop/aopservlet并且get请求参数为apptx
BasicRule wl:1001 "mz:$URL:/aop/aopservlet|$ARGS_VAR:apptx";
# total_count:305 (38.03%), peer_count:15 (88.24%) | double quote """ 引号规则，仅仅针对url为/aop/aopservlet并且get请求参数为msg
BasicRule wl:1001 "mz:$URL:/aop/aopservlet|$ARGS_VAR:msg";


# total_count:45 (5.61%), peer_count:10 (58.82%) | mysql keyword (|) 管道符规则，仅仅针对url为/aop/aopservlet并且get请求参数为msg
BasicRule wl:1005 "mz:$URL:/aop/aopservlet|$ARGS_VAR:msg";
# total_count:40 (4.99%), peer_count:1 (5.88%) | mysql keyword (|) 管道符规则，仅仅针对url为/aop/aopservlet并且post请求参数为msg
BasicRule wl:1005 "mz:$URL:/aop/aopservlet|$BODY_VAR:msg";


# total_count:40 (4.99%), peer_count:1 (5.88%) | equal in var, probable sql/xss "=" 等号规则，仅仅针对url为/aop/aopservlet并且post请求参数为sign
#BasicRule wl:1009 "mz:$URL:/aop/aopservlet|$BODY_VAR:sign";
# total_count:2 (0.25%), peer_count:2 (11.76%) | equal in var, probable sql/xss "=" 等号规则，仅仅针对url为/aop/aopservlet并且get请求参数为msg
#BasicRule wl:1009 "mz:$URL:/aop/aopservlet|$ARGS_VAR:msg";

# total_count:60 (7.48%), peer_count:3 (17.65%) | Content is neither mulipart/x-www-form.. 导航规则，内容不是mulipart/x-www-form
#BasicRule wl:1402 "mz:$URL:/aop/aopservlet|$HEADERS_VAR:content-type";

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
</pre>
  
  
