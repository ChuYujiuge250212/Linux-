# Linux-
全面的Linux系统安全检查脚本，脚本将检查所有安全方面并将结果保存到文本文件中，不会对系统进行任何修改。
使用方法：
将脚本保存为linux_security_check.sh
赋予执行权限：chmod +x linux_security_check.sh
运行脚本：./linux_security_check.sh
查看生成的报告文件
详细如下：
包括：
1、系统基本信息收集
2、资源使用情况分析
3、系统用户情况评估
4、身份鉴别安全检查
5、访问控制安全分析
6、安全审计功能检查
7、剩余信息保护措施
8、入侵防范安全机制
9、恶意代码防范措施
10、资源控制安全检查
11、内核安全机制检查
12、数据备份与恢复机制
13、网络安全配置检查
14、安全基线符合性检查（CIS、DISA STIG）
15、漏洞扫描工具和关键软件版本检查
16、安全配置管理和变更监控机制
17、系统安全检查总结
只进行检查并记录到文本文件中，不对系统进行任何修改
输出结果保存在带有时间戳的文件中：/tmp/linux_security_check_日期_时间.txt
结构化的报告格式，便于阅读和分析
对于需要root权限的检查，脚本会说明权限要求而不会失败
详细记录了各种安全配置和潜在的安全风险
