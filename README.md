由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责。
# 环境要求：
Python 3.8版本以上  
执行下述命令安装环境  
```bash
pip install requests  
pip install python_whois  
pip install python_nmap  
pip install tqdm  
```
最新库即可  

# 使用说明：
## 执行功能  
1. 获得目标域名基本信息  
```bash
shouji.py -u [目标域名]  
shouji.py -u [目标IP]
```
2. 对目标域名（IP）进行端口扫描  
```bash
shouji.py -u [目标域名] -p  
```
3. 对多个目标域名实现批量扫描  
```bash
shouji.py -r [包含域名的文本]（要在源码目录下）  
```
4. 目标是否使用CDN加速服务判断  
```bash
shouji.py -u [目标域名] -n  
```
5. 对目标域名进行目录扫描  
```bash
 shouji.py -u [目标域名] -d  
 ```
6. 对目标域名进行子域名扫描  
```bash
shouji.py -u [目标域名] -s  
```
7. 对目标域名进行全功能使用  
```bash
shouji.py -u [目标域名] -a  
```
8. 将信息收集工具收集到的信息导出到日志  
```bash
shouji.py -u [目标域名] -o 123.log  
```
