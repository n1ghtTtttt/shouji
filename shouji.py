import argparse
import requests
import socket
import re
import whois
import nmap
import json
import zlib
import random
import string
from tqdm import tqdm
import multiprocessing
import sys


# nmap端口扫描模块
def port_scan(ip_list):
    for ip in ip_list:
        arguments = '-sS -T4 -Pn ' #SYN扫描 级别越高,扫描速度越快 绕过ping扫描
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=ip, arguments=arguments, sudo=True)
        except:
            nm.scan(hosts=ip, arguments=arguments)
        scan_info = nm[ip]
        xx = scan_info["tcp"]
        print("[目标IP:{}]:".format(ip))
        for i in xx.keys():
            print("{} {} {} {}".format(i, xx[i]['state'], xx[i]['name'], xx[i]['version']))


#主机探测
def host_scan(ip_list):
    # 实例化PortScanner对象
    for ip in ip_list:
       arguments = ' -O '
       nm = nmap.PortScanner()
       try:
           # hosts为目标IP地址,argusments为Nmap的扫描参数(-O为进行操作系统探测)
           result = nm.scan(hosts=ip, arguments=arguments, sudo=True)
           # 对结果进行切片，提取操作系统相关的信息
           sys = result["scan"][ip]['osmatch'][0]['name']
           print("操作系统:{}".format(sys))
       except Exception as e:
           print('抱歉，nmap无法扫出目标主机操作系统。')


# 获取ip地址所属位置
def obtain_ip(ip):
    ip_list = []
    for i in ip:
        url = "https://ip.cn/ip/{}.html".format(i)
        res = requests.get(url=url, timeout=20, headers=headers_lib())
        ym = res.text
        site = re.findall('<div id="tab0_address">(.*?)</div>', ym, re.S)[0] #使用re.S：正则表达式会将这个字符串作为一个整体，将“\n”当做一个普通的字符加入到这个字符串中，在整体中进行匹配。
        result = "{}-{}".format(i, site).replace("  ", "-").replace(" ", "-")
        ip_list.append(result)
    return ip_list


# 请求头库
def headers_lib():
    lib = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:57.0) Gecko/20100101 Firefox/57.0",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:57.0) Gecko/20100101 Firefox/57.0",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:57.0) Gecko/20100101 Firefox/57.0",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:58.0) Gecko/20100101 Firefox/58.0",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:57.0) Gecko/20100101 Firefox/57.0",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:25.0) Gecko/20100101 Firefox/25.0",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36 OPR/50.0.2762.58",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0",
           "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; Media Center PC 6.0; InfoPath.2; MS-RTC LM 8",
           "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.62 Safari/537.36",
           "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1464.0 Safari/537.36",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36",
           "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36",
           "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.62 Safari/537.36",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1944.0 Safari/537.36",
           "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36",
           "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36",
           "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36"]
    headers = {
        "User-Agent": random.choice(lib)}
    return headers


# 格式化url
def get_url(url):
    if "https://" in url or "http://" in url:
        url = url.replace("https://", "").replace("http://", "")
    domain = "{}".format(url).split("/")[0]
    return domain


# 获取网页标题
def get_title(url):
    try:
        res = requests.get(url=url, headers=headers_lib(), verify=False, timeout=3)
        res.encoding = res.apparent_encoding #使中文字符成功输出
        ym= res.text
        title = re.findall("<title>(.*?)</title>", ym, re.S)[0]
    except:
        title = "None"
    return title.replace(" ", "").replace("\r", "").replace("\n", "")


# 判断输入是IP还是域名
def ifIP(str):
    try:
        check_ip = re.compile(
            '^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
        if check_ip.match(str):
            return True
        else:
            return False
    except:
        return False


# 获取网站whois等基本信息
def get_info(url):
    domain_url = get_url(url)
    ip = []
    try:
        addrs = socket.getaddrinfo(domain_url, None) #解析IP
        for item in addrs:
            if item[4][0] not in ip:
                ip.append(item[4][0])
        if len(ip) > 1:
            print("[Ip]:{}  目标域名可能使用了CDN加速服务".format(obtain_ip(ip)))

        else:
            print("[Ip]:{}".format(obtain_ip(ip)[0]))
    except Exception as e:
        print("[Ip_Error]:{本工具并未与ip.cn建立连接，请稍后重试}")
    try:
        title = get_title(url)
        print("[目标域名标题]:{}".format(
          title.replace(" ", "").replace("/r", "").replace("/n", "")))
    except Exception as e:
        print("未能打开目标页面")
    if ifIP(domain_url):
        url_d = "https://site.ip138.com/{}/".format(domain_url)
        res = requests.get(url=url_d, headers=headers_lib())
        ym = res.text
        site = re.findall('<span class="date">(.*?)</span><a href="/(.*?)/" target="_blank">(.*?)</a>', ym, re.S)
        if len(site) > 0:
            print("[该IP绑定的域名有]:")
            for a, b, c in site:
                print("{} {}".format(a, b))
    else:
        whois_info = whois.whois(domain_url)
        format_print(whois_info)
    what_web(url)
    return ip

# 获取网站的中间件、服务器等版本信息，接口每日可调用1000次
def what_web(url):
    requests.packages.urllib3.disable_warnings()
    re = requests.get(url, verify=False)
    what_cms_dict = {"url": re.url, "text": re.text, "headers": dict(re.headers)}
    what_cms_dict = json.dumps(what_cms_dict) #把python对象转换成json对象的一个过程，生成的是字符串
    what_cms_dict = what_cms_dict.encode()
    what_cms_dict = zlib.compress(what_cms_dict)
    data = {"info": what_cms_dict}
    res = requests.post("http://whatweb.bugscaner.com/api.go", files=data)
    whatcms = res.json()
    format_print(whatcms)


# 美化输出whatcms内容
def format_print(res_info):
    res_info = dict(res_info)
    for key in res_info.keys():
        try:
            if res_info[key] is not None:
                isList = True if type(res_info[key]) == list else False
                if isList:
                    print("[{}]:{}".format(key, res_info[key]))
                    print()
                else:
                    print("[{}]:{}".format(key, res_info[key]))
                    print()
        except Exception as e:
            print('[Error]:{}'.format(e))


# 多地ping
def n_ping(key):
    print("[N_ping]:")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded; "
    }

    callback_lib = [
        "jQuery111306167052211460833_1630908921895",
        "jQuery111306167052211460833_1630908921896",
        "jQuery111306167052211460833_1630908921897",
        "jQuery111306167052211460833_1630908921898",
        "jQuery111306167052211460833_1630908921899",
    ]

    node = {
        "安徽合肥[移动]": "fc778772-3967-4b70-be93-9045f310e16c",
        "安徽合肥[联通]": "66426ad9-99d9-471f-b55f-c270cc3fc878",
        "浙江扬州[多线]": "4a40427f-502e-4a85-8752-980f2d8bbae1",
        "广东东莞[电信]": "cd4e7631-8427-41b6-8e44-869a70a04b20",
        "山东济南[联通]": "4d7637d7-4950-4b79-9741-c397789bcf05",
        "辽宁大连[电信]": "e1d5b78f-6ba5-485d-a4dd-54dc546b991a",
        "上海[多线]": "a936bb02-6b19-4da5-9c82-e8bb68fcfbea",
        "北京[多线]": "463cd3ff-65cb-4b5a-8c77-555ef43b6612",
        "内蒙古呼和浩特[多线]": "8c0b720b-e1a1-4422-a948-e8d7ec7e4906",
        "山东枣庄[联通]_1": "9e980285-f696-4478-a645-fc1e5a76ed47",
        "山东枣庄[联通]_2": "2573ad6d-082d-479d-bab6-49f24eca4e47",
        "江苏徐州[电信]": "92dad4c3-9bc3-4f71-a0b0-db9376613bb2",
        "辽宁沈阳[多线]": "07f2f1cc-8414-4557-a8c1-27750a732f16",
        "新疆哈密[电信]": "9bc90d67-d208-434d-b680-294ae4288571",
        "云南昆明[电信]": "14ef4fcf-3712-4971-9c24-0d1657751022",
        "中国香港_1": "cdcf3a45-8366-4ab4-ae80-75eb6c1c9fca",
        "中国香港_2": "a0be885d-24ad-487d-bbb0-c94cd02a137d",
        "中国台湾": "483bad95-d9a8-4026-87f4-7a56501bf5fd",
        "韩国CN2": "1f4c5976-8cf3-47e7-be10-aa9270461477",
        "韩国CN联通_1": "dc440a55-1148-480f-90a7-9d1e0269b682",
        "韩国CN联通_2": "6cd2450a-d73d-40c7-96ce-afc20540eeea",
        "美国_1": "737831b4-95e1-445f-a981-c1333faf88bd",
        "美国_2": "e4f8c1ef-2160-47f7-850f-6446ca0680b4",
        "德国": "d9041619-7d90-42ea-9811-2b2fe11cb2b0",
    }
    ip_value = ""
    keys = tqdm(node.keys(), ncols=75)
    keys.set_description("进度条") #使进度条可以交替显示
    for n in keys:
        url = "http://ping.chinaz.com/iframe.ashx?t=ping&callback={}".format(random.choice(callback_lib))
        data = "guid={}&host={}&ishost=0&isipv6=0&encode=g4LFw6M5ZZa9pkSC|tGN8JBHp|lHVl2x&checktype=0".format(
            node[n], key)
        res = requests.post(url=url, headers=headers, data=data)
        r_node = res.text
        node_value = re.findall("\({(.*?)}\)", r_node, re.S)
        if len(node_value[0]) == 14:
            keys.write('{}:The node timed out！'.format(n))
        else:
            keys.write('{}:{}'.format(n, node_value[0]))
            ip_value += node_value[0]
    set_ip = set(re.findall("ip:'(.*?)',", ip_value, re.S))
    if len(set_ip) > 1:
        print("经检测该域名可能使用CDN加速，共发现{}个节点：{}".format(len(set_ip), ",".join(set_ip)))
    else:
        print("经检测该域名未使用CDN加速，仅发现1个节点：{}".format(",".join(set_ip)))


# 存在虚假页面进行目录扫描
def func1(url, key, check_value):
    b = key.strip()
    url = url + b
    try:
        c = requests.get(url=url, timeout=3, headers=headers_lib())
        if c.status_code == 200 and c.content not in check_value[0]:
            return '[url]:' + c.url + '\t200 OK'
    except:
        return


# 不存在虚假页面进行目录扫描
def func2(url, key):
    b = key.strip()
    url = url + b
    try:
        c = requests.get(url=url, timeout=3, headers=headers_lib())
        if c.status_code == 200:
            return '200 OK ' + '\t' + 'URL:' + c.url
    except:
        return


# 随机生成字符串
def genRandomString(slen=10):
    return ''.join(random.sample(string.ascii_letters + string.digits, slen))


# 目录扫描前检测是否存在伪响应页面
def check_res(url):
    check_value = []
    for i in range(3):
        test_url = url + "/" + genRandomString(slen=24)
        res = requests.get(url=test_url, headers=headers_lib())
        if res.status_code == 200: #网页状态码
            html = res.content
            check_value.append(html)   #追加元素
    check_value = list(set(check_value))  #set取消重复元素
    if len(check_value) == 1:
        print('目标域名存在伪响应页面')
        return check_value


# 更新目录扫描进度条
def update_dir(url):
    if url and url not in dir:
        dir.append(url)
        pbar.write(url)
    pbar.update()


# 读取字典
def read_dict(filename):
    with open(filename, 'r') as a:
        dict_lib = a.readlines()
    return dict_lib


# 目录扫描主方法
def dire_scan(url):
    print("[扫描开始]:")
    if url.count("/") == 2:
        url = url + "/"
    if "." in url[url.rfind("/"):]:
        url = url.replace(url[url.rfind("/"):], "")
    url = url.rstrip("/")
    check_value = check_res(url)
    dir_dict = read_dict("dict/fuzz.txt")
    pool_num = multiprocessing.cpu_count()  #查看本机核心数
    pool = multiprocessing.Pool(processes=5 * pool_num)
    global pbar
    pbar = tqdm(total=len(dir_dict), ncols=75)
    pbar.set_description("进度条")
    global dir
    dir = []
    if check_value:
        for key in dir_dict:
            if key[:1] != "/":
                key = "/{}".format(key)
            pool.apply_async(func1, args=(url, key, check_value),
                             callback=update_dir)  # 维持执行的进程总数为processes，当一个进程执行完毕后会添加新的进程进去
    else:
        for key in dir_dict:
            if key[:1] != "/":
                key = "/{}".format(key)
            pool.apply_async(func2, args=(url, key), callback=update_dir)
    pool.close()
    pool.join()

# 检测http头是否缺失
def check_head(url):
    if url[:4] == "http":
        return url
    else:
        head = "https://"
        do_url = head + url
        try:
            res = requests.get(url=url, headers=headers_lib(), verify=False)
            if res.status_code == 200:
                return do_url
            else:
                return "http://" + url
        except:
            return "http://" + url

# 检测子域名是否存在
def check_sub(nitname, url):
    try:
        domain_url = "https://{}.{}".format(nitname, url)
        res1 = requests.get(url=domain_url, headers=headers_lib(), timeout=3)
        if res1.status_code == 200:
            domain_url = "{}.{}".format(nitname, url)
            return domain_url
    except:
        domain_url = None
    try:
        domain_url = "http://{}.{}".format(nitname, url)
        res2 = requests.get(url=domain_url, headers=headers_lib(), timeout=3)
        if res2.status_code == 200:
            domain_url = "{}.{}".format(nitname, url)
            return domain_url
    except:
        domain_url = None
    domain_url = None
    return domain_url


# 格式化输出子域名扫描
def update_sub(domain_url):
    ip = []
    if domain_url:
        try:
            addrs = socket.getaddrinfo(domain_url, None)
            for item in addrs:
                if item[4][0] not in ip:
                    ip.append(item[4][0])
            title = get_title(check_head(domain_url))
            if len(ip) > 1:

                nit.write("{}-{}-{} 目标域名可能使用了CDN加速服务".format(domain_url, title, obtain_ip(ip)))
            else:
                nit.write(
                    "{}-{}-{}".format(domain_url, title, obtain_ip(ip)[0]))
        except Exception as e :
            nit.write("[Sub_Error]:{}".format(e))
    nit.update() #更新字典内的数据


# 子域名扫描主方法
def sub_scan(url):
    print("[子域名爆破]:")
    url = ".".join(get_url(url).split(".")[1:])
    nit_dict = read_dict("dict/subdomain.txt")
    pool_num = multiprocessing.cpu_count()
    pool = multiprocessing.Pool(processes=5 * pool_num)
    global nit
    nit = tqdm(total=len(nit_dict), ncols=75) #total预定的迭代次数  total进度条长度
    nit.set_description("进度条") #设置描述信息
    for nitname in nit_dict:
        nitname = nitname.replace("\n", "")
        pool.apply_async(check_sub, args=(nitname, url), callback=update_sub)  #callback回调函数
    pool.close() #关闭pool，使其不在接受新的（主进程）任务
    pool.join()  #主进程阻塞后，让子进程继续运行完成，子进程运行完后，再把主进程全部关掉。

# 读文件，批量扫描功能模块
def bat_scan(filename):
    with open(filename, "r+", encoding="utf-8") as f:
        url_list = f.readlines()
    return url_list

# 程序功能选择模块
def switch(url, port, nping, dirscan, subscan, fullscan):
    ip = get_info(url)
    if fullscan:
        print('======正在启动端口扫描======')
        port_scan(ip)
        print('======正在启动多地ping======')
        n_ping(url)
        print('======正在启动目录扫描======')
        dire_scan(url)
        print('======正在启动子域名扫描======')
        sub_scan(url)
    if port:
        print('======正在启动端口扫描======')
        port_scan(ip)
        host_scan(ip)
    if nping:
        print('======正在启动多地ping======')
        n_ping(url)
    if dirscan:
        print('======正在启动目录扫描======')
        dire_scan(url)
    if subscan:
        print('======正在启动子域名扫描======')
        sub_scan(url)


# 日志功能
class Logger(object):
    def __init__(self, filename="Default.log"):
        self.terminal = sys.stdout
        self.log = open(filename, "w+")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(
            "{}".format(message))
    def flush(self):
        pass


# 主程序入口
if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings()
    parser = argparse.ArgumentParser(
        description="BugMap (An automatic information collection tool for pre penetration testing)")
    parser.add_argument('-u', '--url', help='Scan target banner')
    parser.add_argument('-r', '--read', help='Batch scan target url')
    parser.add_argument('-p', '--port', help='Scan target port', action='store_true')
    parser.add_argument('-n', '--nping', help='Multi-node ping target', action='store_true')
    parser.add_argument('-d', '--dirscan', help='Scan target directory', action='store_true')
    parser.add_argument('-s', '--subscan', help='Scan target subdomain', action='store_true')
    parser.add_argument('-a', '--fullscan', help='Use all options', action='store_true')
    parser.add_argument('-o', '--outlog', help='Output log')
    args = parser.parse_args()
    url = args.url
    filename = args.read
    nping = args.nping
    port = args.port
    dirscan = args.dirscan
    subscan = args.subscan
    fullscan = args.fullscan
    outlog = args.outlog
    if outlog:
        sys.stdout = Logger(outlog) # 将程序输出的数据标准输出到文件
        print('成功生成日志！！！')
    if filename is not None:
        url_list = bat_scan(filename)
        print("[多个目标]:{}".format(len(url_list)))
        i = 0
        for url in url_list:
            try:
                i += 1
                url = url.replace("\n", "")
                print("[本次扫描目标{}]:{}".format(i, url))
                switch(check_head(url), port, nping, dirscan, subscan, fullscan)
                print()
            except Exception as e:
                print('[Error]:{}'.format(e))
    else:
        if url:
            print("[目标]:{}".format(url))
            switch(check_head(url), port, nping, dirscan, subscan, fullscan)
