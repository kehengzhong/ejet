eJet是一款在GitHub上开源的Web服务器，下载地址为 [https://github.com/kehengzhong/ejet](https://github.com/kehengzhong/ejet)，利用[adif数据结构和算法库](https://github.com/kehengzhong/adif) 和 [ePump框架](https://github.com/kehengzhong/epump)开发的嵌入式Web服务器、代理服务器、Web Cache系统，可以库的形式嵌入到应用程序中，提供Web服务功能。

# 一. eJet是什么？

eJet Web服务器是利用GitHub上的开源项目 [adif数据结构和算法库](https://github.com/kehengzhong/adif) 和 [ePump框架](https://github.com/kehengzhong/epump)，用C语言开发的一个事件驱动模型、多线程、大并发连接的轻量级的高性能Web服务器，支持HTTP/1.0和HTTP/1.1协议，并支持HTTP Proxy、Tunnel等功能。

在Linux下，eJet Web服务器编译成动态库或静态库的大小约为300K，可集成嵌入到任何应用程序中，增加应用程序使用HTTP通信和服务承载的能力，使其具备像Nginx服务器一样强大的Web功能。

eJet Web服务器完全构建在ePump框架之上，利用ePump框架的多线程事件驱动模型，实现完整的HTTP请求<-->HTTP响应事务流程。eJet并没有创建进程或线程，利用ePump框架的事件驱动多线程，高效地运用服务器的CPU处理能力。

eJet接收和处理各TCP连接上的HTTP请求头和请求体，经过解析、校验、关联、实例化等处理，执行HTTP请求，或获取Web服务器特定目录下的文件，或代理客户端发起向源HTTP服务器的请求，或将HTTP请求通过FastCGI接口转发到CGI服务器，或将客户端HTTP请求交给上层设置的回调函数处理等。所有处理结果，最终以HTTP响应方式，包括HTTP响应头和响应体，通过客户端建立的TCP连接，返回给客户端。该TCP连接可以Pipe-line方式继续发送和接收多个HTTP请求和响应。

eJet服务器提供了作为Web服务器所需的其他各项功能，包括基于TLS/SSL的安全和加密传输、虚拟主机、资源位置Location的各种匹配策略、对请求URI执行动态脚本指令（包括rewrite、reply、return、try_files等）、在配置文件中使用HTTP变量、正向代理和反向代理、HTTP Proxy、FastCGI、HTTP Proxy Cache功能、HTTP Tunnel、MultiPart文件上传、动态库回调或接口函数回调机制、HTTP日志功能、CDN分发等。

eJet Web服务器采用JSon格式的配置文件，进行系统配置管理。对JSon语法做了一定的扩展，使得JSon支持include文件指令，支持嵌入Script脚本程序语言。使用扩展JSon功能的配置文件，可更加灵活、方便地扩展Web服务功能。

eJet系统大量采用了Zero-Copy、内存池、缓存等技术，来提升Web服务器处理性能和效率，加快了请求响应的处理速度，支撑更大规模的并发处理能力，支持更大规模的网络吞吐容量等。

eJet Web服务器既可以面向程序员、系统架构师提供应用程序开发接口或直接嵌入到现有系统中，也可以面向运维工程师部署完全类似Nginx Web服务器、Web Cache、CDN回源等商业服务系统，还是面向程序员提供学习、研究开发框架、通信系统等的理想平台。

开发eJet Web服务器的原则是尽可能不依赖于第三方代码和库，降低版权和复杂部署等因素带来的潜在风险。系统使用的第三方代码或库主要为：OpenSSL库、Linux系统自带的符合POSIX标准的正则表达式regex库。gzip压缩需要依赖zlib开源库，目前没有添加进来，所以eJet Web服务器暂时不提供gzip、deflate的压缩支持。

# 二. JSon格式的配置文件

## 2.1 JSON语法特点

JSON的全称是JavaScript Object Notation，是一种轻量级的数据交换格式。JSON的文本格式独立于编程语言，采用name:value对存储名称和数据，可以保存数字、字符串、逻辑值、数组、对象等数据类型，是理想的数据交换语法格式，简洁干练，易于扩展、阅读和编写，也便于程序解析和生成。

正是由于JSon语法的简单和强扩展性、采用可保存各种数据类型的name/value对语法、可嵌套JSON子对象等特性，与配置文件的配置属性特别吻合，所以，eJet系统使用JSon格式来保存、传递、解析系统配置文件。

## 2.2 eJet配置文件对JSON的扩展

### 2.2.1 分隔符

eJet系统使用adif中的JSon库来解析、访问配置文件信息。JSon语法缺省格式以冒号(:)来分隔name和value，以单引号(')或双引号(")来包含name和value串，以逗号(,)作为name/value对的分隔符，以中括号\[\]表示数组，以大括号{}表示对象。

eJet系统采用JSon作为配置文件语法规范，为了兼容传统配置文件的编写习惯，将JSon基础语法做了一些扩展，即分隔name与value的冒号(:)换成等于号(=)，分隔name/value对之间的逗号(,)换成分号(;)，其他基础语法不变。

### 2.2.2 include指令

由于配置信息数据较大，需要使用不同的文件来保存不同的配置信息，借鉴C语言/PHP语言的include宏指令，eJet系统的JSon语法引入了include指令。扩展语法中将把"include"作为JSon语法的关键字，不会被当做对象名称和值内容来处理，而是作为嵌入另外一个文件到当前位置进行后续处理的特殊指令。其语法规范如下：

```
include <配置文件名>;
```

解析JSon内容时，如果遇到include指令，就将include指令后面的文件内容加载到当前指令位置，作为当前文件内容的一部分，进行解析处理。

### 2.2.3 单行注释和多行注释

为了增加配置文件中代码的可读性，需要对相关的定义添加详细说明、注解等内容，方便使用人员快速阅读和理解。

为支持注释功能，eJet系统的配置文件对JSON语法做了相应扩展，增加了单行注释符号#和多行注释(/* */)，其语法规范如下：

```
# 这是单行注释，如果井号(#)不在JSon某个Key-Value对的引号里面，那么以井号开头，井号后面的内容都是注释

/* 注意：多行注释是以连在一起的/和*开始
         以连在一起的*和/结尾，中间的内容都是注释
   多行注释开闭符号，必须不能在Key-Value对的引号里面
 */
```
注释的内容在解析时直接忽略跳过，不会被系统解析和处理。

### 2.2.4 script语法

使用JSON格式的数据都是由name/value对构成，eJet系统中需要在配置文件中支持Script脚本程序，灵活动态地处理HTTP请求。

eJet配置文件对JSON语法格式扩展了一种固定名称的script对象，将名称"script"作为特殊对象的名称关键字，即以script为名称的对象，其内容不能作为JSON子对象处理，而是作为Script脚本程序内容，存放在对象名为script的对象中。其语法规范如下：

```
script = {
    if ($request_uri ~* '^/topic/[0-9](*)/(.*)\.mp4$') {
        set $video_flag 1;
    }
};
```

在同一个JSon对象下，可以有多个script对象，自动构成script对象数组。

另外，使用特殊的开闭标签<script>和</script>，也可以定义脚本程序。在这两个开闭标签中间的内容，即是Script脚本程序，并将这些内容存储到配置文件定义的任意name名称对象中，其语法规范如下：

```
cache file = <script>
       if ($request_uri ~* 'laoooke')
           return "${host_name}_${server_port}${req_path_only}${req_file_only}";
       else if (!-f $root$request_path) {
           return "${host_name}_${server_port}${req_path_only}${index}";
       } else if (!-x $root$request_path) {
           return "$root$request_path is not an executable file";
       } else
           return "${request_header[host]}${req_path_only}else.html";
     </script>;
```

这样，"cache file"对象的内容就是一段脚本程序，需要在解释执行到这里时，才真正具有实际数据。

# 三. eJet资源管理架构

## 3.1 三层资源定位架构

eJet Web服务器的资源管理结构分成三层：

-   **HTTP监听服务HTTPListen**\- 对应的是监听本地IP地址和端口后的TCP连接
-   **HTTP虚拟主机HTTPHost**\- 对应的是请求主机名称domain
-   **HTTP资源位置HTTPLoc**\- 对应的是主机下的各个资源目录

一个eJet Web服务器可以启动一个到多个监听服务HTTPListen，一个监听服务下可以配置一个到多个HTTP虚拟主机，一个虚拟主机下可以配置多个资源位置HTTPLoc。这里的‘多个’没有数量限制，取决于系统的物理和内核资源限制。

## 3.2 HTTP监听服务 - HTTPListen

HTTP监听服务HTTPListen是指eJet Web服务器在启动时，需要绑定本地某个服务器IP地址和某个端口后，启动TCP监听服务，等候接收客户端发起TCP连接和HTTP请求数据，每个接受的HTTPCon连接一定属于某个HTTP监听服务HTTPListen。严格来说，HTTPListen负责接受HTTPCon连接，并将请求数据存储到HTTPCon的接收缓冲区，所以监听服务对应的是TC连接资源管理，即对应的是请求资源的domain和端口。

HTTP监听服务的配置信息格式参考如下：

```
listen = {
    local ip = *; #192.168.1.151
    port = 443;
    forward proxy = on;

    ssl = on;
    ssl certificate = cert.pem;
    ssl private key = cert.key;
    ssl ca certificate = cacert.pem;

    request process library = reqhandle.so

    script = {
        #reply 302 https://ke.test.ejetsrv.com:8443$request_uri;
        addResHeader X-Nat-IP $remote_addr;
    }

    host = {.....}
    host = {.....}
    host = {.....}
}
```

一台物理服务器可以安装多个网卡，每个网卡配置一个独立IP地址，HTTP监听服务可以监听某一个IP地址上的某个端口，也可以监听所有IP地址上的同一个端口。能启动监听服务的端口数量理论上是65536个，其中小于1024的端口需要有root超户权限才能监听。

HTTP监听服务HTTPListen依赖于底层ePump框架的eptcp_mlisten接口函数，通过该接口，让每一个epump监听线程都去监听指定IP地址和端口上的连接请求和数据请求服务。对于支持REUSEPORT的操作系统内核，大量客户端发起的并发连接，将会通过内核accept系统调用均衡地分摊到各epump线程处理，对于不支持REUSEPORT的操作系统，ePump框架负责大并发连接在各监听线程间的负载均衡。

HTTP监听服务HTTPListen可以设置当前监听为需要SSL的安全连接，并配置SSL握手所需的私钥、证书等。配置为SSL安全连接监听服务后，客户端发起的HTTP请求都必须是以 https:// 开头的URL。

在HTTP监听服务HTTPListen里，可以设置Script脚本程序，执行各种针对请求数据进行预判断和预处理的指令。这些脚本程序的执行时机是在收到完整的HTTP请求头后进行的。

eJet系统提供了动态库回调机制，使用动态库回调，既可以扩展eJet Web服务器能力，也可以将小型应用系统附着在eJet Web服务器上，处理客户端发起的HTTP请求。

HTTP监听服务HTTPListen下可管理多个虚拟主机HTTPHost，采用主机名称为索引主键的hashtab来管理下属的虚拟主机表。当当前监听服务的端口收到TCP请求和数据后，根据Host请求头的主机名称，来精确匹配定位出该请求的HTTP虚拟主机HTTPHost。

## 3.3 HTTP虚拟主机 - HTTPHost

在HTTPListen监听服务下，可以配置多个虚拟主机，虚拟主机HTTPHost是eJet Web服务器资源管理体系的第二层，将HTTPCon缓冲区的数据进行解析，创建HTTPMsg来保存解析后的HTTP请求数据，HTTP协议规范中，请求头Host携带的值内容是URL中domain信息，所以HTTP虚拟主机HTTPHost，对应的就是请求域名，或者就是一个网站。一个监听服务HTTPListen下可以寄宿大量的通过虚拟主机HTTPHost来管理的网站。

HTTP虚拟主机的配置信息格式参考如下：

```
host = {
    host name = *; #www.ejetsrv.com
    type = server | proxy | fastcgi;
    gzip = on;

    ssl certificate = cert.pem;
    ssl private key = cert.key;
    ssl ca certificate = cacert.pem;

    script = {
        #reply 302 https://ke.test.ejetsrv.com:8443$request_uri;
        addResHeader X-Nat-IP $remote_addr;
    }

    error page = {
        400 = 400.html;
        504 = 504.html;
        root = /opt/ejet/errpage;
    }

    root = /home/hzke/sysdoc;

    location = {...}
    location = {...}
    location = {...}
}
```

HTTP虚拟主机的名称一般是域名格式，即多级名称体系，包含顶级域名、二级域名、三级域名等，通过DNS系统，将该域名解析到当前eJet Web服务器所在的IP地址上，如果在该IP地址上启动HTTPListen服务，那么所有使用该域名的请求都会指向到对应的HTTPHost虚拟主机。

eJet系统根据功能服务形式，对虚拟主机定义了几种类型：Server、Proxy、FastCGI等，这几种类型可以同时并存，可或在一起。

虚拟主机HTTPHost下可以设置资源的缺省目录，下属的资源位置HTTPLoc都可以复用虚拟主机的缺省目录。

如果当前虚拟主机HTTPHost的上级监听服务是建立在安全连接SSL上，那么在有多个网站即多个虚拟主机情况下，需要为每个网站配置属于该网站域名的证书、私钥等安全身份标识信息，客户端在向同一个监听服务发送请求后，采用TLS SNI机制和eJet中实现的SSL域名选择回调，来完成域名和证书的选择。

HTTPHost虚拟主机下可以设置Script脚本程序，虚拟主机下的脚本程序被执行时机是在创建HTTPMsg实例，并设置完DocURI后开始执行资源位置实例化流程，在该流程中分别执行HTTPListen的Script脚本、HTTPHost的Script脚本、HTTPLoc的Script脚本。脚本程序的执行按照上述优先级来进行，使用脚本程序的指令来预处理HTTP请求的各类数据。

一个虚拟主机HTTPHost下可以配置多个资源位置HTTPLoc，代表访问当前域名下的不同目录。虚拟主机HTTPHost采用多种方式管理下属的资源位置HTTPLoc实例，主要包括三种：

-   精确匹配请求路径的虚拟主机表 \- 以请求路径名称为索引的资源位置索引表
-   对请求路径前缀匹配的虚拟主机表 \- 以请求路径前缀名称为索引的资源位置字典树
-   对请求路径进行正则表达式运算的虚拟主机表 \- 对正则表达式字符串为索引建立的资源位置列表

进入当前虚拟主机后，到底采用哪个资源位置HTTPLoc，匹配规则和顺序是按照上述列表的排序来进行的，首先根据HTTP请求的路径名在资源位置索引表中精准匹配，如果没有，则对请求路径名的前缀在资源位置字典树中进行匹配检索，如果还没有匹配上，最后对资源位置列表中的每个HTTPLoc，利用其正则表达式字符串，去匹配当前请求路径名，如果还是没有匹配的资源位置HTTPLoc，那么使用当前虚拟主机的缺省资源位置。

## 3.4 HTTP资源位置 - HTTPLoc

HTTP资源位置HTTPLoc代表的是请求资源在某个监听服务下的某个虚拟主机里的目录位置，HTTPLoc代表的是请求路径，根据HTTPMsg中的客户端请求数据，最终基于各种资源匹配规则，找到HTTPListen、HTTPHost、HTTPLoc后，基本确定了当前请求的资源位置、处理方式等。一个网站对应的虚拟主机下，可以有多种功能和资源类别的资源位置HTTPLoc，如图像文件放置在image为根的目录下，PHP文件需要采用FastCGI转发给php-fpm解释器等。

HTTP资源位置的配置信息格式参考如下：

```
location = {
    type = server;
    path = [ "\.(h|c|apk|gif|jpg|jpeg|png|bmp|ico|swf|js|css)$", "~*" ];

    root = /opt/ejet/httpdoc;
    index = [ index.html, index.htm ];
    expires = 30D;

    cache_file = <script>
           if ($request_uri ~* 'laoke')
               return "${host_name}_${server_port}${req_path_only}${req_file_only}";
           else if (!-f $root$request_path) {
               return "$root$request_path is not a regular file";
           } else if (!-x $root$request_path) {
               return "$root$request_path is not an executable file";
           } else
               return "${request_header[host]}${req_path_only}else.html";
         </script>;
}

location = {
    path = [ '^/view/([0-9A-Fa-f]{32})$', '~*' ];
    type = proxy;
    passurl = http://cdn.ejetsrv.com/view/$1;

    root = /opt/cache/;
    cache = on;
    cache file = /opt/cache/${request_header[host]}/view/$1;
}

location = {
    type = fastcgi;
    path = [ "\.(php|php?)$", '~*'];

    passurl = fastcgi://localhost:9000;

    index = [ index.php ];
    root = /opt/ejet/php;
}

location = {
    path = [ '/' ];
    type = server;

    script = {
        try_files $uri $uri/ /index.php?$query_string;
    };

    index = [ index.php, index.html, index.htm ];
}
```

HTTP资源位置HTTPLoc是通过路径名path和匹配类型matchtype来作为其标识，路径名为配置中设置的名称，客户端请求的路径名通过匹配类型定义的匹配规则来跟设置的路径名进行匹配，如果符合匹配，则该请求使用此资源位置HTTPLoc。

匹配规则matchtype一般定义在配置文件中path数组里的第二项，分为如下几种：

-   精准匹配，使用等于号'='
-   前缀匹配，使用'^~'这两个符号
-   区分大小写的正则表达式匹配，使用'~'符号
-   不区分大小写的正则表达式匹配，使用'~*'这两个符号
-   通用匹配，使用'/'符号，如果没有其他匹配，任何请求都会匹配到

匹配的优先级顺序为： (location =) > (location 完整路径) > (location ^~ 路径) > (location,* 正则顺序) > (location 部分起始路径) > (/)

eJet系统根据功能服务形式，对资源位置HTTPLoc定义了几种类型：Server、Proxy、FastCGI等，通常情况下，一个资源位置HTTPLoc只属于一种类型。

HTTP资源位置HTTPLoc都需要一个缺省的根目录，指向当前资源所在的根路径，客户端请求的路径都是相对于当前HTTPLoc下的root跟目录来定位文件资源的。对于Proxy模式，根目录一般充当缓存文件的根目录，即需要对Proxy代理请求回来的内容缓存时，都保存在当前HTTPLoc下的root目录中。

每个HTTPLoc下都会有缺省文件选项，可以配置多个缺省文件，一般设置为index.html等。使用缺省文件的情形是客户端发起的请求只有目录形式，如`http://www.xxx.com/`，这时该请求访问的是HTTPLoc的根目录，eJet系统会自动地依次寻找当前根目录下的各个缺省文件是否存在，如果存在就返回缺省文件给客户端。不过需要注意的是，eJet系统中这个流程是在设置DocURI时处理的。

HTTP资源位置如果是Proxy类型或FastCGI类型，则必须配置转发地址passurl，转发地址passurl一般都为绝对URL地址，含有指向其他服务器的domain域名，passurl的形式取决HTTPLoc资源类型。

反向代理（Reverse Proxy）就是将HTTPLoc的资源类型设置为Proxy模式，通过设置passurl指向要代理的远程服务器URL地址，来实现反向代理功能。在反向代理模式下，passurl可以是含有匹配结果变量的URL地址，这个地址指向的是待转发的下一个Origin服务器，匹配变量如果为$1、$2等数字变量，即表示基于正则表达式匹配路径时，把第一个或第二个匹配字符串作为passurl的一部分。当然passurl可以包含任何全局变量或配置变量，使用这些变量可以更灵活方便地处理转发数据。

在反向代理模式下，HTTPLoc资源位置下有一个cache开关，如果设置cache=on即打开Cache功能，则需要在当前HTTPLoc下设置cachefile缓存文件名。对于不同的请求地址，cachefile必须随着请求路径或参数的变化而变化，所以cachefile的取值设置需要采用HTTP变量，或者使用Script脚本来动态计算cachefile的取值。

HTTPLoc下一般都会部署Script脚本程序，包括rewrite、reply、try_files等，根据请求路径、请求参数、请求头、源地址等信息，决定当前资源位置是否需要重写、是否需要转移到其他地址处理等。

# 四. HTTP变量

## 4.1 HTTP变量的定义

HTTP变量是指在eJet Web服务器运行期间，能动态地访问HTTP请求、HTTP响应、HTTP全局管理等实例对象中的存储空间里的数据，或者访问HTTP配置文件的配置数据等等，针对这些存储空间的访问，而抽象出来的名称叫做HTTP变量。

变量的引用必须以$开头，后跟变量名，如果变量名后面还有连续紧随的其他字符串，则需用{}来包括住变量名，其基本格式为：$变量名称， ${变量名称}， ${ 变量名称 }，等等

## 4.2 HTTP变量的应用

使用HTTP变量的场景主要在JSon格式的配置文件中，给各个配置项目增加动态的可编程接口，就需要基于不同的HTTP请求的信息，做判断、比较、赋值、拷贝、串接等操作，这些都离不开变量，需要不同的变量名去访问不同HTTP请求中的不同信息内容，通过配置中使用变量：访问变量的值，进行条件判断、比较、匹配、加减乘除、赋值等。变量的使用样例可参考如下：

```
access log = {
    log2file = on;
    log file = /var/log/access.log;
    format = [ '$remote_addr', '-', '[$datetime[stamp]]', '"$request"', '"$request_header[host]"',
               '"$request_header[referer]"', '"$http_user_agent"', '$status', '$bytes_recv', '$bytes_sent' ];
}

script = {
    reply 302 https://ke.test.ejetsrv.com:8443$request_uri;
}

cache file = /opt/cache/${request_header[host]}/view/$1;

params = {
    SCRIPT_FILENAME   = $document_root$fastcgi_script_name;
    QUERY_STRING      = $query_string;
    REQUEST_METHOD    = $request_method;
    CONTENT_TYPE      = $content_type;
    CONTENT_LENGTH    = $content_length;
}

script = {
    if ($query[fid])
        cache file = $real_path$query[fid]$req_file_ext;
    else if ($req_file_only)
        cache file = $real_path$req_file_only;
    else if ($query[0])
        cache file = ${real_path}${query[0]}$req_file_ext;
    else
        cache file = ${real_path}index.html;
}
```

## 4.3 HTTP变量的类型和使用规则

eJet系统中，共定义了四种HTTP变量类型，分别为：

-   匹配变量 \- 基于资源位置HTTPLoc模式串匹配HTTP请求路径时匹配串，通过数字变量来访问，如$1,$2等；
-   局部变量 \- 由script脚本在执行过程中用set指令或赋值符号“=”设置的变量；
-   配置变量 \- 配置文件中Listen、Host、Location下定义的JSon Key变量，以系统会使用到的常量定义为主；
-   参数变量 \- 变量名称由系统预先定义、但值内容是在HTTPMsg创建后被赋值的变量，参数变量的值是只读不可写。

变量的使用规则符合高级语言的约定，对于同名变量，取值时优先级顺序为： $匹配变量 > $局部变量 > $配置变量 \> $参数变量

HTTP变量的值类型是弱类型，根据赋值、运算的规则等上下文环境的变化，来确定被使用时变量是数字型、字符型等。除了匹配变量外，其他变量的名称必须是大小写字母和下划线_组合而成，其他字符出现在变量名里则该变量一定是非法无效变量。变量的定义很简单，前面加上美元符号$，后面使用变量名称，系统就会认为是HTTP变量。美元符号后的变量名称也可以通过大括号{}来跟跟其他字符串区隔。

如果变量的值内容包含多个，那么该变量是数组变量，数组变量是通过中括号\[\]和数字下标序号来访问数组的各个元素，如$query\[1\]访问是请求参数中的第一个参数的值。

匹配变量的名称为数字，以美元号$冠头，如$1,$2...，其数字代表的是使用HTTPLoc定义的路径模式串，去匹配当前HTTP请求路径时，被匹配成功的多个子串的数字序号。匹配变量的寿命周期是HTTPMsg实例化成功即准确找到HTTPLoc资源位置实例后开始，到HTTP响应被成功地发送到客户端后，HTTPMsg消息被销毁时为止。

局部变量的名称由字母和下划线组成，是script脚本在执行过程中用set指令或赋值符号“=”设置的变量，其寿命周期是从变量被创建之后到该HTTPMsg被销毁这段期间，而HTTPMsg则是用户HTTP请求到达时创建，成功返回Response后被摧毁。

配置变量是JSon格式的配置文件中定义的Key-Value对中，以Key为名称的变量，变量的值是设置的Value内容。在配置文件中位于Location、Host、Listen下定义的Key-Value赋值语句对，左侧为变量名，右侧为变量值，用$符号可以直接引用这些变量定义的内容；在Listen、Host、Location下定义的配置变量，主要是以系统中可能使用到的常量定义为主，这些常量定义也可以使用script脚本来动态定义其常量值，此外，用户可以额外定义系统配置中非缺省常量，我们称之为动态配置变量。

参数变量是系统预定义的有固定名称的一种变量类型，参数变量一般指向HTTP请求的各类信息、eJet系统定义的全局变量等。参数变量的名称是eJet系统预先定义并公布，但大部分变量的内容是跟HTTP请求HTTPMsg相关的，即不同的请求HTTPMsg，参数变量名的值也是随着变化的。一般要求，参数变量是只读不可写变量，即参数变量的值不能被脚本程序改变，只能读取访问。

## 4.4 预定义的参数变量列表和实现原理

相比其他三种变量，参数变量是被使用最多、最有访问价值的变量，参数变量是系统预先定义的固定名称变量，变量的值是随着HTTP请求HTTPMsg的不同而不同。通过参数变量，配置文件中可以根据请求的信息，灵活动态地决定相关配置选项的赋值内容，从而扩展eJet服务器的能力，减少因额外功能扩展升级eJet系统的定制开销。

参数变量一般由eJet系统预先定义发布，其变量的值内容是跟随HTTP请求HTTPMsg的变化而变化，但变量名称是全局统一通用，所以参数变量也有时称为全局变量。

eJet系统预定义的参数变量如下：

-   **remote_addr**\- HTTP请求的源IP地址
-   **remote_port**\- HTTP请求的源端口
-   **server_addr**\- HTTP请求的服务器IP地址
-   **server_port**\- HTTP请求的服务器端口
-   **request_method**\- HTTP请求的方法，如GET、POST等
-   **scheme**\- HTTP请求的协议，如http、https等
-   **host_name**\- HTTP请求的主机名称
-   **request_path**\- HTTP请求的路径
-   **query_string**\- HTTP请求的Query参数串
-   **req\_path\_only**\- HTTP请求的只含目录的路径名
-   **req\_file\_only**\- HTTP请求路径中的文件名称
-   **req\_file\_base**\- HTTP请求路径中的文件基本名
-   **req\_file\_ext**\- HTTP请求路径中文件扩展名
-   **real_file**\- HTTP请求对应的真实文件路径名
-   **real_path**\- HTTP请求对应的真实文件所在目录名
-   **bytes_recv**\- HTTP请求接收到的客户端字节数
-   **bytes_sent**\- HTTP响应发送给客户端的字节数
-   **status**\- HTTP响应的状态码
-   **document_root**\- HTTP请求的资源位置根路径
-   **fastcgi\_script\_name**\- HTTP请求中经过脚本运行后的DocURI的路径名
-   **content_type**\- HTTP请求的内容MIME类型
-   **content_length**\- HTTP请求体的内容长度
-   **absuriuri**\- HTTP请求的绝对URI
-   **uri**\- HTTP请求源URI的路径名
-   **request_uri**\- HTTP请求源URI内容
-   **document_uri**\- HTTP请求经过脚本运行后的DocURI内容
-   **request**\- HTTP请求行
-   **http\_user\_agent**\- HTTP请求用户代理
-   **http_cookie**\- HTTP请求的Cookie串
-   **server_protocol**\- HTTP请求的协议版本
-   **ejet_version**\- eJet系统的版本号
-   **request_header**\- HTTP请求的头信息数组，通过带有数字下标或请求头名称的中括号来访问
-   **cookie**\- HTTP请求的Cookie数组，通过带有数字下标或Cookie名称的中括号来访问
-   **query**\- HTTP请求的Query参数数组，通过带有数字下标或参数名称的中括号来访问
-   **response_header**\- HTTP响应的头信息数组，通过带有数字下标或响应头名称的中括号来访问
-   **datetime**\- 系统日期时间数组，不带中括号是系统时间，带createtime或stamp的中括号则访问HTTPMsg创建时间和最后时间
-   **date**\- 系统日期数组，同上
-   **time**\- 系统时间，同上

随着应用场景的扩展，根据需要还可以扩展定义其他名称的参数变量。总体来说，使用上述参数变量，基本可以访问HTTP请求相关的所有信息，能满足绝大部分场景的需求。

系统中预定义的参数变量，都是指向特定的基础数据结构的某个成员变量，在该数据结构实例化后，其成员变量的地址指针就会被动态地赋值给预定义的参数变量，从而将地址指针指向的内容关联到参数变量上。

在设置预定义参数变量名时，一般需要设置关联的数据结构、数据结构的成员变量地址或位置、成员变量类型（字符、短整数、整数、长整数、字符串、字符指针、frame\_t）、符号类型、存储长度等，eJet系统中维持一个这样的参数变量数组，分别完成参数变量数据的初始化，通过hashtab\_t来快速定位和读写访问数组中的参数变量。

获取参数变量的实际值时，需要传递HTTPMsg这个数据结构的实例指针，根据参数变量名快速找到参数变量数组的参数变量实例，根据参数变量的信息，和传入的实例指针，定位到该实际成员变量的内存指针和大小，从内存中取出该成员变量的值。

# 五. HTTP Script脚本

## 5.1 HTTP Script脚本定义

eJet系统在配置文件上扩展了Script脚本语言的语法定义，对JSon语法规范进行扩展，定义了一套符合JavaScript和C语言的编程语法，并提供Script脚本解释器，实现一定的编程和解释执行功能。

Script脚本是由一系列符合定义的语法规则而编写的代码语句组成，代码语句风格类似Javascript和C语言，每条语句由一到多条指令构成，并以分号;结尾。

## 5.2 Script脚本嵌入位置

HTTP Script脚本程序的嵌入位置，共有两种。第一种嵌入位置是在配置文件的Listen、Host、Location下，通过增加JSon对象script，将脚本程序作为script对象的内容，来实现配置文件中嵌入脚本编程功能。在这种位置中，插入script脚本代码的语法共定义了三种：

```
  script = {....};
  script = if()... else...;
  <script> .... </script>
```

另外一种嵌入Script脚本程序的位置，是在JSon中的Key-Value对中，在Value里增加特殊闭合标签<script> Script Codes </script>，在标签里面嵌入Script脚本代码，执行完代码后返回的内容，作为Key的值，这种方式使得JSon规范中Key的值可以动态地由Script脚本程序计算得来。在Listen、Host或Location的常量赋值中，Value内容可以是script脚本，如

```
  cache file = <script> if ()... return... </script>
```

对adif 基础库中的json.c文件做了修改扩展，使得Json对象都能支持script脚本定义的这几种语法，如果某个对象下有名称为script的数据项，就认为该数据项下的Value值为脚本内容。这就将名称script作为Json的缺省常量名称了，使用时轻易不要使用script作为变量名。

## 5.3 Script脚本范例

HTTP Script脚本程序示例如下：

```
 script = {
     if ($query[fid]) "cache file" = $req_path_only$query[fid]$req_file_ext;
     else if ($req_file_only) "cache file" = ${req_path_only}index.html;
     else "cache file" = $req_path_only$req_file_only; 
 }

 cache file = <script> if ($query[fid]) return $req_path_only$query[fid]$req_file_ext;
                        else if ($req_file_only) return ${req_path_only}index.html;
                        else return $req_path_only$req_file_only; 
              </script>

 <script>
     if ($query[fid]) "cache file" = $req_path_only$query[fid]$req_file_ext;
     else if ($req_file_only) "cache file" = ${req_path_only}index.html;
     else "cache file" = $req_path_only$req_file_only; 
 </script>

 <script>
     if ($scheme == "http://") rewrite ^(.*)$  https://$host$1;
 </script>
```

HTTP Script脚本程序的解释执行，是在创建HTTPMsg实例并设置完DocURI后，开始执行资源位置实例化流程，在实例化过程中，分别执行HTTPListen的Script脚本、HTTPHost的Script脚本、HTTPLoc的Script脚本。

## 5.4 Script脚本语句

script脚本是由一系列语句构成的程序，语法类似于JavaScript和C语音，主要包括如下语句：

### 5.4.1 条件语句

条件语句主要以if、else if、else组成，基本语法为：

```
  if (判断条件) { ... } else if (判断条件) { ... } else { ... }
```

判断条件至少包含一个变量或常量，通过对一个或多个变量的值进行判断或比较，取出结果为TRUE或FALSE，来决定执行分支，判断条件包括如下几种情况：

-   (a) 判断条件中只包含一个变量；
-   (b) 判断条件中包含了两个变量；
-   (c) 文件或目录属性的判断；

判断比较操作主要包括：

-   (a) 变量1 == 变量2，判断是否相等，两个变量值内容相同为TRUE，否则为FALSE
-   (b) 变量1 != 变量2，判断不相等，两个变量值内容不相同为TRUE，否则为FALSE
-   (c) 变量名，判断变量值，变量定义了、且变量值不为NULL、且变量值不为0，则为TRUE，否则为FALSE
-   (d) !变量名，变量值取反判断，变量未定义，或变量值为NULL、或变量值为0，则为TRUE，否则为FALSE
-   (e) 变量1 ^~ 变量2，变量1中的起始部分是以变量2开头，则为TRUE，否则为FALSE
-   (f) 变量1 ~ 变量2，在变量1中查找变量2中的区分大小写正则表达式，如果匹配则为TRUE，否则为FALSE
-   (g) 变量1 ~* 变量2，在变量1中查找变量2中的不区分大小写正则表达式，如果匹配则为TRUE，否则为FALSE
-   (h) -f 变量，取变量值字符串对应的文件存在，则为TRUE，否则为FALSE
-   (i) !-f 变量，取变量值字符串对应的文件不存在，则为TRUE，否则为FALSE
-   (j) -d 变量，取变量值字符串对应的目录存在，则为TRUE，否则为FALSE
-   (k) !-d 变量，取变量值字符串对应的目录存在，则为TRUE，否则为FALSE
-   (l) -e 变量，取变量值字符串对应的文件、目录、链接文件存在，则为TRUE，否则为FALSE
-   (m) !-e 变量，取变量值字符串对应的文件、目录、链接文件不存在，则为TRUE，否则为FALSE
-   (n) -x 变量，取变量值字符串对应的文件存在并且可执行，则为TRUE，否则为FALSE
-   (o) !-x 变量，取变量值字符串对应的文件不存在或不可执行，则为TRUE，否则为FALSE

### 5.4.2 赋值语句

赋值语句主要由set语句构成，eJet系统中局部变量的创建和赋值是通过set语句来完成的。其语法如下：

```
  set $变量名  value;
```

### 5.4.3 返回语句

返回语句也即是return语句，将script闭合标签内嵌入的Scirpt脚本代码执行运算后的结果，或Key-Value对中Value内嵌的脚本程序，解释执行后的结果返回给Key变量，基本语法为：

```
  return $变量名;
  return 常量;
```

其使用形态如下：

```
  cache file = <script> if ($user_agent ~* "MSIE") return $real_file; </script>;
```

### 5.4.4 响应语句

响应语句也就是reply语句，执行该语句后，eJet系统将终止当前HTTP请求HTTPMsg的任何处理，直接返回HTTP响应给客户端，其语法如下：

```
  reply  状态码  [ URL或响应消息体 ];
```

如果返回的状态码是 444，则直接断开 TCP 连接，不发送任何内容给客户端。

调用Reply指令时，可以使用的状态码有：204，400，402-406，408，410, 411, 413, 416 与 500-504。如果不带状态码直接返回 URL 则被视为 302。其使用形态如下：

```
  if ($http_user_agent ~ curl) {
      reply 200 'COMMAND USER\n';
  }   
  if ($http_user_agent ~ Mozilla) {
      reply 302 http://www.baidu.com?$args;
  }      
  reply 404;
```

eJet系统在解释器解释执行Script代码时，先执行Listen下的script脚本、再执行Host下的script脚本，最后再执行Location下的script脚本。在执行下一个脚本之前，先判断刚刚执行的script脚本是否已经Reply了或者已经关闭当前HTTPMsg了。如果Reply了或关闭当前消息了，则直接返回，无需继续解析并执行后续的script脚本程序。

### 5.4.5 rewrite语句

eJet系统中的URL重写是通过Script脚本来实现的，分别借鉴了Apache和Nginx的成功经验。

rewrite语句实现URL重写功能，当客户HTTP请求到达Web Server并创建HTTPMsg后，分别依次执行Listen、Host、Location下的script脚本程序，rewrite语句位于这些script脚本程序之中，rewrite语句会改变请求DocURL，一旦改变请求DocURL，在依次执行完这些script脚本程序之后，继续基于新的DocURL去匹配新的Host、Location，并继续依次执行该Host、Location下的script脚本程序，如此循环，是否继续循环执行，取决于rewrite的flag标记。

rewrite基本语法如下：

```
  rewrite regex replacement [flag];
```

执行该语句时是用regex的正则表达式去匹配DocURI，并将匹配到的DocURI替换成新的DocURI（replacement），如果有多个rewrite语句，则用新的DocURI，继续执行下一条语句。

flag标记可以沿用Nginx设计的4个标记外，还增加了proxy或forward标记。其标记定义如下：

-   (a) last
    -   停止所有rewrite相关指令，使用新的URI进行Location匹配。
-   (b) break
    -   停止所有rewrite相关指令，不再继续新的URI进行Location匹配，直接使用当前URI进行HTTP处理。
-   (c) redirect
    -   使用replacement中的URI，以302重定向返回给客户端。
-   (d) permament
    -   使用replacement中的URI，以301重定向返回给客户端。
-   (e) proxy | forward
    -   使用replacement中的URI，向Origin服务器发起Proxy代理请求，并将Origin请求返回的响应结果返回给客户端。

由于reply语句功能很强大，rewrite中的redirect和permament标记所定义和实现的功能，基本都在reply中实现了，这两个标记其实没有多大必要。

rewrite使用案例如下：

```
  addReqHeader  <header name>  <header value>;
```

不能是空格字符，以字母开头后跟字母、数字和下划线_的字符串，可以用双引号圈定起来； 是任意字符串，可以以引号包含起来，字符串中可包含变量。

使用案例如下：

```
if ($proxied) {
    addReqHeader X-Real-IP $remote_addr;
    addReqHeader X-Forwarded-For $remote_addr;
}
```

### 5.4.7 addResHeader语句

其基本语法为：

```
 addResHeader  <header name>  <header value>;
```

### 5.4.8 delReqHeader语句

其基本语法为：

```
 delReqHeader  <header name>;
```

### 5.4.9 delResHeader语句

其基本语法为：

```
  delResHeader  <header name>;
```

### 5.4.10 try_files 语句

try_files 是一个重要的指令，建议位于Location、Host下面。使用该指令，依次测试列表中的文件是否存在，存在就将其设置DocURI，如不不存在，则将最后的URI设置为DocURI，或给客户端返回状态码code。

try_files基本语法如下：

```
chunked body = chunk-size[; chunk-ext-nanme [= chunk-ext-value]]\r\n
               ...
               0\r\n
               [footer]
               \r\n
```

chunk size是以16进制表示的长度，footer一般是以\\r\\n结尾的entity-header，一般都忽略掉。

eJet系统使用HTTPChunk数据结构来解析chunk分块传输编码的消息体数据，使用chunk\_t数据结构来打包分块传输编码。HTTPChunk数据结构包含chunk\_t成员实例，用于存储解析成功的Chunk数据块，每一个Chunk数据块解析状态和信息用ChunkItem来存储管理，HTTPChunk中用item_list来管理多个ChunkItem。

采用chunk分块传输编码的消息体，实际情况是一边传输一边解析，解析过程要充分考虑到当前接收缓冲区内容的不完整性，这是由HTTPChunk里的http\_chunk\_add_bufptr来实现的，函数定义如下：

```c
int http_chunk_add_bufptr (void * vchk, void * vbgn, int len, int * rmlen);
```
vbgn和len指向需解析的消息体数据，rmlen是解析成功后实际用于chunk分块传输编码的字节数量。

eJet在遇到chunk分块传输编码的消息体时，每次收到读事件，就将数据读取到缓冲区，将缓冲区所有数据交给这个解析函数解析处理，返回的rmlen值是被解析和处理的字节数，将处理完的数据从缓冲区移除掉。通过http\_chunk\_gotall来判断是否接收到全部chunk分块传输编码的所有数据，如果没有，循环地用新接收的数据调用该函数来解析和处理，直至成功接收完毕。

# 九. 反向代理和正向代理

## 9.1 判断是否为代理请求

反向代理是将不同的Origin服务器代理给客户端，客户端不做任何代理配置发起正常的HTTP请求到反向代理服务器，反向代理服务器根据配置的路径规则，代理访问不同的Origin服务器并将响应结果返回给客户端，让客户端认为反向代理服务器就是其访问的Origin服务器。

正向代理需要求客户端设置正向代理服务器地址，明确给定Origin服务器地址，要求正向代理服务器想给定的Origin服务器转发请求和响应。

上面描述的反向代理服务器，在这里就是eJet Web服务器，除了充当Web服务器功能外，还可以充当正向代理服务器和反向代理服务器。

eJet系统在HTTPMsg实例化完成后，首先要检查的是当前请求是否为Proxy代理请求:

-   是否在rewrite时启动forward到一个新的Origin服务器的动作，如果是则代理转发到新的URL
-   是否为正向代理，正向代理的请求地址request URI是绝对URI，如果是则代理转发到绝对URI上
-   判断当前资源位置HTTPLoc是否配置了反向代理，以及反向代理指向的Origin服务器，如果是，根据规则生成访问Origin服务器的URL地址

以上三种情况中，第一种和第三种为反向代理，第二种为正向代理，对应的配置样例如下：

```
location = { #rewrite ... forward
    type = server;
    path = ['/5g/', '^~' ];
    script = {
        rewrite ^/5g/.*tpl$ http://temple.ejetsrv.com/getres.php forword;
    }
}

# HTTP请求行是绝对URI地址
GET http://cdn.ejetsrv.com/view/23C87F23D909B47E2187A0DB83AF07D3 HTTP/1.1
....

location = { # 反向代理配置
    path = [ '^/view/([0-9A-Fa-f]{32})$', '~*' ];
    type = proxy;
    passurl = http://cdn.ejetsrv.com/view/$1;
......
}
```

无论是正向代理，还是反向代理，最后转发请求的操作流程基本类似，即需明确指向新Origin服务器的URL地址，作为下一步转发地址，主动建立到Origin服务器的HTTPCon连接，组装新的HTTPMsg请求，发送请求并等候响应，将响应结果转发到源HTTPMsg中，发送给客户端。

如果是代理请求，包括正向代理或反向代理，eJet需要做Proxy代理转发处理。

## 9.2 代理请求的实时转发

需要重点介绍的是实时转发源请求到Origin服务器的流程。代理转发时先创建一个代理转发的HTTPMsg实例，将源请求HTTPMsg实例的请求数据复制到代理请求HTTPMsg中，如果HTTP请求含有请求消息体时，代理转发流程有两种实现方式：

-   一种方式是存储转发，即接收完所有的HTTP请求消息体后，再复制到代理转发HTTPMsg中，最后发送出去
-   另一种方式实时转发，即接收一部分消息体就发送一部分消息体，直到全部发送完毕

为了确保代理转发效率和降低存储消耗，eJet系统采用实时转发模式。

源请求的消息体内容保存在HTTPCon的rcvstream中，响应IOE\_READ事件时将网络内容读取到该缓冲区后，就要调用http\_proxy\_srv\_send来实时转发。转发的数据包括代理请求头、上次未发送成功的消息体、及当期位于HTTPCon缓冲区中的rcvstream，严格按照接收的顺序来发送。

每次未发送成功的消息体，将会从HTTPCon的rcvstream中拷贝出来，转存到代理请求HTTPMsg中的req\_body\_stream中，作为临时缓冲区保存累次未能发送的消息体。当从源HTTPCon中接收到新数据、或到Origin服务器的目的HTTPCon中可写就绪时，都会启动http\_proxy\_srv\_send的实时发送流程，而优先发送的消息体就是代理请求中req\_body_stream中的内容。

源请求的消息体有三种情况：

-   没有消息体内容
-   存在以Content-Length来标识大小的消息体内容
-   存在以Transfer-Encoding标识分块传输编码的消息体内容

实时转发需要处理这三种情况，最终通过http\_con\_writev来发送给对方。发送不成功的剩余内容，需要从源HTTPCon中拷贝到代理请求HTTPMsg中的req\_body\_stream中。

实时转发最大问题是拥塞问题，即源HTTPCon上的请求数据发送速度很快，但到Origin服务器的目的HTTPCon连接的发送速度比较慢，导致大量的数据会堆积到代理消息HTTPMsg中req\_body\_stream中，消耗大量内存，严重时会导致内存消耗过大系统崩溃。

代理消息实时转发模式的拥塞问题根源在于两条线路传输速度不对等导致，只要发送侧速度大于接收侧速度，拥塞问题就会出现。解决拥塞问题需从源头来考虑，判断是否拥塞的标准是堆积的内存缓冲区超过一定的阈值，一旦内存堆积超过阈值，就断定为拥塞，需限制客户端继续发送任何内容，直到解除拥塞后继续发送。

## 9.3 代理响应的实时转发

代理请求转发给Origin服务器后，会返回响应消息，包括响应头和响应体，eJet处理响应头的接收和处理编码。

和HTTP请求消息的实时转发类似，代理消息的响应也需要实时转发给客户端。

根据代理HTTPMsg内部成员proxiedl连判断当前消息是否为代理，对Origin返回的响应头信息进行预处理：

-   如果是301/302跳转，当前代理消息是反向代理，并且系统允许自动重定向，则需重新发送重定向请求；
-   如果需要缓存到本地存储系统，采用缓存处理流程，见4.20章节
-   其他情形就按照代理响应来处理
    

复制所有的响应状态码和响应头到源HTTPMsg中，并将响应HTTPCon的接收缓冲区rcvstream数据实时转发到源HTTPCon中，同样地，HTTPCon中没有发送不成功的数据，转存到源HTTPMsg中的res\_body\_stream中临时缓存起来。每次当源HTTPCon可写就绪、或代理HTTPCon有数据可读并读取成功后，都会调用http\_proxy\_cli\_send，优先发送的是堆积在res\_body_stream中的数据。

其他后续流程类似请求消息的实时转发。

# 十. FastCGI机制和启动PHP的流程

## 10.1 FastCGI基本信息

FastCGI是CGI（Common Gateway Interface）的开放式扩展规范，其技术规范见网址 [http://www.mit.edu/~yandros/doc/specs/fcgi-spec.html](http://www.mit.edu/~yandros/doc/specs/fcgi-spec.html)

对静态HTML页面中嵌入动态脚本程序的内容，如PHP、ASP等，需要由特定的脚本解释器来解释运行，并动态生成新的页面，这个过程需要eJet Web服务器和脚本程序解释器之间有一个数据交互接口，这个接口就是CGI接口，考虑到性能局限，早期的独立进程模式的CGI接口发展成FastCGI接口规范。习惯地，我们把解释器称之为CGI服务器。

使用CGI接口规范的页面脚本程序可以使用任何支持标准输入STDIN、标准输出STDOUT、环境变量的编程语言来编写，如PHP、Perl、Python、TCL等。在传统CGI规范的fork-and-execute模式中，Web服务器会为每个HTTP请求，创建一个新进程、解释执行、返回响应、销毁进程，这是个很重的工作流程。

FastCGI对CGI这种重模式进行了简化，脚本解释器和Web服务器之间的交互，通过Unix Socket或TCP协议来实现，Web服务器收到需要解释执行的HTTP请求时，建立并维持通信连接到CGI服务器，按照FastCGI通信规范发送请求，并接收响应，这个流程相比CGI模式，大大提升了性能和并发处理能力。

PHP解释器名称为php-fpm（php FastCGI Processor Manager），作为FastCGI通信服务器监听来自Web服务器的连接请求，并接收连接上的数据，进行解析、解释执行后，返回响应给Web服务器端。php-fpm的配置项中，启动监听服务：

```
; The address on which to accept FastCGI requests.
; Valid syntaxes are:
;   'ip.add.re.ss:port'    - to listen on a TCP socket to a specific IPv4 address on
;                            a specific port;
;   '[ip:6:addr:ess]:port' - to listen on a TCP socket to a specific IPv6 address on
;                            a specific port;
;   'port'                 - to listen on a TCP socket to all addresses
;                            (IPv6 and IPv4-mapped) on a specific port;
;   '/path/to/unix/socket' - to listen on a unix socket.
; Note: This value is mandatory.
listen = /run/php-fpm/www.sock
;listen = 9000
```

## 10.2 eJet如何启用FastCGI

eJet收到客户端的HTTP请求并创建HTTPMsg和完成HTTPMsg实例化后，根据资源位置HTTPLoc是否将资源类型设置为FastCGI、并且设置了指向CGI服务器地址的passurl，如果都设置这两个参数，则当前请求会被当做FastCGI请求转发给CGI服务器。

启用FastCGI的参数配置如下：

```
location = {
    type = fastcgi;
    path = [ "\.(php|php?)$", '~*'];

    passurl = fastcgi://127.0.0.1:9000;
    #passurl = unix:/run/php-fpm/www.sock;

    index = [ index.php ];
    root = /data/wwwroot/php;
}
```

只要是请求DocURL中路径名称是以.php或.php5等结尾，当前请求都会被FastCGI转发。

在获取转发URL地址时，是复制配置中的passurl地址，即CGI服务器地址，不能把HTTP请求中的路径和query参数信息添加在这个转发URL后面。转发地址有两种形态：

-   采用TCP协议的CGI服务器地址，以fastcgi://打头，后跟IP地址和端口，或域名和端口；
-   采用Unix Socket的CGI服务器地址，以unix:打头，后跟Unix Socket的路径文件名。
    

passurl地址指向CGI服务器，eJet服务器可以支持很多个CGI服务器。

eJet获取到FastCGI转发地址后，根据该地址创建或打开CGI服务器FcgiSrv对象实例，建立TCP连接或Unix Socket连接到该服务器的FcgiCon实例，为当前HTTP请求创建FcgiMsg消息实例，将HTTP请求信息按照FastCGI规范封装到FcgiMsg中，并启动发送流程，将请求发送到CGI服务器。

## 10.3 FastCGI的通信规范

FastCGI通信依赖于C/S模式的可靠的流式的连接，协议定义了十种通信PDU（Protocol Data Unit）类型，每个PDU都由两部分组成：一部分是FastCGI Header头部，另一部分是FastCGI消息体，FastCGI的PDU是严格8字节对齐，PDU总长度不足8的倍数，需要添加Padding补齐8字节对齐。FastCGI的PDU头格式如下：

```c
typedef struct fastcgi_header {
    uint8           version;
    uint8           type;
    uint16          reqid;
    uint16          contlen;
    uint8           padding;
    uint8           reserved;
} FcgiHeader, fcgi_header_t;
```

上面定义的协议头格式中，version版本号1个字节，缺省值为1，type为PDU类型1个字节，共计定义了10种类型，reqid为PDU的序号，两字节BigEndian整数，contlen是PDU消息体的内容长度，两字节BigEndian整数，1字节的padding是PDU消息体不是8字节的倍数时，需要补齐8字节对齐所填充的字节数，保留1字节。

其中PDU类型共有十种，分别定义如下：

```c
/* Values for type component of FCGI_Header */
#define FCGI_BEGIN_REQUEST       1
#define FCGI_ABORT_REQUEST       2
#define FCGI_END_REQUEST         3
#define FCGI_PARAMS              4
#define FCGI_STDIN               5
#define FCGI_STDOUT              6
#define FCGI_STDERR              7
#define FCGI_DATA                8
#define FCGI_GET_VALUES          9
#define FCGI_GET_VALUES_RESULT  10
#define FCGI_UNKNOWN_TYPE       11
#define FCGI_MAXTYPE            (FCGI_UNKNOWN_TYPE)
```

其中从Web服务器发送给CGI服务器的PDU类型为：BEGIN\_REQUEST、ABORT\_REQUEST、PARAMS、STDIN、GET\_VALUES等，从CGI服务器返回给Web服务器的PDU类型为：END\_REQUEST、STDOUT、STDERR、GET\_VALUES\_RESULT等。

根据PDU type值，PDU消息体格式也都不一样，分别定义为：

```c
typedef struct {
    uint8  roleB1;
    uint8  roleB0;
    uint8  flags;
    uint8  reserved[5];
} FCGI_BeginRequest;

/* Values for role component of FCGI_BeginRequest */
#define FCGI_RESPONDER           1
#define FCGI_AUTHORIZER          2
#define FCGI_FILTER              3
```

BEGIN_REQUEST是发送数据到CGI服务器时，第一个必须发送的PDU。其中的角色role是两个字节组成，高位在前、低位在后，一般情况role值为RESPONSER，即要求CGI服务器充当Responder来处理后续的PARAMS和STDIN请求数据。字段flags是指当前连接keep-alive还是返回数据后立即关闭。

第二个需发送到CGI服务器的PDU是PARAMS，其格式是由FcgiHeader加上带有长度的name/value对组成，PDU消息体格式如下：

```c
typedef struct {
    uint8    namelen;    //namelen < 0x80
    uint32   lnamelen;   //namelen >= 0x80
    uint8    valuelen;   //valuelen < 0x80
    uint32   lvaluelen;  //valuelen >= 0x80
    uint8  * name;       //[namelen];
    uint8  * value;      //[valuelen];
} FCGI_PARAMS;
```

FastCGI中的PARAMS PDU是将HTTP请求头信息和预定义的Key-Value头信息发送给CGI服务器，这些信息都是Key-Value键值对。如果key或value的数据长度在128字节以内，其长度字段只需一个字节即可，如果大于或等于128字节，则其长度字段必须用BigEndian格式的4字节。在对HTTP请求头和预定义头Key-Value对信息封装编码成PARAMS PDU时，每个Header字段的编码格式为：先是Header的name长度，再是value长度，随后是name长度的name数据内容，最后是value长度的value数据内容。

```
1字节namelen或4字节namelen + 1字节valuelen或4字节valuelen + name + value
```

所有头信息按照上述编码格式打包完成后，总长度如果不是8的倍数，计算需不全8字节对齐的padding数量，将这些数据填充到FcgiHeader中。

第三个要发送到CGI服务器的PDU是STDIN，STDIN PDU是由FcgiHeader加上实际数据组成。注意的是STDIN数据长度不能大于65535，如果HTTP请求中消息体数据大于65535，需要对消息体拆分成多个STDIN包，使得每个STDIN PDU的消息体长度都在65536字节以下。需要特别注意的是，所有数据内容拆分成多个STDIN PDU完成后，最后还需要添加一个消息体长度为0的STDIN PDU，表示所有的STDIN数据发送完毕。

当eJet系统收到HTTP请求并需要FastCGI转发是，按照以上三类数据包协议格式，将HTTP请求打包封装，并发送成功后，就等等CGI服务器的处理和响应了。

CGI服务器返回的PDU一般如下：

如果出现请求格式错误或其他错误，会返回STDERR数据，其消息体是错误内容，将错误内容取出来可以直接返回给客户端。

正常情况下，CGI服务器会返回一个到多个STDOUT PDU，STDOUT的消息体是实际的数据内容，最大长度小于65536。需要将这些STDOUT的内容整合在一起，作为HTTP响应内容。需注意的是STDOUT内容中，也包含部分HTTP响应头信息，其格式遵循HTTP规范，每个响应头有key-value对构成，以\\r\\n换行符结束，响应头和响应体之间相隔一个空行\\r\\n。

全部STDOUT数据结束后，紧接着返回的是END_REQUEST PDU，其格式是8字节的FcgiHeader，加上8字节的消息体，其消息体定义如下：

```c
typedef struct {
    uint32     app_status;
    uint8      protocol_status;
    uint8      reserved[3];
} FCGI_EndRequest;

/* Values for protocolStatus component of FCGI_EndRequest */
#define FCGI_REQUEST_COMPLETE    0
#define FCGI_CANT_MPX_CONN       1
#define FCGI_OVERLOADED          2
#define FCGI_UNKNOWN_ROLE        3
```

eJet服务器收到END_REQUEST时，就表示CGI服务器已经返回全部的响应数据了，将这些数据发送给客户端，即可结束当前处理。

## 10.4 FastCGI消息的实时转发

eJet系统将HTTP请求实时转发给CGI服务器，基本过程跟Proxy代理转发类似，包括实时转发、流量拥塞控制等。

其中在接收CGI服务器的响应数据时，需要解析以流式返回的STDOUT PDU的数据，但响应数据的总长度并未返回，eJet对这些响应数据的实时转发是采用Transfer-Encoding分块传输编码模式。为了减少响应数据的多次拷贝，FcgiCon中每次数据读就绪时，存入rcvstream缓冲区的数据，连同rcvstream一起移入到发起HTTP请求的源HTTPMsg内的res\_rcvs\_list列表中，并将解析成功的内容指针存入到res\_body\_chunk里，类似客户端访问本地文件一样，通过http\_cli\_send发送给客户端。

# 十一. HTTP Cache系统

## 11.1 HTTP Cache功能设置

HTTP Cache是指Web服务器充当HTTP Proxy代理服务器（包括正向代理和反向代理），通过HTTP协议向Origin服务器下载文件，然后转发给客户端，这些文件在转发给客户端的同时，缓存在代理服务器的本地存储中，下次再有相同请求时，根据相关缓存策略决定本地文件是否被命中，如果命中，则该请求无需向Origin服务器请求下载，直接将缓存中命中的文件读取出来返回给客户端，从而节省网络开销。

在配置文件中配置正向代理或反向代理的地方，都可以开启cache功能，并基于配置脚本动态设置缓存文件名等缓存选项。

```
location = {
    path = [ '^/view/([0-9A-Fa-f]{32})$', '~*' ];
    type = proxy;
    passurl = http://cdn.yunzhai.cn/view/$1;

    # 反向代理配置缓存选项
    root = /opt/cache/;
    cache = on;
    cache file = /opt/cache/${request_header[host]}/view/$1;
}

send request = {
    max header size = 32K;

    /* 正向代理配置的缓存选项 */
    root = /opt/cache/fwpxy;
    cache = on;
    cache file = <script>
                   if ($req_file_only)
                       return "${host_name}_${server_port}${req_path_only}${req_file_only}";
                   else if ($index)
                       return "${host_name}_${server_port}${req_path_only}${index}";
                   else
                       return "${host_name}_${server_port}${req_path_only}index.html";
                 </script>;
}
```

在配置中启动了缓存功能后，还要根据Origin服务器返回的响应头指定的缓存策略，来决定当前下载文件是否保存在本地、缓存文件保存多长时间等。HTTP响应头中有几个头是负责缓存策略的：

```
Expires: Wed, 21 Oct 2020 07:28:00 GMT            (Response Header)
Cache-Control: max-age=73202                      (Response Header)
Cache-Control: public, max-age=73202              (Response Header)

Last-Modified: Mon, 18 Dec 2019 12:35:00 GMT      (Response Header)
If-Modified-Since: Fri, 05 Jul 2019 02:14:23 GMT  (Request Header)
 
ETag: 627Af087-27C8-32A9E7B10F                    (Response Header)
If-None-Match: 627Af087-27C8-32A9E7B10F           (Request Header)
```

Proxy代理服务器需要处理Origin服务器返回的响应头，主要是Expires、Cache-Control、Last-Modified、ETag等。根据Cache-Control的缓存策略决定当前文件是否缓存：如果是no-cache或no-store，或者设定了max-age=0，或者设定了must-revalidate等都不能将当前文件保存到缓存文件中。如果设置了max-age大于0则根据max-age值、Expires值、Last-Modified值、ETag值来判断下次请求是否使用该缓存文件。

## 11.2 eJet系统Cache存储架构

eJet系统是否启动缓存由配置信息来设定。如果是反向代理，HTTP请求对应的HTTPLoc下的反向代理开关cache是否开启，即cache=on，cache file项是否设置，来决定是否启动缓存功能；如果是正向代理，在send request选项中，是否启动cache，以及cache file命名规则是否设置，决定是否启动缓存管理。

启动了cache功能，还需要根据当前请求转发给Origin后，返回的响应头中，是否有Cache管理的头信息，来确定当前返回的响应体是否缓存，以及确定当前缓存的相关信息。

缓存的Raw文件内容存储在上述配置中以cache file命名的文件中，当文件所有内容全都下载并存储起来前，文件名后需要增加扩展名.tmp，以表示当前存储文件正在下载中，还不是一个完整的文件，但已经缓存的内容则可以被命中使用。

cache管理信息则存储在缓存信息管理文件（Cache Information Management File）中，简称为CacheInfo文件，CacheInfo文件的存储位置在Raw缓存文件所在目录下建立一个隐藏目录.cacheinfo，CacheInfo文件就存放该隐藏目录下，CacheInfo文件名是在Raw存储文件后增加后缀.cacinf，譬如Raw缓存文件为foo.jpg，则缓存信息管理文件路径为： .cacheinfo/foo.jpg.cacinf

CacheInfo文件的结构包括三部分：Cache头信息（96字节）、Raw存储碎片管理信息。Cache头信息是固定的96字节，其结构如下：

```c
/* 96 bytes header of cache information file */
typedef struct cache_info_s {
    char         * cache_file;
    void         * hcache;
    char         * info_file;
    void         * hinfo;

    uint8          initialized;
 
    uint32         mimeid;
    uint8          body_flag;
    int            header_length;
    int64          body_length;
    int64          body_rcvlen;
 
    /* Cache-Control: max-age=0, private, must-revalidate
       Cache-Control: max-age=7200, public
       Cache-Control: no-cache */
    uint8          directive;     //0-max-age  1-no cache  2-no store
    uint8          revalidate;    //0-none  1-must-revalidate
    uint8          pubattr;       //0-unknonw  1-public  2-private(only browser cache)
 
    time_t         ctime;
    time_t         expire;
    int            maxage;
    time_t         mtime;
    char           etag[36];
 
    FragPack     * frag;
 
} CacheInfo;
```

在头信息之后存放的是存储内容碎片管理信息，每个碎片单元为8字节：

```c
typedef struct frag_pack {
    int64    offset;
    int64    length;
} FragPack;
```

内存中采用动态有序数组来管理每一个碎片块，相邻块就需要合并成一个块，完整文件只有一个块。将这些碎片块信息按照8字节顺序存储在这个区域中。每当文件有新内容写入时，内存碎片块数组要完成合并等更新，并将最新结果更新到这个区域。碎片块信息管理的是Raw存储文件中从Origin服务器下载并实际存储的数据存储状态，每块是以偏移量和长度来唯一标识，相邻的碎片块合并，完整文件只有一个碎片块。

## 11.3 eJet系统缓存处理流程

eJet系统作为正向代理或反向代理服务器，实现边下载边缓存、完整缓存时无需代理转发直接返回缓存内容给客户端等功能，可以实现对大大小小的Origin文件的实时缓存功能，包括碎片存储、随机存储等。

### 11.3.1 全局管理CacheInfo对象

系统维护一个全局的CacheInfo对象哈希表，以Raw缓存文件名作为唯一标识和索引，如果存在多个用户请求同一个需要缓存的Origin文件时，只打开或创建一个CacheInfo对象，该对象成员由互斥锁来保护。而每个对同一Origin文件的HTTP请求，请求位置、偏移量、读写Raw缓存文件的句柄等都保存在各自的HTTPMsg实例对象中。

CacheInfo对象是管理和存放Raw缓存文件的各项元信息，对外暴露的主要接口是：`cache_info_open, cache_info_create, cache_info_close, cache_info_add_frag等`

用户发起Origin文件请求时，先调用cache\_info\_open打开CacheInfo对象，如果不存在，则在收到Origin的成功响应后，调用cache\_info\_create创建CacheInfo对象。每次调用cache\_info\_open时，如果CacheInfo对象已经在内存中，则将count计数加1，只有count计数为0时才可以删除释放CacheInfo对象。当HTTPMsg成功返回给用户后，需要关闭CacheInfo对象，调用cache\_info\_close，首先将count计数减1，如果count大于0，直接返回不做资源释放。

### 11.3.2 向Origin服务器转发Proxy代理请求

eJet收到HTTP客户请求时，如果是Proxy请求，则调用http\_proxy\_cache\_open检测并打开缓存，先根据请求URL对应的HTTPLoc配置信息或正向代理对应的send request配置信息，决定当前代理模式下的HTTP请求是否启用了Cache功能，如果启用了Cache功能，并且Cache File变量设置了正确的Raw缓存文件名，将该缓存文件名保存在HTTPMsg对象的res\_file_name中。

检查该缓存文件是否存在，如果存在则直接将该缓存文件返回给客户端即可。注：在没有收到全部字节数据之前Raw缓存文件名是实际缓存文件后加.tmp做扩展名。

如果该文件不存在，以该缓存文件名为参数，调用cache\_info\_open打开CacheInfo对象，如果不存在缓存信息对象CacheInfo，则返回并直接将客户端请求转发到Origin服务器。

如果存在CacheInfo对象，也就是存在以.tmp为扩展名的Raw缓存文件和以.cacinf为扩展名的缓存信息文件，则判断当前请求的内容（Range规范指定的请求区域）是否全部包含在Raw缓存文件中，如果包含了，则直接将该部分内容返回给客户端，无需向Origin服务器发送HTTP下载请求；如果不包含，则需要向Origin服务器发送请求，但本地缓存中已经有的内容不必重新请求，而是将客户端请求的区域（Range规范指定的范围）中尚未缓存到本地的起始位置和长度计算出来，组成新的Range规范，向Origin发送HTTP请求。

### 11.3.3 处理Origin服务器返回的响应头

当HTTP请求转发到Origin服务器并返回响应后，正常情况是将Proxy代理请求HTTPMsg中所有的响应头全部复制一份到源请求HTTPMsg的响应头中，包括状态码也复制过去。

但对于启用了Cache=on并且CacheInfo也已经打开的情况，则需要修正源请求HTTPMsg的响应头，即调用http\_cache\_response_header来完成：删除掉不必要的响应头，修正HTTP响应体的内容传输格式，即选择Content-Length方式还是Transfer-Encoding: chunked方式，并将状态码修改成206还是200，修改Content-Range的值内容，因为源请求的Range和向Origin服务器发起的Proxy代理请求的Range不一定是一致的。并根据CacheInfo信息决定是否增加Expires和Cache-Control等响应头，等等

随后，对Origin服务器返回的HTTP响应头进行解析，调用http\_proxy\_cache_parse来完成：分别解析Expires、ETag、Last-Modified、Cache-Control等响应头，基于这些响应头信息，再次判断当前响应内容是否需要缓存Cache=on。

如果不需要缓存：则将Cache设置为off，并关闭已经打开的CacheInfo（甚至删除掉CacheInfo文件和Raw缓存文件），最主要的是检查源请求的Range范围和Proxy代理请求的Range范围是否一致，如果不一致，则需要重新将源HTTP请求原样再发送一次，并清除当前Proxy代理请求的所有信息。由于将源HTTP请求HTTPMsg中Cache设置为off了，后续重新发送的Proxy代理请求将不启用缓存功能，直接使用实时转发模式。如果两个请求的Range一致，则直接将当前代理请求的响应体内容采用实时转发模式，发送给客户端。

如果需要缓存：解析出响应头中的Content-Range中的信息，如果之前用cache\_info\_open打开CacheInfo对象失败，则此时需调用cache\_info\_create来创建CacheInfo对象，如果创建失败（内存不够、目录不存在等）则关闭缓存功能，用实时转发模式发送响应。随后，提取此次响应的信息，并保存到CacheInfo对象中，打开或创建Raw缓存文件，最重要的几点是：打开或创建的Raw缓存文件句柄存放在源请求的HTTPMsg中，并将该文件seek写定位到Range或Content-Range头中指定的偏移位置上，在此位置上存放Proxy代理请求中的响应体。最后，将CacheInfo对象的最新内容写入到缓存信息文件中。

### 11.3.4 存储Origin服务器返回的响应体

任何开启了Cache功能的HTTP请求，只要请求的内容不在本地缓存中，都需要向Origin服务器以Proxy模式转发HTTP请求，在处理完代理请求的响应头后，需要将响应体存储到Raw缓存文件适当位置，将存储位置信息更新到缓存信息文件中，并启动向客户端发送响应。

存储Proxy代理请求的响应体是调用http\_proxy\_srv\_cache\_store来实现的：先验证当前源HTTPMsg是否为pipeline后面的请求消息，是否Cache=on等。将代理请求HTTPcon接收缓冲区中的内容作为要存储的响应体内容，进行简单解析判断，

- （a）如果响应体是Content-Length格式：计算还剩余多少内容没收到，并对比接收缓冲区内容。如果剩余内容为0，则已经全部收到了请求的内容，关闭当前HTTP代理消息，并将res\_body\_chunk设置为结束。如果还有很多剩余内容没收到，则将接收缓冲区写入到.tmp的Raw缓存文件中，写文件句柄在源HTTPMsg对象中，将写入成功数据块的文件位置和长度信息，追加到CacheInfo对象中，并更新到缓存信息文件里，将代理请求HTTPCon缓冲区中已经写入Raw缓存文件的内容删除掉。最后再判断，刚才从缓冲区追加写入到文件的内容是否全部收齐了，如果收齐了，关闭当前HTTP代理消息。

- （b）如果响应体是Transfer-Encoding: chunked格式：这种格式并不知道响应体总长度是多少，也不知道剩余还有多少内容，返回的响应体是以一块一块数据块编码方式，每个数据块前面是当前数据块长度（16进制）加上\\r\\n，每个数据块结尾也加上\\r\\n为结尾。只有收到一个长度为0的数据块，才知道全部响应体已经结束和收齐了。由于网络传输的复杂性，每次接收数据时，并不一定会完整地收齐一个完整的数据块，所以需要将接收缓冲区的数据交给http_chunk模块判断，是否为接续块、是否收到结尾块等。

处理接收缓冲区数据前，先判断是否收齐了全部响应体，如果收齐了，设置res\_body\_chunk结束状态，关闭当前代理消息。将接收缓冲区的所有内容添加到http_chunk中解析判断，得出缓冲区的内容哪些是接续的数据块，是否收齐等，将接收缓冲区中那些接续数据块部分写入到.tmp的Raw缓存文件中，其中写文件句柄存放在源HTTPMsg对象中，更新总长度，删除接收缓冲区中已经写入的内容，并将写入成功的数据块的文件位置和长度信息，追加到CacheInfo对象中，并更新到缓存信息文件里。最后判断，如果全部数据块都接收齐全了，关闭当前HTTP代理消息，关闭当前HTTP代理消息，同时正式计算并确定当前收齐了所有数据，设置实际的文件长度。

- （c）最后启动发送缓存文件数据到客户端。

### 11.3.5 向源HTTPMsg的客户端发送响应

发送的响应包括响应头和位于缓存文件中的响应体，调用http\_proxy\_cli\_cache\_send来处理：

通过HTTP的承载协议TCP来发送数据前，需要有序地整理待发送的数据内容，一般情况下，待发送的数据内容包括缓冲区数据、文件数据（完整文件内容、部分文件内容等）、未知的需要网络请求的数据等等，这些数据的总长度有可能知道、也可能不知道，这些待发送数据一般情况下，都位于不同存储位置，譬如在内存中、硬盘上、网络里等，其特点是分布式的、不连续的、碎片化的、甚至内容长度非常大（大到内存都不可能全部容纳的极端情况），管理这些不连续的、碎片化、甚至超大块头数据，是由数据结构chunk_t来实现的。

chunk\_t数据结构提供了各类功能接口，包括添加各种数据（内存块、文件名、文件描述符、文件指针等）、有序整理、统一输出、检索等访问接口，最主要的功能是该数据结构解决了不同类别数据整合在一起，模拟成为了一个大缓冲区，大大减少了数据读写拷贝产生的巨额性能开销，大大减少了内存消耗。使用该数据结构，只需将要发送的各种数据内容，通过chunk\_t的各类数据追加接口，添加到该数据结构的实例对象中，最后通过tcp\_writev或tcp\_sendfile来实现数据高效、快速、零拷贝方式的传输发送。

基于以上逻辑，向客户端发送数据的主要工作是如何将待发送内容添加到源HTTPMsg中的res\_body\_chunk中：

- （a）首先计算出res\_body\_chunk中累计存放的响应体数据总长度，加上源HTTP请求文件的起始位置（如果有Range取其起始位置，如果没有Range，缺省为0），得到当前要追加发送给客户端的数据在缓存文件中的位置偏移量。分别考虑两种响应体编码格式的处理情况；

- （b）如果响应体是通过Content-Length来标识：

先用HTTP消息响应总长度减去chunk中的响应体总长度，就计算出剩余的有待添加的数据长度。通过CacheInfo的碎片数据管理接口，查询出当前Raw缓存文件中，以(a)中计算出的缓存文件偏移量位置，查出可用的数据长度有多少。

如果Raw缓存文件中存在可用数据，对比剩余数据长度，截取多余部分。将该Raw缓存文件名、文件偏移位置、截取处理过的可用数据长度等作为参数，调用chunk添加数据接口，添加到res\_body\_chunk中，如果跟chunk中之前存储且未发送出去的数据是接续的，合并处理。如果添加到chunk中的数据总长度达到或超过源请求HTTPMsg消息的响应总长度，则将res\_body\_chunk设置结束状态，启动TCP发送流程。

如果Raw缓存文件中不存在可用数据，则判断是否向Origin服务器发送HTTP代理请求：当前源HTTP请求中没有其他的代理请求存在、Raw缓存文件数据不完整、源HTTP请求的数据范围不在Raw缓存文件中，这三个条件都满足时，则需要向Origin服务器发送HTTP代理请求。这个代理请求是HTTP GET请求，可能跟源HTTP请求方法不一样，只是获取缓存数据的某一部分内容，其Range值是从源请求起始位置开始，去查找实际Raw缓存文件存储情况，得出的空缺处偏移位置。该HTTP代理请求，只负责下载数据存储到本地缓存文件，其响应头信息并不更新到缓存信息文件中。

- （c）如果响应体的编码格式为Transfer-Encoding: chunked时：

通过CacheInfo的碎片数据管理接口，查询出当前Raw缓存文件中，以(a)中计算出的缓存文件偏移量位置，查出可用的数据长度有多少。

如果Raw缓存文件中存在可用数据，将可用数据长度截成最多50个1M大小的数据块，将Raw缓存文件名、1M数据块起始位置、长度作为参数添加到res\_body\_chunk中。如果添加到chunk中的数据总长度达到或超过源请求HTTPMsg消息的响应总长度，则将res\_body\_chunk设置结束状态，启动TCP发送流程。

如果Raw缓存文件中不存在可用数据，则与上述（b）流程类似。

- （d）如果源HTTPMsg中统计发送给客户端的响应数据总长度小于res\_body\_chunk中的总长度，开始发送chunk中的数据。

### 11.3.6 发送响应给客户端的流程是标准通用的流程

基于HTTP Proxy的缓存数据存储、发送、缓存信息管理维护等功能全部实现完成。

# 十二. HTTP Tunnel

HTTP Tunnel是在客户端和Origin服务器之间，通过Tunnel网关，建立传输隧道的通信方式，eJet服务器可以充当HTTP Tunnel网关，分别与客户端和Origin服务器之间建立两个TCP连接，并在这两个连接之间进行数据的实时转发。根据RFC 2616规范，HTTP CONNECT请求方法是建立HTTP Tunnel的基本方式。

HTTP Tunnel最常用的场景是HTTP Proxy正向代理服务器，代理转发客户端https的安全连接请求到Origin服务器，一般情况下，需要采用端到端的TLS/SSL连接，这时，客户端会尝试发送CONNECT方法的HTTP请求，建立一条通过Proxy服务器，到达Origin服务器的连接隧道，即两个TCP连接串联来实时转发数据，通过这个连接隧道，进行TLS/SSL的安全握手、认证、密钥交换、数据加密等，从而实现端到端的安全数据传输。

# 十三. eJet的Callback回调机制

## 13.1 eJet回调机制

eJet系统提供了HTTP请求消息交付给应用程序处理的回调机制，回调机制是事件驱动模型中底层系统异步调用上层处理函数的编程模式，上层应用系统需事先将函数实现设置到底层系统的回调函数指针中。

eJet系统提供了两种回调机制，一种是在启动eJet时，设置的全局回调函数，另一种是在系统配置文件中位于监听服务下的动态库配置回调机制。

## 13.2 eJet全局回调函数

全局回调函数的设置是在启动eJet系统时，应用层可以实现HTTP消息处理函数，来处理所有HTTP请求的HTTPMsg，这是程序级的回调机制，需要将eJet代码嵌入到应用系统中来实现回调处理。

设置全局回调的API如下：

```c
int http_set_reqhandler (void * httpmgmt, RequestHandler * reqhandler, void * cbobj);
```

其中，httpmgmt是eJet系统创建的全局管理入口HTTPMgmt对象实例， reqhandler是应用层实现的回调函数，cbobj是应用层回调函数的第一个回调参数，eJet每次调用回调函数时，必须携带的第一个参数就是cbobj。

应用层回调函数的原型如下：

```c
typedef int RequestHandler (void * cbobj, void * vmsg);
```

其中，cbobj是设置全局回调函数时传递回调参数，vmsg是当前封装HTTP请求的HTTPMsg实例对象。

应用程序将系统管理所需的数据结构（包括应用层配置、数据库连接、用户管理等）封装好，创建并初始化一个cbobj对象，作为设置回调函数时的回调参数。通过回调参数，已经HTTPMsg请求对象，可以将请求信息和应用程序内的数据对象建立各种关联关系。

## 13.3 eJet动态库回调

eJet系统另外一种回调是使用动态库的回调方式，这是松耦合型的、修改配置文件就可以完成回调处理的方式。应用程序无需改动eJet的任何代码，只需在配置中添加含有路径的动态库文件名，即可以实现回调功能，其中动态库必须实现三个固定名称的函数，且遵循eJet约定的函数原型定义。

配置文件中添加动态库回调的位置：

```
listen = {
    local ip = *;
    port = 8181;

    request process library = reqhandle.so app.conf
......
```

eJet系统启动期间，加载配置文件后，解析三层资源架构的第一步HTTPListen时，其配置项下的动态库会被加载，加载过程为：

-   加载配置项指定动态库文件；
-   根据函数名http\_handle\_init，获取动态库中的初始化函数指针；
-   根据函数名http_handle，获取动态库中的回调处理函数指针；
-   根据函数名http\_handle\_clean，获取动态库中的清除函数指针；
-   执行动态库初始化函数，并返回初始化后的回调参数对象。

在eJet系统退出时，会调用http\_handle\_clean来释放初始化过程分配的资源。

动态库在实现回调时，必须含有这三个函数名：http\_handle\_init、http\_handle、http\_handle_clean，其函数原型定义如下：

```c
typedef void * HTTPCBInit     (void * httpmgmt, int argc, char ** argv);
typedef void   HTTPCBClean    (void * hcb);
typedef int    RequestHandler (void * cbobj, void * vmsg);
```

其中回调函数http\_handle的第一个参数cbobj是由http\_handle_init返回的结果对象，vmsg即是eJet系统的HTTPMsg实例对象。

## 13.4 回调函数使用HTTPMsg的成员函数

eJet系统通过传递HTTPMsg实例对象给回调函数，来处理HTTP请求。HTTP对象封装了HTTP请求的所有信息，回调函数在处理请求时，可以添加各种响应数据到HTTPMsg中，包括响应状态、响应头、响应体等。

访问请求头信息或添加响应数据的操作，既可以直接对HTTPMsg的成员变量进行数据读取或写入，也可以通过调用HTTPMsg内置的指针函数来进行处理，HTTPMsg中封装了很多函数调用，通过这些函数，基本可实现eJet系统HTTP请求处理的各种操作。这些例子函数如下：

```c
......
char * (*GetRootPath)     (void * vmsg);
 
int    (*GetPath)         (void * vmsg, char * path, int len);
int    (*GetRealPath)     (void * vmsg, char * path, int len);
int    (*GetRealFile)     (void * vmsg, char * path, int len);
int    (*GetLocFile)      (void * vmsg, char * p, int len, char * f, int flen, char * d, int dlen);
 
int    (*GetQueryP)       (void * vmsg, char ** pquery, int * plen);
int    (*GetQuery)        (void * vmsg, char * query, int len);
int    (*GetQueryValueP)  (void * vmsg, char * key, char ** pval, int * vallen);
int    (*GetQueryValue)   (void * vmsg, char * key, char * val, int vallen);

int    (*GetReqContentP)    (void * vmsg, void ** pform, int * plen);
 
int    (*GetReqFormJsonValueP)  (void * vmsg, char * key, char ** ppval, int * vallen);
int    (*GetReqFormJsonValue)   (void * vmsg, char * key, char * pval, int vallen);

int    (*SetStatus)      (void * vmsg, int code, char * reason);
int    (*AddResHdr)      (void * vmsg, char * na, int nlen, char * val, int vlen);
int    (*DelResHdr)      (void * vmsg, char * name, int namelen);
 
int    (*SetResEtag) (void * vmsg, char * etag, int etaglen);

int    (*SetResContentType)   (void * vmsg, char * type, int typelen);
int    (*SetResContentLength) (void * vmsg, int64 len);

int    (*AddResContent)       (void * vmsg, void * body, int64 bodylen);
int    (*AddResContentPtr)    (void * vmsg, void * body, int64 bodylen);
int    (*AddResFile)          (void * vmsg, char * filename, int64 startpos, int64 len);

int    (*Reply)          (void * vmsg);
int    (*RedirectReply)  (void * vmsg, int status, char * redurl);
......
```

eJet通过设置回调函数的两种接口机制，将客户端的HTTP请求转交给特定的应用程序来处理，充分利用Web开发的各种前端技术，扩展应用程序与用户前端的交互能力。
