## eJet - a lightweight high-performance embeded Web Server

*eJet 是一个轻量级、高性能、嵌入式Web服务器，实现HTTP/1.1协议全栈功能，包括TLS/SSL、正向代理、反向代理、FastCGI、Cookie、Web Cache、访问日志、HTTP变量、HTTP Script脚本程序、JSon配置文件、虚拟主机、HTTP Location、Rewrite/Try_files等指令、HTTP Tunnel、应用回调和动态库回调等，是承载超大文件上传下载、网站、PHP、CDN、Web Cache、嵌入式Web等服务的理想平台。*


## 目录
* [一. eJet是什么？](#一-ejet是什么)
* [二. eJet系统流程和工作原理](#二-ejet系统流程和工作原理)
    * [2.1 Web服务器基本功能](#21-web服务器基本功能)
    * [2.2 eJet Web服务器启动流程](#22-ejet-web服务器启动流程)
    * [2.3 启动监听服务](#23-启动监听服务)
    * [2.4 http_pump作为事件驱动核心入口](#24-http_pump作为事件驱动核心入口)
    * [2.5 IOE_ACCEPT事件驱动eJet创建HTTPCon连接](#25-ioe_accept事件驱动ejet创建httpcon连接)
    * [2.6 IOE_READ事件驱动eJet读取请求数据](#26-ioe_read事件驱动ejet读取请求数据)
    * [2.7 解析HTTP请求数据](#27-解析http请求数据)
    * [2.8 创建HTTPMsg保存请求数据](#28-创建httpmsg保存请求数据)
    * [2.9 设置DocURI并启动HTTPMsg资源实例化](#29-设置docuri并启动httpmsg资源实例化)
    * [2.10 Proxy代理转发](#210-proxy代理转发)
        * [2.10.1 判定是否代理转发---正向代理或反向代理](#2101-判定是否代理转发---正向代理或反向代理)
        * [2.10.2 代理请求资源是否在本地缓存里](#2102-代理请求资源是否在本地缓存里)
        * [2.10.3 创建代理请求消息](#2103-创建代理请求消息)
        * [2.10.4 打开源服务器并建立通信连接](#2104-打开源服务器并建立通信连接)
        * [2.10.5 发送代理请求到源服务器](#2105-发送代理请求到源服务器)
    * [2.11 FastCGI转发](#211-fastcgi转发)
    * [2.12 读取并解析请求体](#212-读取并解析请求体)
    * [2.13 由Handler处理HTTPMsg](#213-由handler处理httpmsg)
        * [2.13.1 校验请求方法](#2131-校验请求方法)
        * [2.13.2 反向Proxy模式缓存内容处理](#2132-反向proxy模式缓存内容处理)
        * [2.13.3 正向Proxy模式校验](#2133-正向proxy模式校验)
        * [2.13.4 HTTP消息应用回调和动态库回调处理](#2134-http消息应用回调和动态库回调处理)
        * [2.13.5 读取并发送资源文件或路径下的缺省文件](#2135-读取并发送资源文件或路径下的缺省文件)
    * [2.14 发送响应到客户端](#214-发送响应到客户端)
    * [2.15 用状态机处理不完整请求](#215-用状态机处理不完整请求)
    * [2.16 设置可写通知产生IOE_WRITE事件处理网络拥塞](#216-设置可写通知产生ioe_write事件处理网络拥塞)
    * [2.17 利用定时器产生的IOE_TIMEOUT事件监管实例对象](#217-利用定时器产生的ioe_timeout事件监管实例对象)
* [三. eJet系统基本数据结构](#三-ejet系统基本数据结构)
    * [3.1 HTTPMgmt - eJet内核](#31-httpmgmt---ejet内核)
    * [3.2 HTTPMsg - 消息](#32-httpmsg---消息)
    * [3.3 HTTPCon - 通信连接](#33-httpcon---通信连接)
    * [3.4 HTTPListen - 监听服务](#34-httplisten---监听服务)
    * [3.5 HTTPHost - 虚拟主机](#35-httphost---虚拟主机)
    * [3.6 HTTPLoc - 资源位置](#36-httploc---资源位置)
    * [3.7 HTTPHeader - 头信息](#37-httpheader---头信息)
    * [3.8 HTTPUri - 资源地址URL](#38-httpuri---资源地址url)
    * [3.9 HTTPVar - HTTP变量](#39-httpvar---http变量)
    * [3.10 HTTPLog - 日志信息](#310-httplog---日志信息)
    * [3.11 CacheInfo - 缓存信息管理](#311-cacheinfo---缓存信息管理)
    * [3.12 HTTPForm - 表单信息](#312-httpform---表单信息)
    * [3.13 HTTPScript - 脚本程序](#313-httpscript---脚本程序)
    * [3.14 HTTPSrv - 源服务器](#314-httpsrv---源服务器)
    * [3.15 HTTPChunk - HTTP数据块](#315-httpchunk---http数据块)
    * [3.16 HTTPCookie - Cookie数据](#316-httpcookie---cookie数据)
    * [3.17 FcgiSrv - FastCGI服务器](#317-fcgisrv---fastcgi服务器)
    * [3.18 FcgiCon - FastCGI通信连接](#318-fcgicon---fastcgi通信连接)
    * [3.19 FcgiMsg - FastCGI消息](#319-fcgimsg---fastcgi消息)
* [四. eJet核心功能模块](#四-ejet核心功能模块)
    * [4.1 eJet资源管理架构](#41-ejet资源管理架构)
        * [4.1.1 三层资源定位架构](#411-三层资源定位架构)
        * [4.1.2 HTTP监听服务 - HTTPListen](#412-http监听服务---httplisten)
        * [4.1.3 HTTP虚拟主机 - HTTPHost](#413-http虚拟主机---httphost)
        * [4.1.4 HTTP资源位置 - HTTPLoc](#414-http资源位置---httploc)
    * [4.2 HTTP变量](#42-http变量)
        * [4.2.1 HTTP变量的定义](#421-http变量的定义)
        * [4.2.2 HTTP变量的应用](#422-http变量的应用)
        * [4.2.3 HTTP变量的类型和使用规则](#423-http变量的类型和使用规则)
        * [4.2.4 预定义的参数变量列表和实现原理](#424-预定义的参数变量列表和实现原理)
    * [4.3 HTTP Script脚本](#43-http-script脚本)
        * [4.3.1 HTTP Script脚本定义](#431-http-script脚本定义)
        * [4.3.2 Script脚本嵌入位置](#432-script脚本嵌入位置)
        * [4.3.3 Script脚本范例](#433-script脚本范例)
        * [4.3.4 Script脚本语句](#434-script脚本语句)
            * [4.3.4.1 条件语句](#4341-条件语句)
            * [4.3.4.2 赋值语句](#4342-赋值语句)
            * [4.3.4.3 返回语句](#4343-返回语句)
            * [4.3.4.4 响应语句](#4344-响应语句)
            * [4.3.4.5 rewrite语句](#4345-rewrite语句)
            * [4.3.4.6 addReqHeader语句](#4346-addreqheader语句)
            * [4.3.4.7 addResHeader语句](#4347-addresheader语句)
            * [4.3.4.8 delReqHeader语句](#4348-delreqheader语句)
            * [4.3.4.9 delResHeader语句](#4349-delresheader语句)
            * [4.3.4.10 try_files 语句](#43410-try_files-语句)
            * [4.3.4.11 注释语句](#43411-注释语句)
        * [4.3.5 Script脚本解释器](#435-script脚本解释器)
    * [4.4 JSon格式的系统配置文件](#44-json格式的系统配置文件)
        * [4.4.1 JSON语法特点](#441-json语法特点)
        * [4.4.2 eJet配置文件对JSON的扩展](#442-ejet配置文件对json的扩展)
            * [4.4.2.1 分隔符](#4421-分隔符)
            * [4.4.2.2 include指令](#4422-include指令)
            * [4.4.2.3 单行注释和多行注释](#4423-单行注释和多行注释)
            * [4.4.2.4 script语法](#4424-script语法)
        * [4.4.3 eJet配置文件](#443-ejet配置文件)
    * [4.5 事件驱动流程 http_pump](#45-事件驱动流程-http_pump)
    * [4.6 HTTP请求和响应](#46-http请求和响应)
        * [4.6.1 HTTP请求格式](#461-http请求格式)
        * [4.6.2 HTTP响应格式](#462-http响应格式)
        * [4.6.3 头和体的解析与编码](#463-头和体的解析与编码)
    * [4.7 HTTPMsg的实例化流程](#47-httpmsg的实例化流程)
    * [4.8 HTTP MIME管理](#48-http-mime管理)
    * [4.9 HTTP URI管理](#49-http-uri管理)
    * [4.10 chunk_t数据结构](#410-chunk_t数据结构)
    * [4.11 HTTP请求/响应的发送流程（writev/sendfile）](#411-http请求响应的发送流程writevsendfile)
    * [4.12 使用writev和sendfile提升发送效率](#412-使用writev和sendfile提升发送效率)
    * [4.13 eJet日志系统](#413-ejet日志系统)
    * [4.14 Callback回调机制](#414-callback回调机制)
    * [4.15 正则表达式的使用](#415-正则表达式的使用)
    * [4.16 超大文件上传](#416-超大文件上传)
    * [4.17 TLS/SSL](#417-tlsssl)
    * [4.18 Chunk传输编码解析](#418-chunk传输编码解析)
    * [4.19 反向代理](#419-反向代理)
    * [4.20 FastCGI机制和启动PHP的流程](#420-fastcgi机制和启动php的流程)
    * [4.21 两个通信连接的串联Pipeline](#421-两个通信连接的串联pipeline)
    * [4.22 HTTP Cache系统](#422-http-cache系统)
    * [4.23 HTTP Tunnel](#423-http-Tunnel)
    * [4.24 HTTP Cookie机制](#424-http-cookie机制)
    * [4.25 零拷贝Zero-Copy技术](#425-零拷贝zero-copy技术)
    * [4.26 内存池](#426-内存池)
* [五. eJet为什么高性能](#五-ejet为什么高性能)
* [六. eJet Web服务应用案例](#六-ejet-web服务应用案例)
    * [6.1 大型资源网站](#61-大型资源网站)
    * [6.2 承载PHP应用](#62-承载php应用)
    * [6.3 充当代理服务器](#63-充当代理服务器)
    * [6.4 Web Cache服务](#64-web-cache服务)
    * [6.5 作为CDN边缘分发](#65-作为cdn边缘分发)
    * [6.6 应用程序集成eJet](#66-应用程序集成ejet)
* [七. eJet相关的另外两个开源项目](#七-ejet相关的另外两个开源项目)
    * [adif 项目](#adif-项目)
    * [ePump项目](#epump项目)
* [八. 关于作者 老柯 (laoke)](#八-关于作者-老柯-laoke)
 
***

一. eJet是什么？
------
 
eJet是采用标准C语言开发的Web服务器，支持HTTP/1.0和HTTP/1.1协议，eJet Web服务器是以adif库和ePump框架为底层支撑，构建的一个事件驱动模型、多线程、大并发连接的轻量级的高效Web服务器。eJet Web服务器的全部功能都封装成一个300K左右大小的动态库或静态库，可以嵌入到任何应用程序中，使其具备像Nginx服务器一样强大的Web功能，也可以使用一二百行代码来调用eJet库，轻易实现一个高性能的Web服务器。

eJet Web服务器的全部代码均为作者编写，绝大部分不依赖于任何第三方代码。少数几个使用开源代码的功能包括：HTTPS安全数据传输使用了OpenSSL库；正则表达式匹配是依赖于Linux系统提供的POSIX标准的regex功能实现；gzip压缩需要依赖zlib开源库，目前没有添加进来，所以eJet Web服务器暂时不提供gzip、deflate的压缩支持。

eJet Web服务器完全构建在ePump框架之上，利用ePump框架的多线程事件驱动模型，实现完整的HTTP请求<-->HTTP响应事务流程。eJet服务器调用ePump接口，监听HTTP端口，各个worker工作线程均衡地接受客户侧的TCP连接请求，eJet接收和处理各TCP连接上的HTTP请求头和请求体，经过解析、校验、关联、实例化等处理，执行HTTP请求，或获取Web服务器特定目录下的文件，或代理客户端发起向源HTTP服务器的请求，或将HTTP请求通过FastCGI接口转发到CGI服务器，或将客户端HTTP请求交给上层设置的回调函数处理，等等。所有处理结果，最终以HTTP响应方式，包括HTTP响应头和响应体，通过客户端建立的TCP连接，返回给客户端。该TCP连接可以Pipe-line方式继续发送和接收多个HTTP请求和响应。

围绕着TCP连接上接收HTTP请求、发送HTTP响应，eJet服务器提供了作为Web服务器所需的其他各项功能，包括基于TLS/SSL的安全和加密传输、虚拟主机、资源位置Location的各种匹配策略、对请求URI执行动态脚本指令（包括rewrite、reply、return、try_files等）、在配置文件中使用HTTP变量、正向代理和反向代理、HTTP Proxy、FastCGI、HTTP Proxy Cache功能、HTTP Tunnel、MultiPart文件上传、动态库回调或接口函数回调机制、HTTP日志功能、CDN分发等等。其中HTTP Proxy、FastCGI、HTTP Cache、CDN等功能的实现又是一个long story。

eJet Web服务器采用JSon格式的配置信息设置系统配置，并对JSon语法做了一定的扩展，使得JSon支持include文件指令，支持嵌入Script脚本程序语言，通过配置文件更加灵活、方便地扩展Web服务功能。

eJet系统大量采用了Zero-Copy、内存池、缓存、合理高效的CPU并行处理等技术，来提升Web服务器处理性能和效率，加快了请求响应的处理速度，支撑更大规模的并发处理能力，支持更大规模的网络吞吐容量等。

eJet是一个库，可用寥寥几行代码调用eJet库来实现一个强大的Web服务器。eJet是个轻量级的Web服务器，总体大小区区300KB，但却是个重量级的HTTP全功能、高性能服务器模块。eJet可轻易嵌入到各种应用程序中，来增加应用程序使用HTTP通信和服务承载的能力。eJet并没有创建进程或线程，却可以利用ePump框架的线程，高效地使用服务器的CPU处理能力。

eJet Web服务器面向程序员、系统架构师提供应用程序开发接口或直接嵌入到现有系统中，也可以面向运维工程师部署完全类似Nginx Web服务器、CDN回源等商业服务系统，还是面向程序员提供学习、研究开发框架、通信系统等的理想平台。


二. eJet系统流程和工作原理
------

### 2.1 Web服务器基本功能

Web服务器，常称网站服务器，将具有独立IP地址的服务器上承载的图、文、音频、视频和数据文件等资源，以URL方式来标识，以HTTP协议对外提供下载、浏览、上传、交互等服务。HTTP协议是一个请求-响应的事务型协议，Web服务器的基本工作流程基本是围绕请求应答来完成的，具体包括：
* 建立连接 —— 接受客户端连接，或拒绝并关闭连接；
* 接收请求 —— 从网络接口中读取 HTTP 请求头和请求体；
* 处理请求 —— 对请求头和请求体进行解析；
* 访问资源 —— 访问HTTP请求指定的资源；
* 构建响应 —— 创建带有头和体的 HTTP 响应；
* 发送响应 —— 将响应回送给客户端；
* 记录日志 —— 与已完成事的内容记录在日志文件中。

eJet Web服务器也是按照上述流程来设计和实现的，在这些环节中，增加了各种应用程序或配置接口，更好地满足服务需求，及为提升服务性能而设计了很多功能模块。

### 2.2 eJet Web服务器启动流程

在启动系统时，首先为各模块分配空间和资源，解析和读取系统配置信息，初始化各模块，并构建各模块数据结构，包括：
* 初始化SSL库模块；
* 根据配置，URI在解码/编码时，设置需要进行转义处理的字符的位掩码；
* 初始化HTTP请求代理，向Origin服务器发送HTTP请求时，根据配置信息，设置Proxy地址和端口
* 初始化HTTP访问日志模块；
* 初始化HTTP连接、HTTP消息等核心数据结构，并分配内存池；
* 加载HTTP MIME数据，并初始化MIME管理模块；
* 初始化HTTP Cache缓存管理模块；
* 初始化HTTP变量和变量管理模块；
* 设置并初始化HTTP响应状态码管理；
* 初始化Origin服务器管理模块；
* 构建SSL Context上下文环境；
* 初始化HTTP Overhead流量统计模块；
* 加载并初始化FastCGI模块；
* 初始化HTTP Cookie模块；
* 根据系统配置，初始化并加载HTTP Listen监听服务、虚拟主机服务、资源定位服务模块，包括配置中设定的Script脚本、配置选项等；

### 2.3 启动监听服务

eJet系统启动HTTP监听服务时，调用ePump框架提供的接口函数eptcp_mlisten，设置事件回调函数为http_pump，那么监听端口的所有事件都会发送到http_pump中，包括TCP连接建立请求等，http_pump是eJet系统事件驱动模型的核心。

要特别说明的是ePump框架中提供的接口函数eptcp_mlisten封装了很多操作系统细节，自动识别当前操作系统是否支持REUSEPORT，以及内核级针对多线程监听时的TCP连接事件在多线程（多进程）间的负载均衡，如果支持，就启用这个内核功能，如果不支持，就启用ePump系统实现的用户态下的TCP连接事件多线程负载均衡，最终确保高效利用CPU的并发处理能力。

### 2.4 http_pump作为事件驱动核心入口

eJet系统依赖ePump多线程事件驱动框架，本身不创建线程，也不创建进程，通过ePump的事件回调机制，处理所有来自ePump的事件，这是典型的事件驱动event-driven架构。

eJet系统将http_pump设置为ePump框架的事件回调入口函数，所有底层通信设施和定时器产生的任何事件，都会送到http_pump函数来处理，函数原型如下：
```
int http_pump (void * vmgmt, void * vobj, int event, int fdtype)
```
vmgmt是HTTPMgmt实例对象，vobj是产生该事件的iodev_t设备或定时器，event是事件类型，fdtype是iodev_t的文件描述类型。

### 2.5 IOE_ACCEPT事件驱动eJet创建HTTPCon连接

eJet系统的服务起点是http_pump模块接收到客户端的TCP连接请求，即IOE_ACCEPT事件，响应该事件的处理流程是创建HTTPCon连接，保存客户端请求的各种信息，包括iodev_t socket设备对象、四元组地址、是否为SSL连接等，启动定时器来管理当前连接的寿命，并将当前TCP连接的iodev_t设备绑定到一个负载最低的epump线程中，通过该线程监听并创建该TCP连接后续各类读、写等事件。

### 2.6 IOE_READ事件驱动eJet读取请求数据

客户端发起的TCP连接接受成功后，客户端开始发送HTTP Request，eJet系统http_pump模块会收到IOE_READ事件，即http_pump会被ePump的工作线程回调执行。响应该事件的处理流程是根据回调参数得到HTTPCon实例，如果是普通的TCP连接，则调用TCP非阻塞、零拷贝接口函数，读取内核中该连接上的数据存入缓冲区，如果是SSL连接，则调用SSL接口函数完成SSL握手、认证过程，并在加密连接上读取解密过的数据存入缓冲区。

### 2.7 解析HTTP请求数据

对HTTPCon内缓冲区的数据进行解析处理，根据HTTP协议规范约定，HTTP请求头和请求体之间有两个空行即4字节\r\n\r\n，因为请求体的内容是否存在、是什么内容格式、大小等信息都包含在HTTP请求头中。首先通过快速字符串模式匹配算法，定位出缓冲区数据中是否存在\r\n\r\n，即找到HTTP Request中头信息的结尾后，对请求行、请求头进行解析。

### 2.8 创建HTTPMsg保存请求数据

创建HTTPMsg实例，保存HTTP请求的各项信息，将HTTP请求头字节流存入HTTPMsg中的req_header_stream，基于这个流，解析出HTTP Method、URL、HTTP_VERSION和所有的HTTP请求头，请求头保存在hashtab中，方便快速查找。对特定的请求头做特殊解析处理，如针对Range头，需根据Range规范解析出客户端想要目标资源的部分内容，起始位置、长度等；需根据Cookie头来解析出各个Cookie信息；Connection头表示客户端希望当前TCP连接是否为Long-lived连接；Content-Type头中，如果存在multipart内容，则需以该格式解析后续的请求体；最主要的是请求体内容的传输编码格式是什么，需要Conent-Length头或Transfer-Encoding头来决定。

要强调一下的是，请求头信息都是小碎片内存开销，eJet系统采用内存池和保存偏移量等方式，降低了使用大量碎片内存分配导致的内存使用效率风险。

针对请求行、请求头信息解析成功后，构建并设置URL绝对地址，并将当前HTTPMsg实例对象加入到HTTPCon的消息队列中。校验当前请求内容是否合法，非法或不支持的请求，直接返回404或505等错误，并终止当前HTTPCon连接。

### 2.9 设置DocURI并启动HTTPMsg资源实例化

此刻，需启动HTTPMsg请求资源实例化流程，先设置当前请求URL地址为DocURI，得到当前HTTP请求的主机名、端口、路径、Query参数等信息。在当前监听服务HTTPListen下，根据HTTP请求的主机名，利用HTTPListen和HTTPHost管理结构，找到系统配置的虚拟主机对象HTTPHost，随后根据路径名，基于当前虚拟主机下资源位置的配置规则，将当前请求路径按照精准匹配、前缀匹配、正则表达式匹配等去匹配虚拟主机下的多个资源位置HTTPLoc。匹配成功后，分别指向HTTPListen监听服务下、虚拟主机HTTPHost下、资源位置HTTPLoc下的脚本程序，脚本程序中可能会包含rewrite、try_files等导致循环嵌套执行HTTPMsg请求资源实例化的指令。注：嵌套执行的总次数不超过16次。

完成了请求内容的解析和HTTPMsg请求资源实例化后，在接收并解析请求体之前，需要做两个判断：一是判断当前请求是否采用正向代理Forward Proxy或者反向代理Reverse Proxy进行转发；二是判断当前请求是否要使用FastCGI转发。

### 2.10 Proxy代理转发

#### 2.10.1 判定是否代理转发---正向代理或反向代理

判断是否为Proxy代理转发，如果请求URI是绝对URL地址，即URL地址包含了`http://domain:port`，并且其URL中的地址不是当前主机，那么当前HTTP请求需要做正向代理转发处理，将当前地址作为正向代理转发地址。如果HTTPMsg中的资源位置HTTPLoc中在配置文件中设置了反向代理，获取配置中的反向代理URL地址，如果配置中是正则表达式匹配，则需对反向代理URL地址做正则匹配后的变量替换处理，如果不是正则表达式匹配，则从请求路径中删除掉匹配子串，剩余部分添加加到配置中的反向代理URL中。最后，将HTTP请求的query参数添加到反向代理URL后面，并最终确认为反向Proxy代理转发。

#### 2.10.2 代理请求资源是否在本地缓存里

如果是Proxy代理转发，首先检查转发的请求资源是否已经保存在本地缓存了，其方法是检查当前HTTPLoc资源位置中Cache选项是否打开、CacheFile缓存文件是否设置，如果没有HTTPLoc资源位置，判断发送HTTP请求的配置项里Cache开关和CacheFile是否设置，CacheFile一般含有HTTP变量，经过变量取值处理后的文件为缓存文件。缓存文件如果存在，则资源已在本地，否则继续检查该缓存文件对应的缓存信息管理文件CacheInfo是否存在，如果存在的话，则将当前请求的资源内容区域，与CacheInfo中已经保存的缓存区域比对，如果请求区域的内容都保存在临时缓存文件中，则请求资源已经保存在本地。

#### 2.10.3 创建代理请求消息

如果请求资源已经保存在本地缓存中，则跳过当前Proxy代理转发流程，进行下一步处理。如果不在本地缓存，则创建一个新的代理请求HTTPMsg消息，设置代理请求URL地址，将源请求HTTPMsg的请求头复制到Proxy请求的HTTPMsg中，根据CacheInfo判断，如果本地缓存中保存了一部分请求内容，那么需要从剩余的未保存内容开始，设置Range请求头，去请求未保存部分，不用重新请求已经缓存了的内容。

#### 2.10.4 打开源服务器并建立通信连接

根据请求的目标IP地址和端口，打开或创建代表Origin服务器的HTTPSrv实例，并在HTTPSrv下创建或复用一个新的TCP连接HTTPCon，将代理消息HTTPMsg交给该TCP连接来发送，并设置当前TCP连接的任何后续读写事件，都采用当前工作线程，即跟源请求的TCP连接一起都由一个worker工作线程来处理事件，以确保处理环节的连续性pipeline。

#### 2.10.5 发送代理请求到源服务器

在面向Origin服务器的代理TCP连接上发送代理HTTPMsg消息，过程比较复杂。不仅仅要转发请求头，还要把源HTTP请求的消息体转发给目标服务器。由于传输网络的抖动、延迟、请求消息体数据大小不一、传输编码差异等因素，请求消息体不一定都存储在本地缓冲区，也不一能来一个数据立即转发一个，需要做解析、碎片化发送等处理，具体算法和流程见后面章节。完成Proxy代理转发后，当前客户端HTTP请求的读事件处理完毕。

### 2.11 FastCGI转发

如果当前请求不是Proxy代理转发，则需继续判断是否为FastCGI转发。根据HTTPMsg中的资源位置HTTPLoc的配置信息，判断是否为FastCGI转发模式，如果是FastCGI转发模式，则将转发URL，即FastCGI服务器地址URL返回出来。否则跳过FastCGI转发流程。

如果是FastCGI转发，首先使用FastCGI服务器URL地址，打开或创建FastCGI主机实例FcgiSrv，随后创建FastCGI转发消息FcgiMsg，打开或创建到达FastCGI服务器的Unix Socket连接或TCP连接FcgiCon，并将该消息绑定到连接上，启动发送流程。

### 2.12 读取并解析请求体

如果当前HTTP请求消息既不是Proxy代理转发，也不是FastCGI转发，则根据请求头判断是否有后续的消息体需要读取、解析和存储等处理。如果请求头中包含Content-Length，并且值大于0，或者包含Transfer-Encoding头，则需把当前HTTPCon缓冲区内容拷贝到HTTPMsg的请求体缓冲区req_body_stream中，或者根据系统配置文件中receive request中的body cache开关，以及是否启动Cache缓存的消息体大小阈值，来决定请求体是否启用Cache缓存，如果启用了请求体缓存，并请求消息体大小也大于缓存阈值，则将当前请求体的内容都存入到缓存文件中。对于Chunk编码的消息体，需要解析解码处理。将请求体内容，无论是在内存中，还是在缓存文件里，都添加到不连续碎片存储管理结构chunk_t中。随后，根据请求头Content-Type值，对请求体内容进行处理，如果是multipart格式，则将消息体各部分的内容解析到http_form_t中，如果是urlencoded格式，则解析到kev-value键值对链表中，如果是JSon格式，则解析成JSon数据结构，而解析出来的这些内容的存储结构都是HTTPMsg对象的成员。

### 2.13 由Handler处理HTTPMsg

#### 2.13.1 校验请求方法

处理完消息头或消息体后，封装了客户端请求所有信息的HTTPMsg会交给Handler即http_msg_handle来处理。Handler判断请求Method方法，如果是CONNECT时，建立TCP隧道，并返回隧道建立结果状态，生成HTTP响应发送给客户端。如果不是系统支持的方法，如GET、POST、DELETE、PUT、HEAD、OPTIONS、TRACE等，则直接返回405错误。

#### 2.13.2 反向Proxy模式缓存内容处理

Handler处理这些请求方法时，首先判断当前请求内容是否是Proxy模式下的缓存内容，如果是缓存内容，则将缓存文件添加到用于存储响应体的不连续碎片存储管理数据结构res_chunk_body中，当客户端请求时只是部分区域内容，添加到响应体时会自动根据请求头的Range头规范，把指定区域的缓存内容添加到响应体，设置响应状态码和响应内容类型，生成HTTP响应，并启动HTTP响应的发送流程发送给客户端。

#### 2.13.3 正向Proxy模式校验

如果HTTP请求的不是Proxy模式下的缓存内容，先检查一下当前请求是不是正向代理转发，并且当前HTTPListen监听的系统配置里不允许正向代理转发，返回403错误。再检查当前HTTPMsg实例中资源位置HTTPLoc是否存在，不存在则返回404错误。

#### 2.13.4 HTTP消息应用回调和动态库回调处理

针对请求各项检查完毕后，先看看是否设置了系统级的应用回调函数，如果存在，将当前HTTP请求的HTTPMsg实例对象作为参数，执行应用级的回调函数。随后，判断该HTTPMsg是否被成功地处理并发送了HTTP响应，如果尚未发送响应，则检查当前HTTPListen是否配置了动态库回调函数，如果存在，则加载动态库并执行动态库的回调函数。

#### 2.13.5 读取并发送资源文件或路径下的缺省文件

到这里，如果该HTTP请求的HTTPMsg还没有被处理并发送响应，则根据其资源位置HTTPLoc，获取其资源文件路径，判断该路径的资源文件是否存在，如果存在，则将该文件添加到响应体的res_chunk_body中，启动HTTP响应的发送流程。如果资源文件不存在，但资源文件路径是一个目录，根据资源位置HTTPLoc下配置的缺省文件列表，逐个查找该目录下的缺省文件是否存在，如果存在，则将该文件添加到响应体的res_body_chunk中，并发送给客户端。

最后，如果该HTTP请求的HTTPMsg还没有被各级接口成功地处理和发送响应，把404错误码发给客户端，eJet不知道客户端想要什么！

### 2.14 发送响应到客户端

到此为止，客户端请求数据通过IOE_READ事件，驱动eJet服务器的全部工作流程，只剩下最后环节，发送HTTP响应给客户端，eJet系统中发送HTTP响应的入口是Reply函数。当然大量的工作是检查响应头是否完整、响应数据是否一致、状态码是否呼应了响应体内容等，需要补充添加或删除响应头等操作，完成响应头数据处理后，对响应数据进行编码。编码过程中，如果发现请求时要求响应内容进行压缩，则根据客户端支持的压缩算法，对响应体内容进行压缩处理。响应头进行编码后的字节流保存在res_stream中，并添加res_body_chunk中的最前面。调用发送函数，将res_body_chunk中的内容发送给客户端，具体细节流程参见后面章节。

### 2.15 用状态机处理不完整请求

以上IOE_READ事件驱动流程，是比较理想的通信过程，通常情况没有那么乐观，由于网络抖动、传输延迟、大并发访问等因素，会导致一个客户端请求数据（包括请求头和请求体）并不是一次性到达，也就是http_pump收到IOE_READ事件时，很多情况下是一个不完整的HTTP请求数据包，甚至多次收到IOE_READ事件并读取数据时到缓冲区时，也是不完整的，需要以上各个处理流程和环节，记录处理状态，基于有限状态自动机FSM模型，在不同状态下完成不同的处理动作。

### 2.16 设置可写通知产生IOE_WRITE事件处理网络拥塞

在调用发送函数发送数据到对方时，由于网络拥塞、带宽不足、客户端处理能力有限等因素，导致Web服务器内核的TCP发送缓冲区已满，后续数据不可写入了，需要调用ePump框架的iodev_add_notify函数，对当前TCP连接设置可写通知监听（writable readiness notification）。即ePump框架监控到该TCP连接一旦可写入数据了，ePump框架就会发送IOE_WRITE事件，驱动http_pump来执行可写入处理，依然根据回调参数得到HTTPCon实例，基于HTTPCon上当前正在发送中的HTTPMsg对象，得到该请求或响应的发送信息，继续将rex_body_chunk中的内容发送到对方，具体TCP发送流程参见后面章节。

### 2.17 利用定时器产生的IOE_TIMEOUT事件监管实例对象

在处理请求和响应时，eJet系统会启动定时器来管理实例对象的寿命周期，如创建HTTPCon对象时，会启动一个life定时器，跟踪管理当前连接的寿命，即所有数据处理完毕且没有其他数据需要处理时，该HTTPCon连接存续10秒左右后，就需要关闭，这是基于定时器来实现的业务流程。

当定时器超时后，ePump框架产生IOE_TIMEOUT事件，回调http_pump函数。根据回调参数，获取到定时器类型、定时器绑定的对象，譬如是HTTPCon连接对象还是Origin服务器HTTPSrv对象等，再分别调用各个实例对象的定时器超时处理逻辑。eJet系统定义了4类定时器，接收客户端请求的HTTPCon连接管理定时器、主动连接Origin服务器时建立的HTTPCon连接管理定时器、主动连接远程主机时以防超时的定时器、Origin服务器HTTPSrv寿命管理定时器。


三. eJet系统基本数据结构
------

eJet Web服务器系统虽然使用标准C语言编写实现的，但系统数据结构的设计遵循了面向对象思想，将管理不同功能的数据属性和操作抽象出来，封装成标准的数据结构和函数实现，以实例对象方式，将实现的各级功能模块加载驻留，并被其他模块继承或复用。

根据eJet Web服务器功能目标，围绕HTTP请求-响应基本事务流程，设计了如下基本数据结构：

* **HTTPMgmt** --- eJet管理入口
* **HTTPMsg** --- 封装请求和响应信息的HTTP消息
* **HTTPCon** --- HTTP通信连接管理
* **HTTPListen** --- HTTP监听服务
* **HTTPHost** --- HTTP虚拟主机
* **HTTPLoc** --- HTTP资源位置
* **HTTPHeader** --- HTTP头信息
* **HTTPUri** --- HTTP URI管理
* **HTTPVar** --- HTTP变量
* **HTTPLog** --- HTTP日志
* **CacheInfo** --- HTTP缓存信息管理
* **HTTPForm** --- HTTP表单管理
* **HTTPScript** --- HTTP脚本
* **HTTPSrv** --- HTTP Origin服务器管理
* **HTTPChunk** --- HTTP Chunk数据管理
* **HTTPCookie** --- HTTP Cookie数据
* **FcgiSrv** --- FastCGI服务器管理
* **FcgiCon** --- FastCGI通信连接
* **FcgiMsg** --- 封装FastCGI请求和响应的消息

### 3.1 HTTPMgmt - eJet内核

整个eJet系统使用HTTPMgmt数据结构作为统一的资源管理入口，所有的配置、内存管理、监听管理、消息、缓存等实例对象都在HTTPMgmt下。

### 3.2 HTTPMsg - 消息

每个HTTP请求和响应的事务信息由HTTPMsg实例对象来存储和管理，HTTPMsg对象内容HTTP请求的请求头、请求体、响应头、响应体、虚拟主机、资源位置、缓存、代理等信息。成功返回HTTP响应给客户端后，HTTPMsg被回收销毁。

### 3.3 HTTPCon - 通信连接

客户端发起建立的TCP连接、eJet主动对外发起HTTP请求建立的TCP连接，都是由HTTPCon数据结构来管理。HTTPCon管理TCP连接四元组地址、当前正在接收处理或排队处理的HTTPMsg列表、HTTP隧道、TCP连接iodev_t设备对象等信息；还有HTTP连接的工作状态、连接寿命等管理；最主要的是维持一个可动态扩展的接收缓冲区，接收来自对方的任何数据进行解析和处理。

### 3.4 HTTPListen - 监听服务

HTTPListen数据结构管理HTTP监听的本地地址和本地端口，是否需要SSL连接，SSL所需的证书、私钥、CA校验证书，端口监听实例对象，每个HTTPMsg产生后需进行实例化，会执行Listen级别的Script脚本，每个HTTPListen下属多个HTTPHost主机，等等。接受的HTTPCon连接和HTTPMsg消息实例，必须关联到某个HTTPListen中。

### 3.5 HTTPHost - 虚拟主机

HTTPHost代表Host虚拟主机，同一个IP地址和端口下（HTTPListen）可以有很多个虚拟主机，即可以承载很多不同域名的网站。Host主机名既可以是映射到本机IP地址的域名，也可以直接是本机IP地址，HTTP请求头中的Host值就对应相应的Host主机。HTTPHost管理的数据包括主机域名或IP地址、反向代理URL地址、访问文件系统的根路径、通过SSL的SNI机制选择不同的域名下的证书、私钥，以及管理多个HTTPLoc，对HTTPMsg实例化处理时进行URI信息的精准匹配、前缀匹配、正则表达式匹配等来确定最终的HTTPLoc，还有400-520之间错误状态码页面管理等等。

### 3.6 HTTPLoc - 资源位置

HTTPLoc代表访问资源的最终位置，通过请求URI的文档路径来唯一标识，定位资源所在的最终位置，是客户端的连接请求是哪个监听端口，就确定属于哪个HTTPListen，根据HTTP请求头的Host值，匹配出HTTPHost虚拟主机，然后根据DocURI下的请求路径，分别采用精准匹配、前缀匹配、正则表达式匹配来找到最终的HTTPLoc资源位置。HTTPLoc信息包括：匹配路径和匹配模式、资源位置类型（Server、Proxy、FastCGI）、资源根路径、代理URL、Cache文件、执行脚本等。

### 3.7 HTTPHeader - 头信息

HTTP头信息是由name和value键值对构成，中间使用冒号（：）分隔，其中Name只能是字母和下划线组成。管理每条头信息的数据结构为HTTPHeader，分别包括头信息的Name和Value信息。需要注意的是，eJet系统中HTTPHeader内的name和value都是指针，指向HTTPMsg中的header_stream，并没有分配实际存储空间，这也是Zero-Copy思想的一部分。

### 3.8 HTTPUri - 资源地址URL

对URI进行存储和解析处理的数据结构是HTTPUri，eJet系统在接收到客户端请求后，一般在HTTPMsg中有三个HTTPUri实例对象来保存三种URI，一个是请求URI，第二个是经过资源位置实例化后的DocURI，第三个是绝对URI。设置URI后，会自动地将该URI解析分解到不同的字段中，如Host、Port、Path、Query、File等。

### 3.9 HTTPVar - HTTP变量

HTTPVar变量是指在eJet服务器运行期间，可通过Script脚本程序或配置文件里动态地读取访问当前HTTP请求响应相对应的HTTPMsg实例对象内特定数据的变量，一般在配置文件、访问日志等地方需要动态地配置或使用这些变量。HTTPVar变量包括全局变量、局部变量、Location变量，变量的引用必须以$开头，后跟变量名，如果变量后面还有连续紧随的其他字符串，则需用{}来包括住变量名。

### 3.10 HTTPLog - 日志信息

每个HTTP请求和响应的信息都要写入日志文件，方便运维和其他统计系统进行处理和分析。HTTPLog数据结构保存日志文件名、文件句柄、要写入日志文件的字段列表等信息，待写入日志文件的字段采用HTTPVar变量方式，在配置文件中设定。HTTPMsg在关闭之前，将配置文件设定的这些变量内容，从HTTPMsg实例变量以及其他实例对象中提取出来，统一写入access.log日志文件中。

### 3.11 CacheInfo - 缓存信息管理

在正向代理或反向代理模式下，客户端的请求都会转移到Origin源服务器，并将Origin服务器的响应转发给客户端。大量的客户端请求，将会导致转发和转收的效率不高，需要采用HTTP Cache系统，将响应内容存储在本地。HTTP Cache存储系统是由Raw缓存文件和缓存信息管理文件组成，Raw缓存文件负责存储实际的文件介质内容，缓存信息管理文件与数据结构CacheInfo一致，每个缓存文件都有一个全局唯一的CacheInfo，管理缓存的各种信息，包括缓存文件名、缓存文件的MIME类型、文件大小、实际缓存的文件大小、缓存策略、文件创建和更新时间，最主要成员是FragPack，记录Raw缓存文件里的所有已下载碎片块存储的位置和大小，确保哪个位置区域是否保存了文件内容。系统根据CacheInfo，可精准地知道缓存文件的存储信息和存储内容读写访问。

### 3.12 HTTPForm - 表单信息

客户端采用HTTP Post方法上传多个需要用户输入的信息内容到Web服务器，包括上传本地文件等，这种情况一般采用Content-Type为multipart/form-data的内容编码方式，各内容之间用客户端随机产生的boundary字符串分隔。eJet Web服务器设计了HTTPForm数据结构来管理multipart/form-data内容的解析和存储，一般情况下，上传内容过大会自动保存到缓存文件里，HTTPForm接口函数对缓存文件进行解析，分别解构出各个字段的名称，该字段的内容在缓存文件中的位置和大小，如果该字段是文件，则记录文件名，以及该上传文件在缓存文件中的起始位置和大小。应用程序可以使用HTTPForm来访问客户端上传的各个字段名称和字段内容，如果上传的是文件，可调用HTTPForm接口，将缓存文件中相应区域的内容提取出来，写入到应用程序指定的目录中。

### 3.13 HTTPScript - 脚本程序

eJet Web服务器的配置文件采用JSon格式，在http.listen（对应HTTPListen对象）、http.listen.host（对应HTTPHost对象）、http.listen.host.location（对应HTTPLoc对象）这三种对象下，通过对JSon语法进行扩展，都可以配置增加script对象，script对象的内容格式是参考C语言语法规范的脚本程序，由eJet系统在特定时刻解释并执行。当客户端发起的每个HTTP请求到达eJet Web服务器时，eJet解析请求并创建HTTPMsg对象，HTTPMsg对象实例化过程主要是根据请求信息匹配和设定HTTPMsg自己的HTTPListen、HTTPHost、HTTPLoc，在匹配到这三个对象的那一刻，eJet系统首先会调用HTTPScript接口来解释执行这三个对象下配置的Script对象中的脚本程序。像rewrite、return、reply、try_files、if、else等指令和语法都是脚本程序的基本内容。脚本程序的动态执行使得客户端的请求，以更加灵活机动的方式被处理。

### 3.14 HTTPSrv - 源服务器

eJet Web服务器可充当HTTP客户端向远程HTTP服务器发起HTTP请求，或充当代理模式发起HTTP请求，建立的HTTPCon连接主要是根据目标IP地址和端口来区分，具有相同目的IP地址和端口的HTTPCon请求，可以复用来发送后续相同地址的HTTP请求，这是用HTTPSrv数据结构来管理这些具有相同目的IP地址和端口的HTTPCon连接，这样，HTTPSrv就代表了HTTP Origin服务器。HTTPSrv包含一个HTTPMsg请求消息队列，当有HTTP请求发送到某个HTTP Origin服务器时，直接将该请求消息添加到该队列中，HTTPSrv会在当前连接中均衡分配一个HTTPCon或创建一个新的HTTPCon，来发送该请求。

### 3.15 HTTPChunk - HTTP数据块

HTTP请求和响应的消息体Body在传输过程有两种方式来标识或编码，一种是采用Content-Length，另一种是采用Transfer-Encoding为chunked的传输编码。后者是将Body数据分成一个个Chunk数据块，每个数据块前头是16进制的数据块长度和两个换行符\r\n，chunk数据块后面再跟两个换行符\r\n，最后是以长度为0的Chunk数据块来结尾。这种编码方式特别适合不知道实际长度的内容的传输，如实时压缩的内容、直播流媒体内容等。eJet系统设计HTTPChunk数据结构来解析、存储Chunk数据块内容，尤其是连续传输的Chunk数据块因为网络抖动等原因断续接收时，需要HTTPChunk结构来跟踪Chunk块状态。

### 3.16 HTTPCookie - Cookie数据

OSI七层协议模型中，作为Transaction事务层的HTTP协议是State-less协议，并没有保存通信双方的会话状态，而是通过Cookie机制来维持Session。Web Server通过在HTTP Response头中增加Set-Cookie头来设置Cookie信息，客户端在随后的HTTP Request请求中增加Cookie头将Cookie信息携带上。Cookie内容是由很多个name/value键值对组成，同一个Cookie下不同的name/value键值对是用分号（;）隔开，应用服务器可以根据Cookie键值对来保存会话状态，譬如id、登录会话串等。在Set-Cookie规范设置Cookie时，每个Cookie的属性中必须包含Domain、Path，指定该Cookie属于哪个域名主机的哪个路径，一般还包含max-age和expires，指定该Cookie的寿命周期。eJet系统通过HTTPCookie来解析、保存和管理这些Cookie信息。

### 3.17 FcgiSrv - FastCGI服务器

HTTP请求的资源如果是PHP等内容时，eJet会启动FastCGI模块，将HTTP请求内容通过FastCGI协议发送到FastCGI服务器，如php-fpm，FastCGI服务器执行脚本程序后，将响应内容通过FastCGI协议返回给eJet Web服务器，组装成HTTP响应返回给客户端。通常FastCGI服务器跟eJet Web服务器位于同一台服务器上，与FastCGI服务器之间的通信，一般采用进程间通信IPC机制，如Unix Socket或TCP协议。eJet采用FcgiSrv数据结构来标识管理FastCGI服务器，服务器的标识一般为 unix:/dev/shm/php-cgi.sock 或 fastcgi://127.0.0.1:9000。每个FcgiSrv的角色类似HTTPSrv，代表某个FastCGI服务器，一个eJet Web服务器可以部署配置多个FastCGI服务器。每个FastCGI服务器管理FcgiMsg消息队列，建立和维持多个FastCGI协议的连接FcgiCon。

### 3.18 FcgiCon - FastCGI通信连接

通过Unix Socket或TCP协议，来承载FastCGI协议的通信服务，用FcgiCon数据结构来管理每一个可靠通信连接。首先需要维持一个通信接收缓冲区，任何来自对方的数据，通过事件通知驱动接收接口，存储在缓冲区中用于解析和处理。其次保存该连接的iodev_t对象，以及维持连接所需的定时器，当前正在发送或接收的FcgiMsg消息，或管理处于FIFO排队队列中的消息。每个FcgiCon隶属于FcgiSrv，一个FcgiSrv下有多个FcgiCon，共同均衡地承担传输任务。

### 3.19 FcgiMsg - FastCGI消息

FastCGI协议定义了传输数据规范，数据是由一个到多个FastCGI Record构成，Record都是8字节对齐，每个Record包含一个8字节长的头部，最大不超过65KB大小的可变长度消息体，最后是为了补齐8字节对齐所需的padding字节。FastCGI协议Record类型共有10种，分别为BEGIN_REQUEST、ABORT_REQUEST、END_REQUEST、PARAMS、STDIN、STDOUT、STDERR、DATA、GET_VALUES、GET_VALUES_RESULT。FcgiMsg封装了FastCGI数据规范的这些信息，对FastCGI信息内容进行解析或编码，负责传输过程中消息内容状态的跟踪记录，作为FastCGI通信接口的最基本数据传输单元。


四. eJet核心功能模块
------

### 4.1 eJet资源管理架构

#### 4.1.1 三层资源定位架构

eJet Web服务器的资源管理结构分成三层：
* **HTTP监听服务HTTPListen** - 对应的是监听本地IP地址和端口后的TCP连接
* **HTTP虚拟主机** - 对应的是请求主机名称domain
* **HTTP资源位置HTTPLoc** - 对应的是主机下的各个资源目录

一个eJet Web服务器可以启动一个到多个监听服务HTTPListen，一个监听服务下可以配置一个到多个HTTP虚拟主机，一个虚拟主机下可以配置多个资源位置HTTPLoc。这里的‘多个’没有数量限制，取决于系统的物理和内核资源限制。

#### 4.1.2 HTTP监听服务 - HTTPListen

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

HTTP监听服务HTTPListen可以设置当前监听为需要SSL的安全连接，并配置SSL握手所需的私钥、证书等。配置为SSL安全连接监听服务后，客户端发起的HTTP请求都必须是以https://开头的URL。

在HTTP监听服务HTTPListen里，可以设置Script脚本程序，执行各种针对请求数据进行预判断和预处理的指令。这些脚本程序的执行时机是在收到完整的HTTP请求头后进行的。

eJet系统提供了动态库回调机制，使用动态库回调，既可以扩展eJet Web服务器能力，也可以将小型应用系统附着在eJet Web服务器上，处理客户端发起的HTTP请求。

HTTP监听服务HTTPListen下可管理多个虚拟主机HTTPHost，采用主机名称为索引主键的hashtab来管理下属的虚拟主机表。当当前监听服务的端口收到TCP请求和数据后，根据Host请求头的主机名称，来精确匹配定位出该请求的HTTP虚拟主机HTTPHost。


#### 4.1.3 HTTP虚拟主机 - HTTPHost

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
* 精确匹配请求路径的虚拟主机表 - 以请求路径名称为索引的资源位置索引表
* 对请求路径前缀匹配的虚拟主机表 - 以请求路径前缀名称为索引的资源位置字典树
* 对请求路径进行正则表达式运算的虚拟主机表 - 对正则表达式字符串为索引建立的资源位置列表

进入当前虚拟主机后，到底采用哪个资源位置HTTPLoc，匹配规则和顺序是按照上述列表的排序来进行的，首先根据HTTP请求的路径名在资源位置索引表中精准匹配，如果没有，则对请求路径名的前缀在资源位置字典树中进行匹配检索，如果还没有匹配上，最后对资源位置列表中的每个HTTPLoc，利用其正则表达式字符串，去匹配当前请求路径名，如果还是没有匹配的资源位置HTTPLoc，那么使用当前虚拟主机的缺省资源位置。

#### 4.1.4 HTTP资源位置 - HTTPLoc

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
* 精准匹配，使用等于号'='
* 前缀匹配，使用'^~'这两个符号
* 区分大小写的正则表达式匹配，使用'~'符号
* 不区分大小写的正则表达式匹配，使用'~*'这两个符号
* 通用匹配，使用'/'符号，如果没有其他匹配，任何请求都会匹配到

匹配的优先级顺序为：
  (location =) > (location 完整路径) > (location ^~ 路径) > 
  (location ~,~* 正则顺序) > (location 部分起始路径) > (/)

eJet系统根据功能服务形式，对资源位置HTTPLoc定义了几种类型：Server、Proxy、FastCGI等，通常情况下，一个资源位置HTTPLoc只属于一种类型。

HTTP资源位置HTTPLoc都需要一个缺省的根目录，指向当前资源所在的根路径，客户端请求的路径都是相对于当前HTTPLoc下的root跟目录来定位文件资源的。对于Proxy模式，根目录一般充当缓存文件的根目录，即需要对Proxy代理请求回来的内容缓存时，都保存在当前HTTPLoc下的root目录中。

每个HTTPLoc下都会有缺省文件选项，可以配置多个缺省文件，一般设置为index.html等。使用缺省文件的情形是客户端发起的请求只有目录形式，如`http://www.xxx.com/`，这时该请求访问的是HTTPLoc的根目录，eJet系统会自动地依次寻找当前根目录下的各个缺省文件是否存在，如果存在就返回缺省文件给客户端。不过需要注意的是，eJet系统中这个流程是在设置DocURI时处理的。

HTTP资源位置如果是Proxy类型或FastCGI类型，则必须配置转发地址passurl，转发地址passurl一般都为绝对URL地址，含有指向其他服务器的domain域名，passurl的形式取决HTTPLoc资源类型。

反向代理（Reverse Proxy）就是将HTTPLoc的资源类型设置为Proxy模式，通过设置passurl指向要代理的远程服务器URL地址，来实现反向代理功能。在反向代理模式下，passurl可以是含有匹配结果变量的URL地址，这个地址指向的是待转发的下一个Origin服务器，匹配变量如果为$1、$2等数字变量，即表示基于正则表达式匹配路径时，把第一个或第二个匹配字符串作为passurl的一部分。当然passurl可以包含任何全局变量或配置变量，使用这些变量可以更灵活方便地处理转发数据。

在反向代理模式下，HTTPLoc资源位置下有一个cache开关，如果设置cache=on即打开Cache功能，则需要在当前HTTPLoc下设置cachefile缓存文件名。对于不同的请求地址，cachefile必须随着请求路径或参数的变化而变化，所以cachefile的取值设置需要采用HTTP变量，或者使用Script脚本来动态计算cachefile的取值。

HTTPLoc下一般都会部署Script脚本程序，包括rewrite、reply、try_files等，根据请求路径、请求参数、请求头、源地址等信息，决定当前资源位置是否需要重写、是否需要转移到其他地址处理等。


### 4.2 HTTP变量

#### 4.2.1 HTTP变量的定义

HTTP变量是指在eJet Web服务器运行期间，能动态地访问HTTP请求、HTTP响应、HTTP全局管理等实例对象中的存储空间里的数据，或者访问HTTP配置文件的配置数据等等，针对这些存储空间的访问，而抽象出来的名称叫做HTTP变量。

变量的引用必须以$开头，后跟变量名，如果变量名后面还有连续紧随的其他字符串，则需用{}来包括住变量名，其基本格式为：$变量名称， ${变量名称}， ${ 变量名称 }，等等

#### 4.2.2 HTTP变量的应用

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

#### 4.2.3 HTTP变量的类型和使用规则

eJet系统中，共定义了四种HTTP变量类型，分别为：
* 匹配变量 - 基于资源位置HTTPLoc模式串匹配HTTP请求路径时匹配串，通过数字变量来访问，如$1,$2等；
* 局部变量 - 由script脚本在执行过程中用set指令或赋值符号“=”设置的变量；
* 配置变量 - 配置文件中Listen、Host、Location下定义的JSon Key变量，以系统会使用到的常量定义为主；
* 参数变量 - 变量名称由系统预先定义、但值内容是在HTTPMsg创建后被赋值的变量，参数变量的值是只读不可写。

变量的使用规则符合高级语言的约定，对于同名变量，取值时优先级顺序为：
  $匹配变量 > $局部变量 > $配置变量 > $参数变量

HTTP变量的值类型是弱类型，根据赋值、运算的规则等上下文环境的变化，来确定被使用时变量是数字型、字符型等。除了匹配变量外，其他变量的名称必须是大小写字母和下划线_组合而成，其他字符出现在变量名里则该变量一定是非法无效变量。变量的定义很简单，前面加上美元符号$，后面使用变量名称，系统就会认为是HTTP变量。美元符号后的变量名称也可以通过大括号{}来跟跟其他字符串区隔。

如果变量的值内容包含多个，那么该变量是数组变量，数组变量是通过中括号[]和数字下标序号来访问数组的各个元素，如$query[1]访问是请求参数中的第一个参数的值。

匹配变量的名称为数字，以美元号$冠头，如$1,$2...，其数字代表的是使用HTTPLoc定义的路径模式串，去匹配当前HTTP请求路径时，被匹配成功的多个子串的数字序号。匹配变量的寿命周期是HTTPMsg实例化成功即准确找到HTTPLoc资源位置实例后开始，到HTTP响应被成功地发送到客户端后，HTTPMsg消息被销毁时为止。

局部变量的名称由字母和下划线组成，是script脚本在执行过程中用set指令或赋值符号“=”设置的变量，其寿命周期是从变量被创建之后到该HTTPMsg被销毁这段期间，而HTTPMsg则是用户HTTP请求到达时创建，成功返回Response后被摧毁。

配置变量是JSon格式的配置文件中定义的Key-Value对中，以Key为名称的变量，变量的值是设置的Value内容。在配置文件中位于Location、Host、Listen下定义的Key-Value赋值语句对，左侧为变量名，右侧为变量值，用$符号可以直接引用这些变量定义的内容；在Listen、Host、Location下定义的配置变量，主要是以系统中可能使用到的常量定义为主，这些常量定义也可以使用script脚本来动态定义其常量值，此外，用户可以额外定义系统配置中非缺省常量，我们称之为动态配置变量。

参数变量是系统预定义的有固定名称的一种变量类型，参数变量一般指向HTTP请求的各类信息、eJet系统定义的全局变量等。参数变量的名称是eJet系统预先定义并公布，但大部分变量的内容是跟HTTP请求HTTPMsg相关的，即不同的请求HTTPMsg，参数变量名的值也是随着变化的。一般要求，参数变量是只读不可写变量，即参数变量的值不能被脚本程序改变，只能读取访问。

#### 4.2.4 预定义的参数变量列表和实现原理

相比其他三种变量，参数变量是被使用最多、最有访问价值的变量，参数变量是系统预先定义的固定名称变量，变量的值是随着HTTP请求HTTPMsg的不同而不同。通过参数变量，配置文件中可以根据请求的信息，灵活动态地决定相关配置选项的赋值内容，从而扩展eJet服务器的能力，减少因额外功能扩展升级eJet系统的定制开销。

参数变量一般由eJet系统预先定义发布，其变量的值内容是跟随HTTP请求HTTPMsg的变化而变化，但变量名称是全局统一通用，所以参数变量也有时称为全局变量。

eJet系统预定义的参数变量如下：
* **remote_addr** - HTTP请求的源IP地址
* **remote_port** - HTTP请求的源端口
* **server_addr** - HTTP请求的服务器IP地址
* **server_port** - HTTP请求的服务器端口
* **request_method** - HTTP请求的方法，如GET、POST等
* **scheme** - HTTP请求的协议，如http、https等
* **host_name** - HTTP请求的主机名称
* **request_path** - HTTP请求的路径
* **query_string** - HTTP请求的Query参数串
* **req_path_only** - HTTP请求的只含目录的路径名
* **req_file_only** - HTTP请求路径中的文件名称
* **req_file_base** - HTTP请求路径中的文件基本名
* **req_file_ext** - HTTP请求路径中文件扩展名
* **real_file** - HTTP请求对应的真实文件路径名
* **real_path** - HTTP请求对应的真实文件所在目录名
* **bytes_recv** - HTTP请求接收到的客户端字节数
* **bytes_sent** - HTTP响应发送给客户端的字节数
* **status** - HTTP响应的状态码
* **document_root** - HTTP请求的资源位置根路径
* **fastcgi_script_name** - HTTP请求中经过脚本运行后的DocURI的路径名
* **content_type** - HTTP请求的内容MIME类型
* **content_length** - HTTP请求体的内容长度
* **absuriuri** - HTTP请求的绝对URI
* **uri** - HTTP请求源URI的路径名
* **request_uri** - HTTP请求源URI内容
* **document_uri** - HTTP请求经过脚本运行后的DocURI内容
* **request** - HTTP请求行
* **http_user_agent** - HTTP请求用户代理
* **http_cookie** - HTTP请求的Cookie串
* **server_protocol** - HTTP请求的协议版本
* **ejet_version** - eJet系统的版本号
* **request_header** - HTTP请求的头信息数组，通过带有数字下标或请求头名称的中括号来访问
* **cookie** - HTTP请求的Cookie数组，通过带有数字下标或Cookie名称的中括号来访问
* **query** - HTTP请求的Query参数数组，通过带有数字下标或参数名称的中括号来访问
* **response_header** - HTTP响应的头信息数组，通过带有数字下标或响应头名称的中括号来访问
* **datetime** - 系统日期时间数组，不带中括号是系统时间，带createtime或stamp的中括号则访问HTTPMsg创建时间和最后时间
* **date** - 系统日期数组，同上
* **time** - 系统时间，同上

随着应用场景的扩展，根据需要还可以扩展定义其他名称的参数变量。总体来说，使用上述参数变量，基本可以访问HTTP请求相关的所有信息，能满足绝大部分场景的需求。

系统中预定义的参数变量，都是指向特定的基础数据结构的某个成员变量，在该数据结构实例化后，其成员变量的地址指针就会被动态地赋值给预定义的参数变量，从而将地址指针指向的内容关联到参数变量上。

在设置预定义参数变量名时，一般需要设置关联的数据结构、数据结构的成员变量地址或位置、成员变量类型（字符、短整数、整数、长整数、字符串、字符指针、frame_t）、符号类型、存储长度等，eJet系统中维持一个这样的参数变量数组，分别完成参数变量数据的初始化，通过hashtab_t来快速定位和读写访问数组中的参数变量。
 
获取参数变量的实际值时，需要传递HTTPMsg这个数据结构的实例指针，根据参数变量名快速找到参数变量数组的参数变量实例，根据参数变量的信息，和传入的实例指针，定位到该实际成员变量的内存指针和大小，从内存中取出该成员变量的值。
 

### 4.3 HTTP Script脚本

#### 4.3.1 HTTP Script脚本定义

eJet系统在配置文件上扩展了Script脚本语言的语法定义，对JSon语法规范进行扩展，定义了一套符合JavaScript和C语言的编程语法，并提供Script脚本解释器，实现一定的编程和解释执行功能。

Script脚本是由一系列符合定义的语法规则而编写的代码语句组成，代码语句风格类似Javascript和C语言，每条语句由一到多条指令构成，并以分号;结尾。

#### 4.3.2 Script脚本嵌入位置

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
 
#### 4.3.3 Script脚本范例

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

#### 4.3.4 Script脚本语句

script脚本是由一系列语句构成的程序，语法类似于JavaScript和C语音，主要包括如下语句：
 
##### 4.3.4.1 条件语句

条件语句主要以if、else if、else组成，基本语法为：
```
     if (判断条件) { ... } else if (判断条件) { ... } else { ... }
```

判断条件至少包含一个变量或常量，通过对一个或多个变量的值进行判断或比较，取出结果为TRUE或FALSE，来决定执行分支，判断条件包括如下几种情况：
* (a) 判断条件中只包含一个变量；
* (b) 判断条件中包含了两个变量；
* (c) 文件或目录属性的判断；
 
判断比较操作主要包括：
* (a) 变量1 == 变量2，判断是否相等，两个变量值内容相同为TRUE，否则为FALSE
* (b) 变量1 != 变量2，判断不相等，两个变量值内容不相同为TRUE，否则为FALSE
* (c) 变量名，判断变量值，变量定义了、且变量值不为NULL、且变量值不为0，则为TRUE，否则为FALSE
* (d) !变量名，变量值取反判断，变量未定义，或变量值为NULL、或变量值为0，则为TRUE，否则为FALSE
* (e) 变量1 ^~ 变量2，变量1中的起始部分是以变量2开头，则为TRUE，否则为FALSE
* (f) 变量1 ~ 变量2，在变量1中查找变量2中的区分大小写正则表达式，如果匹配则为TRUE，否则为FALSE
* (g) 变量1 ~* 变量2，在变量1中查找变量2中的不区分大小写正则表达式，如果匹配则为TRUE，否则为FALSE
* (h) -f 变量，取变量值字符串对应的文件存在，则为TRUE，否则为FALSE
* (i) !-f 变量，取变量值字符串对应的文件不存在，则为TRUE，否则为FALSE
* (j) -d 变量，取变量值字符串对应的目录存在，则为TRUE，否则为FALSE
* (k) !-d 变量，取变量值字符串对应的目录存在，则为TRUE，否则为FALSE
* (l) -e 变量，取变量值字符串对应的文件、目录、链接文件存在，则为TRUE，否则为FALSE
* (m) !-e 变量，取变量值字符串对应的文件、目录、链接文件不存在，则为TRUE，否则为FALSE
* (n) -x 变量，取变量值字符串对应的文件存在并且可执行，则为TRUE，否则为FALSE
* (o) !-x 变量，取变量值字符串对应的文件不存在或不可执行，则为TRUE，否则为FALSE
 
##### 4.3.4.2 赋值语句

赋值语句主要由set语句构成，eJet系统中局部变量的创建和赋值是通过set语句来完成的。其语法如下：
```
          set $变量名  value;
```
 
##### 4.3.4.3 返回语句

返回语句也即是return语句，将script闭合标签内嵌入的Scirpt脚本代码执行运算后的结果，或Key-Value对中Value内嵌的脚本程序，解释执行后的结果返回给Key变量，基本语法为：
```
          return $变量名;
          return 常量;
```

其使用形态如下：
```
          cache file = <script> if ($user_agent ~* "MSIE") return $real_file; </script>;
```

##### 4.3.4.4 响应语句

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
 
##### 4.3.4.5 rewrite语句

eJet系统中的URL重写是通过Script脚本来实现的，分别借鉴了Apache和Nginx的成功经验。

rewrite语句实现URL重写功能，当客户HTTP请求到达Web Server并创建HTTPMsg后，分别依次执行Listen、Host、Location下的script脚本程序，rewrite语句位于这些script脚本程序之中，rewrite语句会改变请求DocURL，一旦改变请求DocURL，在依次执行完这些script脚本程序之后，继续基于新的DocURL去匹配新的Host、Location，并继续依次执行该Host、Location下的script脚本程序，如此循环，是否继续循环执行，取决于rewrite的flag标记。
 
rewrite基本语法如下：
```
           rewrite regex replacement [flag];
```
 
执行该语句时是用regex的正则表达式去匹配DocURI，并将匹配到的DocURI替换成新的DocURI（replacement），如果有多个rewrite语句，则用新的DocURI，继续执行下一条语句。
 
flag标记可以沿用Nginx设计的4个标记外，还增加了proxy或forward标记。其标记定义如下：
* (a) last
    * 停止所有rewrite相关指令，使用新的URI进行Location匹配。
* (b) break
    * 停止所有rewrite相关指令，不再继续新的URI进行Location匹配，直接使用当前URI进行HTTP处理。
* (c) redirect
    * 使用replacement中的URI，以302重定向返回给客户端。
* (d) permament
    * 使用replacement中的URI，以301重定向返回给客户端。
* (e) proxy | forward
    * 使用replacement中的URI，向Origin服务器发起Proxy代理请求，并将Origin请求返回的响应结果返回给客户端。
 
由于reply语句功能很强大，rewrite中的redirect和permament标记所定义和实现的功能，基本都在reply中实现了，这两个标记其实没有多大必要。
 
rewrite使用案例如下：
```
           rewrite  ^/(.*) https://www.ezops.com/$1 permanent;
 
           rewrite ^/search/(.*)$ /search.php?p=$1?;
           请求的URL: http://xxxx.com/search/some-search-keywords
           重写后URL: http://xxxx.com/search.php?p=some-search-keywords
 
           rewrite ^/user/([0-9]+)/(.+)$ /user.php?id=$1&name=$2?;
           请求的URL: http://xxxx.com/user/47/dige
           重写后URL: http://xxxx.com/user.php?id=47&name=dige
 
           rewrite ^/index.php/(.*)/(.*)/(.*)$ /index.php?p1=$1&p2=$2&p3=$3?;
           请求的URL: http://xxxx.com/index.php/param1/param2/param3
           重写后URL: http://xxxx.com/index.php?p1=param1&p2=param2&p3=param3
 
           rewrite ^/wiki/(.*)$ /wiki/index.php?title=$1?;
           请求的URL：http://xxxx.com/wiki/some-keywords
           重写后URL：http://xxxx.com/wiki/index.php?title=some-keywords
 
           rewrite ^/topic-([0-9]+)-([0-9]+)-(.*)\.html$ viewtopic.php?topic=$1&start=$2?;
           请求的URL：http://xxxx.com/topic-1234-50-some-keywords.html
           重写后URL：http://xxxx.com/viewtopic.php?topic=1234&start=50
 
           rewrite ^/([0-9]+)/.*$ /aticle.php?id=$1?;
           请求的URL：http://xxxx.com/88/future
           重写后URL：http://xxxx.com/atricle.php?id=88
 ```

在eJet系统中，replacement后加？和不加？是有差别的，加？意味着query参数没了，不加则会自动把源URL中的query串（?query）添加到替换后的URL中。
 
##### 4.3.4.6 addReqHeader语句

特定情况下，需要对客户端请求消息添加额外的请求头，交给后续处理程序，如应用层处理程序、PHP程序、Proxy、Origin服务器等等，来处理或使用到这些信息。譬如在作为HTTP Proxy功能时，发送给远程Origin服务器的请求中都需要添加两个请求头：一个是X-Real-IP，另一个是X-Forwarded-For，使用本语句可以很方便地实现了。
 
其基本语法为：
```
          addReqHeader  <header name>  <header value>;
```
<header name>不能是空格字符，以字母开头后跟字母、数字和下划线_的字符串，可以用双引号圈定起来；
<header value>是任意字符串，可以以引号包含起来，字符串中可包含变量。
 
使用案例如下：
```
            if ($proxied) {
                addReqHeader X-Real-IP $remote_addr;
                addReqHeader X-Forwarded-For $remote_addr;
            }
```
 
##### 4.3.4.7 addResHeader语句

其基本语法为：
```
          addResHeader  <header name>  <header value>;
``` 
 
##### 4.3.4.8 delReqHeader语句

其基本语法为：
```
          delReqHeader  <header name>;
```
 
##### 4.3.4.9 delResHeader语句

其基本语法为：
```
          delResHeader  <header name>;
``` 

##### 4.3.4.10 try_files 语句

try_files 是一个重要的指令，建议位于Location、Host下面。使用该指令，依次测试列表中的文件是否存在，存在就将其设置DocURI，如不不存在，则将最后的URI设置为DocURI，或给客户端返回状态码code。
 
try_files基本语法如下：
```
            try_files file ... uri;
        或
            try_files file ... =code;
``` 

##### 4.3.4.11 注释语句

Script脚本程序中，如果一行除去空格字符外，以#号打头，那么当前行为注释行，不被解释器解释执行；另外通过C语言代码块注释标记 /*  xxx  */也被eJet系统采用。


#### 4.3.5 Script脚本解释器

eJet系统在处理HTTPMsg的实例化过程中，成功定位到HTTPHost、HTTPLoc等资源位置后，开始解释执行这三个层级资源管理框架下的脚本程序，执行的顺序依次为HTTPListen、HTTPHost、HTTPLoc下的Script脚本程序。

eJet系统的Script解释器是逐行逐字进行扫描和识别，提取出Token后，分别匹配上述语句指令，再递归根据各个语句的扫描、识别和处理。这里细节不做描述！


### 4.4 JSon格式的系统配置文件

#### 4.4.1 JSON语法特点

JSON的全称是JavaScript Object Notation，是一种轻量级的数据交换格式。JSON的文本格式独立于编程语言，采用name:value对存储名称和数据，可以保存数字、字符串、逻辑值、数组、对象等数据类型，是理想的数据交换语法格式，简洁干练，易于扩展、阅读和编写，也便于程序解析和生成。

正是由于JSon语法的简单和强扩展性、采用可保存各种数据类型的name/value对语法、可嵌套JSON子对象等特性，与配置文件的配置属性特别吻合，所以，eJet系统使用JSon格式来保存、传递、解析系统配置文件。

#### 4.4.2 eJet配置文件对JSON的扩展

##### 4.4.2.1 分隔符

eJet系统使用adif中的JSon库来解析、访问配置文件信息。JSon语法缺省格式以冒号(:)来分隔name和value，以单引号(')或双引号(")来包含name和value串，以逗号(,)作为name/value对的分隔符，以中括号[]表示数组，以大括号{}表示对象。

eJet系统采用JSon作为配置文件语法规范，为了兼容传统配置文件的编写习惯，将JSon基础语法做了一些扩展，即分隔name与value的冒号(:)换成等于号(=)，分隔name/value对之间的逗号(,)换成分号(;)，其他基础语法不变。

##### 4.4.2.2 include指令

由于配置信息数据较大，需要使用不同的文件来保存不同的配置信息，借鉴C语言/PHP语言的include宏指令，eJet系统的JSon语法引入了include指令。扩展语法中将把"include"作为JSon语法的关键字，不会被当做对象名称和值内容来处理，而是作为嵌入另外一个文件到当前位置进行后续处理的特殊指令。其语法规范如下：
```
    include <配置文件名>;
```
解析JSon内容时，如果遇到include指令，就将include指令后面的文件内容加载到当前指令位置，作为当前文件内容的一部分，进行解析处理。

##### 4.4.2.3 单行注释和多行注释

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

##### 4.4.2.4 script语法

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

#### 4.4.3 eJet配置文件

基于对JSon的扩展，eJet系统使用了JSon风格的配置文件，下面是一个实际部署eJet系统的配置文件样例：
```
/* max FD number allowed open in a process */
rlimit nofile =  65535;
 
pid lock file = /var/lock/subsys/ejet.pid;
 
epump = {
    event notification = epoll; #select
    epump threads = 3;
    worker threads = 20;
}
 
http = {
    /* ! * ' ( ) ; : @ & = + $ , / ? # [ ] */
    url not escape char = "-_.~!*'();:@&=+$,/?#][";
 
    cookie file = ./cookie.txt;
 
    include mime.types;
    include 8091_upload.conf;
 
    access log = {
        log2file = on;
        log file = /var/log/ejet-access.log;
 
        format = [ '$remote_addr', '-', '[$datetime[stamp]]', '"$request"', 
                   '"$request_header[host]"', '"$request_header[referer]"', '"$http_user_agent"',
                   '$status', '$bytes_recv', '$bytes_sent'
                 ];
    }
 
    receive request = {
        max header size = 32K;
 
        #if body-length is greater thant it, body will be saved to cache file
        body cache = on;
        body cache threshold = 64K;  
 
        keepalive timeout = 10;
        connection idle timeout = 10;
        header idle timeout = 10;
        header timeout = 30;
        request handle timeout = 180;
    } 
 
    send request = {
        max header size = 32K;
 
        connecting timeout = 8;
        keepalive timeout = 3;
        connection idle timeout = 180;
 
        /* if request is sending by https:// */
        ssl certificate = cert.pem;
        ssl private key = cert.key;
        ssl ca certificate = cacert.pem;
 
        /* if request HTTPMsg existing Location, Location->root is in place */
        root = /opt/ejet;
        cache = on;
        cache file = <script>
                       if ($req_file_only)
                           return "${host_name}_${server_port}${req_path_only}${req_file_only}";
                       else
                           return "${host_name}_${server_port}${req_path_only}index.html";
                     </script>;
 
        /* next proxy host and port when sending http request */
        proxy setting = {
            /* left-side is regular express to request host:port, right-side is proxy host and port */
            ^(.+)sina.com.cn$ = 214.147.4.5:8080;
        };
    } 
 
    proxy = {
        connect tunnel = on;
        tunnel keepalive timeout = 30;
        auto redirect = on;
 
        buffer size = 256k;
    }
 
    listen = {
        local ip = *;
        port = 443;
        forward proxy = off;
 
        ssl = on;
        ssl certificate = cert.pem;
        ssl private key = cert.key;
        ssl ca certificate = cacert.pem;
 
        host = {
            host name = *; #www.downsha.com
            type = server;
 
            location = {
                type = server;
                path = [ "(\.(.+)$)|/", "~*" ];
 
                root = /opt/ejet;
                index = [ index.html, index.htm ];
                expires = 30D;
            }
        }
    }
 
    listen = {
        local ip = *;
        port = 80;
        forward proxy = on;
 
        #request process library = reqhandle.so
 
        script = {
            addResHeader X-Nat-IP $remote_addr;
        }
 
        host = {
            host name = cache1.cdn.yunzhai.cn;  #DNS dynamically resolving
 
            location = {
                type = proxy;
                path = [ "(\.(.+)$)|/", "~*" ];
 
                passurl = http://cdn.yunzhai.cn;  #origin server
                root = /opt/ejet;
                cache = on;

                script = {
                    if ($query[fid])
                        cache file = $real_path$query[fid]$req_file_ext;
                    else if ($req_file_only)
                        cache file = $real_path$req_file_only;
                    else if ($query[0])
                        cache file = ${real_path}index.html;
                    else
                        cache file = ${real_path}index.html;
                };
                <script>
                    rewrite ^(.*)\.php$ http://vcloud.yunzhai.cn/cdn/$1 forward;
                </script>;
            }
        }
 
        host = {
            host name = *; #www.downsha.com
            type = server | proxy | fastcgi;
            gzip = on;
            root = /data/webroot/wordpress;
 
            error page = {
                400 = 400.html; 401 = 401.html; 402 = 402.html; 403 = 403.html;
                404 = 404.html; 405 = 405.html; 406 = 406.html; 500 = 500.html;
                501 = 501.html; 502 = 502.html; 503 = 503.html; 504 = 504.html;
                root = /opt/ejet/errpage;
            }
 
            /*  =   表示精确匹配
                ' ' 空格开头，表示以该字符串为前缀的匹配，不是正则匹配
                ^~  表示uri以某个常规字符串开头，不是正则匹配
                ~   表示区分大小写的正则匹配;
                ~*  表示不区分大小写的正则匹配
                /   通用匹配, 如果没有其它匹配,任何请求都会匹配到
 
                匹配的优先级顺序为：
                    (location =) > (location 完整路径) > (location ^~ 路径) > 
                    (location ~,~* 正则顺序) > (location 部分起始路径) > (/)
             */
 
            location = {
                type = server;
                path = [ "\.(h|c|apk|gif|jpg|jpeg|png|bmp|ico|swf|js|css)$", "~*" ];
 
                root = /data/webroot/httpdoc;
                index = [ index.html, index.htm ];
            }
 
            location = {
                type = fastcgi;
                path = [ "\.(php|php?)$", '~*'];
 
                passurl = unix:/run/php-fpm/www.sock;
                index = [ index.php ];
            }
 
            location = {
                path = [ '/admin/', '^~' ];
                type = proxy;
                passurl = http://admin.doansha.com/;
 
                script = {
                    rewrite ^/xxx/([0-9]+)/.*$ /pump.so?id=$1;
                };
            }
 
            location = {
                path = [ '^/view/([0-9A-Fa-f]{32})$', '~*' ];
                type = proxy;
                passurl = http://cdn.yunzhai.cn/view/$1;
 
                script = {
                    addReqHeader X-Forwarded-For $remote_addr;
                    addReqHeader X-Real-IP2 $remote_addr;
                };

                root = /opt/cache/;
                cache = on;
                cache file = /opt/cache/${request_header[host]}/view/$1;
            }
 
            location = {
                path = [ '/topic-([0-9]+)-([0-9]+)-(.*)\.html$', '~*' ];
                type = proxy;
                passurl = https://ke.test.ejetsrv.com/bbs.so?topic=$1&start=$2;
            }
 
            location = {
                path = [ '/' ];
                type = server;
 
                script = {
                    try_files $uri $uri/ /index.php?$query_string;
                };
 
                #root = .;
                index = [ index.php, index.html, index.htm ];
            }
        }
    }
 
    fastcgi = {
        connecting timeout = 10;
        keepalive timeout = 30;
        connection idle timeout = 90; 
        fcgi server alive timeout = 120;
 
        buffer size = 256k;
 
        params = {
            SCRIPT_FILENAME   = $document_root$fastcgi_script_name;
            QUERY_STRING      = $query_string;
            REQUEST_METHOD    = $request_method;
            CONTENT_TYPE      = $content_type;
            CONTENT_LENGTH    = $content_length;
 
            SCRIPT_NAME       = $fastcgi_script_name;  #脚本名称   
            REQUEST_URI       = $request_uri;          #请求的地址带参数  
            DOCUMENT_URI      = $document_uri;         #不带Query参数
            DOCUMENT_ROOT     = $document_root;        #在Location配置中root的值   
            SERVER_PROTOCOL   = $server_protocol;      #协议HTTP/1.0或HTTP/1.1
            REQUEST_SCHEME    = $scheme;
 
            
            GATEWAY_INTERFACE = CGI/1.1;               # FastCGI/1.0;           #CGI/1.1  cgi 版本  
            SERVER_SOFTWARE   = ejet/$ejet_version;    #ejet 版本号，可修改、隐藏  
            
            REMOTE_ADDR       = $remote_addr;          #客户端IP  
            REMOTE_PORT       = $remote_port;          #客户端端口  
            SERVER_ADDR       = $server_addr;          #服务器IP地址  
            SERVER_PORT       = $server_port;          #服务器端口  
            SERVER_NAME       = $host_name;            #服务器名，在Host配置中指定的host name
 
            # PHP only, required if PHP was built with --enable-force-cgi-redirect  
            REDIRECT_STATUS   = 200;  
        }
    };
 
    gzip = {
        min length = 1k;
        buffer = 64k;
        compress level = 2;
        http version = 1.1;
        types = [ text/plain, application/x-javascript, text/css, application/xml ];
        vary = on;
    }
}
```

### 4.5 事件驱动流程 http_pump

eJet系统是建立在ePump框架之上的Web服务器，eJet是ePump的事件驱动框架（Event-Driven Architecture）的回调应用。ePump框架基于事件监听机制，产生网络监听事件、网络读事件、网络写事件、连接成功事件、定时器超时事件等，并将事件均衡派发到各个工作线程中，通过工作线程来回调eJet的处理函数，这种通过设备监听、产生事件、以事件驱动工作线程来回调应用接口函数的流程，就是事件驱动架构模型。

驱动eJet工作的ePump事件包括如下：
```
    /* event types include getting connected, connection accepted, readable,
     * writable, timeout. the working threads will be driven by these events */
    #define IOE_CONNECTED        1
    #define IOE_CONNFAIL         2
    #define IOE_ACCEPT           3
    #define IOE_READ             4
    #define IOE_WRITE            5
    #define IOE_INVALID_DEV      6
    #define IOE_TIMEOUT          100
    #define IOE_USER_DEFINED     10000
```

eJet系统中处理这些事件的回调函数是http_pump，其原型如下：
```
int http_pump (void * vmgmt, void * vobj, int event, int fdtype)
```

其中fdtype是产生这些事件的文件描述符类型、定时器等，其定义如下：
```
    /* the definition of FD type in the EventPump device */
    #define FDT_LISTEN            0x01
    #define FDT_CONNECTED         0x02
    #define FDT_ACCEPTED          0x04
    #define FDT_UDPSRV            0x08
    #define FDT_UDPCLI            0x10
    #define FDT_USOCK_LISTEN      0x20
    #define FDT_USOCK_CONNECTED   0x40
    #define FDT_USOCK_ACCEPTED    0x80
    #define FDT_RAWSOCK           0x100
    #define FDT_FILEDEV           0x200
    #define FDT_TIMER             0x10000
    #define FDT_USERCMD           0x20000
    #define FDT_LINGER_CLOSE      0x40000
    #define FDT_STDIN             0x100000
    #define FDT_STDOUT            0x200000
```

eJet系统没有创建任何线程和进程，却能充分利用CPU执行全部HTTP请求和响应的所有流程，完全是被动的，即被这些事件所驱动。

启动ePump的事件驱动，首先需要根据eJet系统的需求，调用ePump框架提供的API，创建相应的iodev_t设备对象和iotimer_t定时器对象，只有这些对象才会被ePump框架监控和触发，从而产生相应的事件，驱动eJet工作。

eJet系统中调用ePump创建事件源的几个API函数如下：
```
/* Note: automatically detect if Linux kernel supported REUSEPORT. 
   if supported, create listen socket for every current running epump threads
   and future-started epump threads.
   if not, create only one listen socket for all epump threads to bind. */
void * eptcp_mlisten (void * vpcore, char * localip, int port, void * para,
                      IOHandler * cb, void * cbpara);

void * eptcp_accept (void * vpcore, void * vld, void * para, int * retval,
                     IOHandler * cb, void * cbpara, int bindtype);
 
void * eptcp_connect (void * vpcore, char * ip, int port,
                      char * localip, int localport, void * para,
                      int * retval, IOHandler * cb, void * cbpara);

void * iotimer_start (void * vpcore, int ms, int cmdid, void * para,
                      IOHandler * cb, void * cbpara);
```

eJet系统完全依赖于ePump极其高效的多线程调度机制，充分利用ePump框架对多核CPU并行处理的调用，使得eJet系统具备支撑大并发、大容量访问的物理基础。

### 4.6 HTTP请求和响应

HTTP请求和响应构成HTTP消息，从客户端发送给服务器端的HTTP消息是HTTP请求，从服务器端到客户端的消息是HTTP响应。HTTP请求和响应的消息格式的格式包括一个起始行、0个或者多个Header字段、一个空行、可能消息体。

#### 4.6.1 HTTP请求格式

按照[RFC 2616](https://datatracker.ietf.org/doc/rfc2616/?include_text=1)规范，HTTP请求消息包括请求行、请求头、消息体，具体格式如下：
```
    Method SP Request-URI SP HTTP-Version CRLF
    *(( general-header | request-header | entity-header ) CRLF)
    CRLF
    [ message-body ]
其中
    Method = "OPTIONS" | "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "TRACE" | "CONNECT"
    Request-URI    = "*" | absoluteURI | abs_path | authority
    HTTP-Version   = "HTTP" "/" 1*DIGIT "." 1*DIGIT
    http_URL = "http:" "//" host [ ":" port ] [ abs_path [ "?" query ]]
```
HTTP请求消息的三部分：请求行、请求头、消息体，前两部分都是纯文本内容，头与体之间由一个空行\r\n隔开。请求行由三部分构成：请求方法、请求URI地址、协议版本。请求URL地址是标识资源位置的定位符，其基本格式为：<协议>://<主机>:[端口]/<路径>?[参数]

#### 4.6.2 HTTP响应格式

按照RFC 2616规范，HTTP响应消息包括状态行、响应头、响应体，具体格式如下：
```
    HTTP-Version SP Status-Code SP Reason-Phrase CRLF
    *(( general-header | response-header | entity-header ) CRLF)
    CRLF
    [ message-body ]
其中
    HTTP-Version   = "HTTP" "/" 1*DIGIT "." 1*DIGIT
```
响应行中的状态码是由3个整型数字构成，状态原因短语是对状态码的简要文字描述。状态码中的第一位代表响应状态的类别，后两位是此类状态的原因，共有五类状态：
* 1xx - 信息，表示请求已收到，继续处理中
* 2xx - 成功，表示请求已成功接收、理解和处理
* 3xz - 重定向，表示请求需要导向到其他地址处理
* 4xx - 客户侧错误，表示请求语法错误、或不能正确理解
* 5xx - 服务侧错误，表示服务器未能处理请求

#### 4.6.3 头和体的解析与编码

eJet从对方接收HTTP请求或响应的字节流时，首先需要解析起始行、头信息，根据这些信息，再判断消息体内容是否存在，如果存在其大小和格式是什么。

根据上述规范，在头和体之间有一个空行，加上前面的换行符号，这四个字符\r\n\r\n就是头部区域的结尾，eJet当作是头部结尾符。解析过程首先要做的是搜索接收缓冲区字节流是否存在这四个字符，如果不存在，就继续等待接收数据到缓冲区，直到遇到这四个结尾符。这个过程需要做错误判断，如果接收缓冲区总长度超过32K字节，还没有收到头部结尾符，则任务客户端发起错误的、恶意的HTTP请求，直接关闭连接。

找到结尾符后，如果不存在HTTPMsg实例，先创建HTTPMsg实例，对结尾符之前的字节流内容按照上述规范进行解析，并保存到HTTPMsg对象成员中，对于HTTP请求，则包括请求方法、请求URI地址、协议版本、所有的请求头等，对于HTTP响应，包括协议版本、状态码、状态原因、响应头等，解析成功后，需分析和预处理这些数据，进行合规性校验和判断。

HTTPMsg对头信息的管理是采用hashtab和动态数组arr_t，方便快速定位和遍历，每个头信息基础数据结构为HeaderUnit，保存的是偏移地址和长度，并没有为每个头分配空间，以防止大量的内存碎片。

HTTPMsg在处理中，eJet系统或上层回调函数都可以根据需要，添加额外的请求头和响应头，发送给对方。

编码过程主要是对HTTPMsg中保存的起始行、动态数组中的头信息按照规范生成以\r\n分隔的文本格式的字节流。

对消息体的解析和编码比较复杂，消息体格式分成三个层级，第一层是传输编码，第二层是内容编码，第三层内容类型编码。

传输编码一般采用Content-Length头来标识的消息体Entity内容的长度，或采用Transfer-Encoding: chunked方法对消息体进行切片分块编码，这两种方法是HTTP/1.1中对消息体在传输之前采用的标准传输方式。

Content-Length方式比较简单，将实际消息体长度指定到头中，消息体内容跟在编码完的头信息之后，顺序传输给对方。

Transfer-Encoding传输编码的样例格式如下：
```
        Chunk format as following:
         24E5CRLF            #chunk-sizeCRLF  (first chunk begin)
         24E5(byte)CRLF      #(chunk-size octet)CRLF
         38A1CRLF            #chunk-sizeCRLF  (another chunk begin)
         38A1(byte)CRLF      #(chunk-size octet)CRLF
         ......              #one more chunks may be followed
         0CRLF               #end of all chunks
         X-bid-for: abcCRLF  #0-more HTTP Headers as entity header
         .....               #one more HTTP headers with trailing CRLF
         CRLF
```
对Transfer-Encoding: Chunk模式的解析，eJet系统是用HTTPChunk数据结构和函数来实现的。

传输过程中，最棘手的问题是收到的消息内容不完整，而且内存不够大时，这些内容分别存储在不同的地方，如有些存储在内存中，有些存储在缓存文件中。

### 4.7 HTTPMsg的实例化流程

    创建HTTPMsg后确定Host、Location并解析和执行script脚本程序的过程，叫HTTPMsg的实例化instance，完成实例化后
    方可进行后续的处理操作。

    Script脚本执行的时机是在引用该变量或当HTTPMsg刚开始创建时，针对配置信息，对HTTPMsg内的相关属性信息进行
    实例化，其中最主要的是基于请求URL（req_path）对配置文件中的Host、Location进行匹配，通过设定的匹配规则计
    算当前请求使用哪个Host和Location，确定Host后Location后，如果该Listen、Host、Location中设定了script脚本程
    序，则需解析并执行该Listen、Host和Location下的script脚本程序。利用Host、Location内定义的参数，可设置或改
    变当前HTTPMsg内部成员变量的值，而当需要根据请求信息（如IP地址、终端类型、特定请求头、请求目的URL等）动态
    设置或改变成员变量值或相关属性配置时，则需要script脚本程序。

### 4.8 HTTP MIME管理


### 4.9 HTTP URI管理
  RequestURI、DocURI、AbaURI


### 4.10 chunk_t数据结构
  解决不同存储介质上的不连续碎片数据融合读写访问
  实现高性能HTTP超大文件的上传下载
  更低的内存使用

 基础库中chunk_t这个数据结构是对不连续的碎片数据存储进行管理，提供连续顺序的访问接口来读写数据。主要用途
    是处理HTTP请求和响应时，动态添加请求体或响应体的数据，这些数据包括内存指针型的数据，如HTTP头数据、XML
    数据、JSon数据、读数据库时返回的数据等，还包括文件数据，如图片文件、HTML文件等，或者文件的一部分数据。
    尤其是在处理HTTP请求时，该返回的响应体来自上层应用的处理，需要动态地发送字节数据块，都是不连续的内容。
 
    这种情况特别适合chunk_t数据结构来解决。
 
    往chunk_t中动态追加的数据块，需要及时地发送出去，Linux提供了与chunk_t相对应的系统调用writev，多个缓冲区
    写到内核，一次系统调用就能解决多缓冲区发送问题，比多次调用write逐个地发送多个缓冲区的效率高很多。另外
    Linux提供了sendfile系统调用，是零拷贝Zero-Copy技术的主要系统调用，可以将chunk_t中的文件数据采用最高效的
    零拷贝技术发送出去。
 
    使用这两个系统调用，通过TCP来发送chunk_t中的数据，我们专门开发了一个函数接口:
        int chunk_vec_get (void * vck, int64 offset, chunk_vec_t * pvec, int httpchunk)
    可以多次地调用，拿到满足调用writev时入口参数所需的顺序存储的多个碎片块内存，和文件，来分别调用writev和
    sendfile发送数据。


    chunk_t是实现很多碎片数据块、不连续数据块，进行统一的、序列化的、连续性管理的基本数据结构，碎片数据内容可以
    来自内存块、文件、回调接口函数等。碎片数据块、不连续数据块的应用场景包括：
    （1）在需要大量大块内存做数据存储时，由于大并发所需的大量大块内存分配导致内存资源不足，需借助文件作为缓存来
         将内存数据存储到外存中，这样导致内存数据、外存数据混合在一起进行检索、查询、遍历、读写等操作；
    （2）为减少通信收发过程中数据的频繁拷贝、应用程序在处理请求时需从不同接口写数据如（内存写入部分数据、从DB写
         入部分数据等），而需将多个不连续的数据接收存储块合在一起，进行检索、查询、遍历、读写处理；
    （3）由于网络波动、CPU和网卡接口处理异步性等原因，调用内核read接口读取网络数据时，每次读取的数据大小不一样、
         数据读取时机也是随机的，那么对数据的处理可能不连贯，如需要读到\r\n\r\n这四个字节时，才认为HTTP头全部收
         到，并才可以进行头信息解析处理，在未收到这四个字节前，数据每次到达和到达大小的随机性，需要一个缓存来连
         续累积保存这些字节流，方便收全相关字节流后统一处理。为了提升效率，尽可能零拷贝，那么将接收到的内存块移
         出来，合在一起，进行连续性的操作；
    这些功能是由chunk_t负责实现，随意添加任意内存块数据（已分配的、未分配要求分配的）、文件数据（文件名、FILE文
    件指针、FD文件描述符）或文件中的部分数据、回调函数界定的数据等，这些数据按照添加的顺序，进行统一管理，提供
    按照序号逐一访问每一个字节、制定偏移量访问内容块、模式匹配查找检索、指定偏移和范围写入到第三方文件和Socket
    中、遍历和跳转等。
 
    基于chunk_t数据结构，借助其文件存储管理功能，可以方便地实现HTTP超大文件的上传，内存数据转存到临时文件中，从
    而消耗内存会非常的低。可以采用零拷贝技术实现网络数据从内核模式和用户模式之间的交互，等等.


### 4.11 HTTP请求/响应的发送流程（writev/sendfile）


### 4.12 使用writev和sendfile提升发送效率


### 4.13 eJet日志系统

 日志文件模块 --- 每个HTTP请求和响应的信息很多，决定哪些内容写入access.log是在配置文件中用HTTP变量来动态配置的；

    AccessLog是记录Web服务器收到客户端HTTP请求并返回响应的基本日志信息，日志条目内容可以在配置文件中动态配置，
    在http.access log项下，设置了AccessLog的配置项。首先配置是否需要启动AccessLog的log2file = on/off，设置配置
    文件名，最后最主要的是写入配置文件每条记录都包含哪些内容，这些内容是由各个变量组成，通过变量动态地获取每个
    请求和响应的基本信息。
 
    采用HTTPLog结构来管理访问日志，包括配置信息、日志文件句柄、写入文件的互斥锁、日志内容空间等。日志的写入时机
    是在HTTPMsg创建、处理完所有操作、并将响应成功返回客户端、准备关闭HTTPMsg之前，来写入这些过程中的所有动态信
    息到文件中。这个时机点，是完成所有请求、处理、返回响应后才开始写入日志信息，过程时间有可能会非常长，如在下载
    一个大文件时，持续时间会长达几分钟、几十分钟或几个小时；流媒体推送流的时间也很长等等.
 
    一般HTTP AccessLog是很多CDN服务平台作为统计实时流量的重要来源，常需要按日、周、月等时间周期来汇总日志信息，
    设计HTTPLog时，需要考虑生成的日志文件是一个固定的文件、还是每天开始时生成一个新日志文件、还是每周或每月开始
    时生成新文件。


### 4.14 Callback回调机制

 作为嵌入式Web服务器，eJet系统的动态库回调和函数回调机制


### 4.15 正则表达式的使用


### 4.16 超大文件上传
 客户端上传大文件时节省内存空间流程。当客户端上传文件过大时（一般超过128KB），上传内容自动保存到缓存文件里，



### 4.17 TLS/SSL
HTTPS的实现
用SNI机制选择不同域名证书私钥


### 4.18 Chunk传输编码解析


### 4.19 反向代理


### 4.20 FastCGI机制和启动PHP的流程


### 4.21 两个通信连接的串联Pipeline

 两个通信连接串联变成管道时，FD事件处理必须在同一个线程

 串联的两个通信连接数据转发模型

 串联的两个通信连接I/O速度不对等时的流量控制
    HTTP Proxy或FastCGI模式下实时转发的流量控制
    流量限速机制

### 4.22 HTTP Cache系统

 Proxy模式下的Cache碎片存储处理流程

### 4.23 HTTP Tunnel


### 4.24 HTTP Cookie机制


### 4.25 零拷贝Zero-Copy技术

 共采用了哪些Zero-Copy技术提升系统性能


### 4.26 内存池



五. eJet为什么高性能
------

  运用了哪些技术来支撑大并发访问
  降低单个HTTP请求的内存使用开销，采用chunk_t的不连续碎片管理技术
  大量运用Zero-Copy技术减少冗余拷贝
  采用writev和sendfile等系统调用，减少用户空间和内核空间的数据拷贝，提升发送效率


六. eJet Web服务应用案例
------

### 6.1 大型资源网站


### 6.2 承载PHP应用


### 6.3 充当代理服务器


### 6.4 Web Cache服务


### 6.5 作为CDN边缘分发
 运用反向代理、Cache存储实现CDN边缘分发

### 6.6 应用程序集成eJet
1. 将eJet作为动态库或静态库嵌入应用程序中，通过设置系统回调函数，来处理所有的客户端请求
2. 将eJet作为独立的Web服务器程序运行，应用程序作为动态库，嵌入到eJet中，通过动态库回调机制，执行动态库中编写的处理流程。



七. eJet相关的另外两个开源项目
------

### adif 项目
 
ePump框架项目依赖于 adif 项目提供的基础数据结构和算法库。adif 是用标准 c 语言开发的常用数据结构和算法基础库，作为应用程序开发接口基础库，为编写高性能程序提供便利，可极大地缩短软件项目的开发周期，提升工程开发效率，并确保软件系统运行的可靠性、稳定性。adif 项目提供的数据结构和算法库，主要包括基础数据结构、特殊数据结构、常用数据处理算法，常用的字符串、字节流、字符集、日期时间等处理，内存和内存池的分配释放管理，配置文件、日志调试、文件访问、文件缓存、JSon、MIME等管理>，通信编程、文件锁、信号量、互斥锁、事件通知、共享内存等等。
 

### ePump项目
 
依赖于 adif 项目提供的基础数据结构和算法库，作者开发并开源了 ePump 项目。ePump 是一个基于I/O事件通知、非阻塞通信、多> 路复用、多线程等机制开发的事件驱动模型的 C 语言应用开发框架，利用该框架可以很容易地开发出高性能、大并发连接的服务器程 序。ePump 框架负责管理和监控处于非阻塞模式的文件描述符和定时器，根据其状态变化产生相应的事件，并调度派发到相应线程的事件队列中，这些线程通过调用该事件关联的回调函数（Callback）来处理事件。ePump 框架封装和提供了各种通信和应用接口，并融合了当今流行的通信和线程架构模型，是一个轻量级、高性能的 event-driven 开发架构，利用 ePump，入门级程序员也能轻易地开发出商业级的高性能服务器系统。 

***

八. 关于作者 老柯 (laoke)
------

有大量Linux等系统上的应用平台和通信系统开发经历，是资深程序员、工程师，发邮件kehengzhong@hotmail.com可以找到作者，或者通过QQ号码[571527](http://wpa.qq.com/msgrd?V=1&Uin=571527&Site=github.com&Menu=yes)或微信号[beijingkehz](http://wx.qq.com/)给作者留言。

eJet Web服务器项目是作者三个关联开源项目的第三个项目，以事件驱动模型、多线程、大并发连接等为特征的轻量级的高性能Web服务器，完全依赖于前两个项目的基础能力，在嵌入式Web服务器、Cache、CDN等应用领域，有广阔的前景。本项目源自于2003年作者开发完成的HTTP服务器项目，并应用于各类需要运用HTTP协议的通信系统中，这些功能的开发断断续续进行中，一直没有中断。

