第一行 PHP 执行之前：两项 RCE 漏洞的请求生命周期分析

CVE-2026-109618 / CVE-2026-109619

作者：Grayson（wind884）

2026-10-21

[English report](REPORT.en.md)

执行摘要

PHP 可以在正常模块初始化之前处理请求输入、上传进度和错误，这让两个本应由生命周期保证隔离的问题进入了同一条调用链：一个操作尚未完成就被 OOM 打断，或者请求已经结束而工作进程仍保存着它的内存引用

CVE-2026-109618 的问题出在异常退出时机，旧版内存耗尽处理可能跳出正在修改内部结构的 C 函数，随后清理流程继续接触无效状态，CVE-2026-109619 的问题出在请求边界，上一条请求留下的引用可能被下一条请求提前使用

PHP 官方已确认 mod_php 下可在应用代码执行前实现 OOM 路径的远程代码执行，并确认 Session 生命周期路径可影响 mod_php 和 FPM，本文分析这些结果背后的源码机制，不把它们写成本文的运行时复现 [OOM 公告](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)、[残留状态公告](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

我核对了 PHP 8.2.34、8.2.35，以及 PHP 8.2 分支[官方修复](https://github.com/php/php-src/commit/01a40e89fbfc499936e3b05888d8f00bfde886df)和[父提交](https://github.com/php/php-src/commit/512c04e39f674dbf4133b8fbbd381cd8c2df6836)，所查的十个相关源码文件在父提交与 8.2.34 之间、修复提交与 8.2.35 之间分别完全一致，未运行触发请求或构建完整利用

8.2.34 是本报告独立检查的最早发布版本，不能据此认定它是首个受影响版本，其他分支的修复范围采用官方公告，未独立核对全部历史版本

背景

一个 PHP 工作进程可以连续处理多条请求，请求堆中的对象随请求释放，而工作进程持有的某些全局字段会继续存在，安全边界要求这些字段及时复位，清理代码也只能处理处于有效状态的对象

RINIT 是扩展的正常请求初始化阶段，它并不是所有请求相关操作的起点，自动请求体解析和上传回调可以在它之前运行，这正是本报告需要区分的两个时间边界

CVE-2026-109619：跨请求残留状态

攻击者需能提交触达 PHP 的 multipart 上传，并提供有效会话标识、供解码的会话数据和上传进度字段，session.upload_progress.enabled 默认开启，但是否能触发所需中断取决于入口、配置和应用行为，两次请求还必须落到同一存活工作进程，上传进度处理无须应用显式调用 session_start()

CVE-2026-109618：内存耗尽导致的不安全退出

PHP 会在执行应用之前解析请求并构造状态，内存限制应终止过量工作，同时保证清理只能接触有效对象，相关前提是请求经前端到达 mod_php，启用自动输入解析，并存在可触发的有限内存限制，攻击者控制请求体，无须登录 PHP 应用或上传服务器代码

公告列举了 multipart 部件头过多、空文件控件配合嵌套字段名导致内部内存放大，以及缺少可用声明长度的请求体，这些是耗尽内存的入口，其可达性仍取决于前端处理

漏洞详情

CVE-2026-109619：跨请求残留状态

PHP 8.2.34 的 [php_request_startup](https://github.com/php/php-src/blob/php-8.2.34/main/main.c#L1820-L1825) 先处理请求环境，再执行模块初始化，因此上传进度回调可以早于普通 RINIT 访问会话，[回调](https://github.com/php/php-src/blob/php-8.2.34/ext/session/session.c#L3062-L3120)要求会话标识和进度键，随后经[进度更新](https://github.com/php/php-src/blob/php-8.2.34/ext/session/session.c#L2960-L2991)调用 [php_session_initialize](https://github.com/php/php-src/blob/php-8.2.34/ext/session/session.c#L458-L482) 读取并解码会话

请求 A 进入 [php_var_unserialize_init](https://github.com/php/php-src/blob/php-8.2.34/ext/standard/var_unserializer.re#L60-L92)，锁和层数均为零时，以 emalloc 分配请求内存，并发布指针和层数

```c
BG(unserialize).data = d;
BG(unserialize).level = 1;
```

正常销毁负责释放上下文、递减层数并清空指针

```c
if (BG(serialize_lock) || BG(unserialize).level == 1) {
	var_destroy(&d);
	efree(d);
}
if (!BG(serialize_lock) && !--BG(unserialize).level) {
	BG(unserialize).data = NULL;
}
```

例如内存耗尽可触发 [bailout](https://github.com/php/php-src/blob/php-8.2.34/Zend/zend_alloc.c#L371-L395)，若中断发生于发布之后，匹配销毁可能被跳过，随后[请求堆释放](https://github.com/php/php-src/blob/php-8.2.34/main/main.c#L1924-L1929)，工作进程仍保留旧指针

请求 B 若在 RINIT 前再次解码，且锁为零、残留层数非零，初始化便复用该指针

```c
d = BG(unserialize).data;
++BG(unserialize).level;
```

普通 php 解码器随后调用 var_tmp_var，其 [tmp_var](https://github.com/php/php-src/blob/php-8.2.34/ext/standard/var_unserializer.re#L157-L189) 会读取该结构的 last_dtor，非空检查不能确认内存仍属于当前请求，[普通格式错误](https://github.com/php/php-src/blob/php-8.2.34/ext/session/session.c#L990-L1035)通常仍走销毁路径，[会话取消处理](https://github.com/php/php-src/blob/php-8.2.34/ext/session/session.c#L250-L272)也未重置 BG(unserialize)，因此不能把任意无效会话或任意致命错误等同于成功触发

CVE-2026-109618：内存耗尽导致的不安全退出

PHP 8.2.34 的 Zend/zend_alloc.c 中，zend_mm_safe_error() 报错后调用 zend_bailout()，Zend/zend.c 的 _zend_bailout() 最终执行 LONGJMP(*EG(bailout), FAILURE)，控制流跳回外层恢复点，跳过尚未完成的 C 操作 [分配器](https://github.com/php/php-src/blob/php-8.2.34/Zend/zend_alloc.c#L371-L396)、[跳转实现](https://github.com/php/php-src/blob/php-8.2.34/Zend/zend.c#L1175-L1189)

以下摘录分别取自上述两个函数，中间没有展示各自的其余代码

```c
zend_bailout();

LONGJMP(*EG(bailout), FAILURE);
```

依据公告，请求对象可能已经对外部清理逻辑可达，但初始化尚未结束，此时任何相关执行路径上的分配失败都可能留下无效状态，失败的分配不必属于该对象，危险来自提前退出与后续使用的组合

mod_php 的 php_apache_request_ctor() 调用 php_request_startup()，构造失败会在处理器的保护块中再次 bailout，离开该块后，顶层请求路径仍调用 php_apache_request_dtor()，进而进入 php_request_shutdown()，清理包含析构、输出处理和全局变量释放，这解释了启动失败后仍会消费请求状态 [构造与析构](https://github.com/php/php-src/blob/php-8.2.34/sapi/apache2handler/sapi_apache2.c#L513-L554)、[处理器](https://github.com/php/php-src/blob/php-8.2.34/sapi/apache2handler/sapi_apache2.c#L659-L725)、[清理](https://github.com/php/php-src/blob/php-8.2.34/main/main.c#L1834-L1902)

可利用性分析

CVE-2026-109619：跨请求残留状态

成立条件是先发布状态、再中断、释放请求堆、复用工作进程，最后在普通重置前消费旧值，源码说明释放后使用的条件，并未证明可控写入或稳定代码执行，堆布局、内存复用和应用入口仍影响利用

FPM 的 [启动失败分支](https://github.com/php/php-src/blob/php-8.2.34/sapi/fpm/fpm/fpm_main.c#L1871-L1878)直接退出子进程，所以不能照搬 mod_php 的启动阶段生产序列，官方验证的 FPM 路径在启动成功后的应用执行阶段留下状态，再由后续上传提前消费

CVE-2026-109618：内存耗尽导致的不安全退出

源码支持的基本机制是初始化被中断，随后处理可达的无效状态，升级为代码执行还取决于具体对象、可控数据、分配布局、扩展和前端，公告报告已在默认 PHP 输入与内存限制下成功利用 mod_php

FPM 不能直接套用上述启动链，它在 php_request_startup() 失败后结束请求、关闭模块并返回 FPM_EXIT_SOFTWARE，使子进程退出，正常启动后的应用操作仍可能触发其他不安全中断点，但公告明确没有展示完整 FPM 利用 [FPM 失败分支](https://github.com/php/php-src/blob/php-8.2.34/sapi/fpm/fpm/fpm_main.c#L1861-L1878)

| 比较项 | CVE-2026-109618 | CVE-2026-109619 |
| --- | --- | --- |
| 核心错误 | 异常退出打断内部操作 | 请求结束后仍残留引用 |
| 危险状态 | 初始化或临时修改尚未完成 | 引用指向已经释放的请求内存 |
| 后续访问 | 当前请求的错误处理和清理 | 同一工作进程中下一条请求的提前处理 |
| 主要修复 | 延迟 OOM 到指定处理点，硬超限退出进程 | 释放前清理，早于消费者初始化 |
| FPM 的关键限制 | 启动失败退出子进程，阻断相同启动链 | 启动后产生残留状态的另一条路径仍已获官方验证 |

概念验证

本文没有可执行 PoC、崩溃日志、内存检查器报告或命令执行结果，也没有对公共目标发起测试，源码中的状态转移、调用顺序与修复行为是本文的直接证据，完整 RCE 的运行结论归于官方公告

源码检查可以回答旧引用为什么有机会被使用，以及 OOM 为什么可能中断状态恢复，尚未回答的是具体构建中的可控字节、堆复用位置和利用稳定性

仍待在隔离环境中完成的验证包括：匹配配置的未修复与修复版本对照，普通失败与致命中断对照，同一工作进程与工作进程重启对照，以及 mod_php 与 FPM 的启动失败行为对照，普通解码失败、一次请求崩溃或请求恰好进入上传回调，都不能单独证明完成了这条利用链

修复建议

官方修复版本如下，部署应升级到相应版本或供应商确认包含完整回补的构建，再重启现有工作进程，单看上游版本号不能判断发行版是否已经回补 [PHP 安全公告](https://www.php.net/archive/2026.php#2026-10-21-5)

| PHP 分支 | 官方公告中的受影响范围 | 首个官方修复版本 |
| --- | --- | --- |
| 8.2 | 8.2 分支中低于 8.2.35 的版本 | 8.2.35 |
| 8.3 | 8.3 分支中低于 8.3.36 的版本 | 8.3.36 |
| 8.4 | 8.4 分支中低于 8.4.27 的版本 | 8.4.27 |
| 8.5 | 8.5 分支中低于 8.5.12 的版本 | 8.5.12 |

该表不声明这些分支之外的版本安全，也不确定漏洞最早何时引入，本次直接检查的修复实现为 PHP 8.2.35

CVE-2026-109619：跨请求残留状态

PHP 8.2.35 在 php_request_startup 中新增 [php_basic_early_rinit 调用](https://github.com/php/php-src/blob/php-8.2.35/main/main.c#L1815-L1817)，早于请求数据处理，其 [实现](https://github.com/php/php-src/blob/php-8.2.35/ext/standard/basic_functions.c#L504-L514)清空相关状态

```c
BG(serialize_lock) = 0;
memset(&BG(serialize), 0, sizeof(BG(serialize)));
memset(&BG(unserialize), 0, sizeof(BG(unserialize)));
```

[普通 RINIT 的重置](https://github.com/php/php-src/blob/php-8.2.35/ext/standard/basic_functions.c#L407-L413)仍然存在，新增重置补足提前访问窗口，应部署完整官方补丁并重启工作进程，[官方修复版本](https://www.php.net/archive/2026.php#2026-10-21-5)为 8.2.35、8.3.36、8.4.27、8.5.12，本文仅抽查 8.2.34 和 8.2.35，未确定最初引入版本，也未逐一检查其他分支

临时禁用上传进度并重启可阻断已知会话路径，不能覆盖错误、对象或扩展状态等其他变体，回归测试应覆盖中断后的连续请求和提前回调

提前重置的具体调用顺序如下，新调用位于 sapi_activate() 之前，不能等到请求输入已经被处理才补做清零

```c
zend_activate();
php_basic_early_rinit();
sapi_activate();
```

上传开始事件也调用 php_rinit_session_globals()，使 Session 自身的请求状态在提前处理开始时复位，下面这一行位于 MULTIPART_EVENT_START 分支 [Session 提前重置](https://github.com/php/php-src/blob/php-8.2.35/ext/session/session.c#L3056-L3064)

```c
php_rinit_session_globals();
```

CVE-2026-109618：内存耗尽导致的不安全退出

修复将软限制超额记录为 EG(delayed_oom).state = ZEND_OOM_STATE_PENDING，并设置 vm_interrupt，让原生操作推进至指定处理点，存在执行帧时通过 zend_throw_unwind_exit() 展开，硬限制超额则调用 _exit(137) 终止进程 [延迟状态](https://github.com/php/php-src/blob/php-8.2.35/Zend/zend_alloc.c#L385-L418)、[处理与展开](https://github.com/php/php-src/blob/php-8.2.35/Zend/zend_alloc.c#L3471-L3523)、[硬限制](https://github.com/php/php-src/blob/php-8.2.35/Zend/zend_alloc.c#L459-L531)

zend_mm_delayed_verror() 中记录待处理状态并请求中断的相邻操作如下

```c
EG(delayed_oom).state = ZEND_OOM_STATE_PENDING;

zend_atomic_bool_store_ex(&EG(vm_interrupt), true);
```

修复并未删除所有 bailout，延迟处理器在没有用户态帧时仍会 bailout，VM 中断也不是唯一处理点，函数调用 API 同样处理延迟 OOM，PHP_OUTPUT_LOCKED 检查还防止报错时释放正在运行的输出处理器栈，这属于相关保护，不能据此另立已确认漏洞 [API 处理点](https://github.com/php/php-src/blob/php-8.2.35/Zend/zend_execute_API.c#L1011-L1017)、[输出保护](https://github.com/php/php-src/blob/php-8.2.35/main/main.c#L1304-L1309)

请求大小与 multipart 限制可减少暴露，但不能替代升级，回归应覆盖启动失败、回调中的延迟 OOM、安全展开和硬限制退出

输出处理器的保护条件也值得单独看，它先确认处理器没有处于运行锁定状态，才允许清空输出栈，以下为 PHP 8.2.35 的 main/main.c 原始条件

```c
if (zend_alloc_in_memory_limit_error_reporting()
        && !(php_output_get_status() & PHP_OUTPUT_LOCKED)) {
    php_output_discard_all();
}
```

[main/main.c, PHP 8.2.35](https://github.com/php/php-src/blob/php-8.2.35/main/main.c#L1304-L1309)

总结

两项漏洞都涉及 PHP 何时允许后续代码看到内部状态，CVE-2026-109618 要避免在对象处于临时无效状态时突然退出，CVE-2026-109619 要保证请求内存释放后不再有旧引用进入下一条请求，提前初始化和安全退出分别修复了这两个边界

同一条启动失败流程在不同 SAPI 下并不等价，判断影响时需要同时保留可达入口、状态产生点、后续消费者和工作进程生命周期，源码分析支持这些因果关系，完整利用结果仍以相应环境中的实际验证为准
