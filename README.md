PHP2Shell: Before the First Line of PHP

第一行 PHP 执行之前：两项 RCE 漏洞的请求生命周期分析

CVE-2026-109618 / CVE-2026-109619

作者 / Author: Grayson (wind884)

2026-10-21

[中文完整报告](REPORT.zh-CN.md) | [Full report in English](REPORT.en.md)

PHP 的请求边界并不等于工作进程的边界，输入解析、上传进度和错误处理可以早于正常模块初始化运行，一旦异常退出打断内部操作，后续清理或下一条请求就可能接触尚未恢复、甚至已经释放的状态

这份报告沿着 PHP 8.2 的真实调用路径，分析旧版 OOM 处理中的非局部跳转，以及跨请求残留的 Session 和反序列化状态，再对照官方修复解释初始化顺序、延迟 OOM 和输出处理器保护各自解决了什么问题

The request boundary in PHP is narrower than the lifetime of a web worker. Input parsing, upload progress and error handling can run before normal module initialization. An interrupted operation can therefore leave invalid state for request shutdown, or stale references for the next request handled by the same worker.

This report follows the PHP 8.2 call paths behind unsafe OOM exits and stale session or decoder state, then examines the upstream changes to initialization order, deferred OOM handling and output handler lifetime.

| 漏洞 / Vulnerability | 失效位置 / Failure | 后续访问 / Consumer |
| --- | --- | --- |
| CVE-2026-109618 | OOM 在内部操作尚未完成时跳出 / OOM exits an unfinished internal operation | 当前请求的清理 / Shutdown of the current request |
| CVE-2026-109619 | 请求内存释放后，工作进程仍持有旧引用 / Worker state retains references after request memory is freed | 下一条请求的提前处理 / Early handling of a subsequent request |

源码对照范围为 PHP 8.2.34、PHP 8.2.35，以及 PHP 8.2 分支官方修复提交和父提交，报告没有运行时利用复现，官方验证的 RCE 结果会单独归于官方公告

The source comparison covers PHP 8.2.34, PHP 8.2.35, and the PHP 8.2 upstream fix and its parent. No exploit was executed for this report. Vendor-confirmed RCE results are attributed to the upstream advisories.

| PHP 分支 / Branch | 官方修复版本 / Fixed release |
| --- | --- |
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

修复版本来自 [PHP 官方安全公告](https://www.php.net/archive/2026.php#2026-10-21-5)，本报告独立核对的发布源码集中在 8.2 分支，其他分支的版本范围按官方公告列出

Fixed releases are listed in the [PHP security announcement](https://www.php.net/archive/2026.php#2026-10-21-5). Direct release-source inspection in this report is limited to the 8.2 branch; release coverage for other branches follows the vendor announcement.

官方技术公告 / Upstream technical advisories

- [CVE-2026-109618: RCE via OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619: RCE via stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP 8.2 upstream fix: Avoid state corruption via bailout](https://github.com/php/php-src/commit/01a40e89fbfc499936e3b05888d8f00bfde886df)
