PHP2Shell: CVE-2026-109618 / CVE-2026-109619

Before the First Line of PHP: Request Lifecycle Analysis of Two RCE Vulnerabilities

Author: Grayson (wind884)

2026-10-21

[中文报告](REPORT.zh-CN.md)

Executive Summary

PHP can process request input, upload progress and errors before normal module initialization. Two lifetime failures become reachable at that boundary: an operation can be interrupted before it restores valid state, or a later request can consume a reference whose request-owned memory has already been freed.

CVE-2026-109618 concerns when PHP exits an operation. Immediate OOM handling can abandon a native function while internal state is incomplete, leaving shutdown to process it. CVE-2026-109619 concerns what survives a request: worker-held references can outlive the memory they identify and be consumed before the next request resets them.

PHP reports confirmed mod_php RCE through the OOM path before application execution, and confirmed session lifecycle RCE against mod_php and FPM. This report traces the source mechanisms behind those vendor results; it does not present them as exploits reproduced here. [OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

I reviewed PHP 8.2.34 and 8.2.35, the PHP 8.2 [upstream fix](https://github.com/php/php-src/commit/01a40e89fbfc499936e3b05888d8f00bfde886df) and its [parent](https://github.com/php/php-src/commit/512c04e39f674dbf4133b8fbbd381cd8c2df6836). The ten inspected source files are byte-identical between the parent and 8.2.34, and between the fix and 8.2.35. I did not execute a triggering request or build an exploit.

Version 8.2.34 is the earliest release independently inspected for this report, not a verified first affected release. Coverage of other release branches follows the vendor announcement; their complete histories were not independently checked.

Background

A PHP web worker can handle successive requests. Request-heap objects are released at the end of a request, while some worker-held global fields persist. Those fields must be reset before their referents disappear, and shutdown must only encounter objects in a valid state.

RINIT is an extension’s normal request initialization phase. It is not the start of every request-related operation: automatic body parsing and upload callbacks can precede it. Separating those boundaries explains why a reset that is correct during ordinary application execution can still arrive too late.

CVE-2026-109619: stale state across requests

The session example requires reachable multipart processing, enabled session upload progress, a usable session identifier, session data reaching a decoder and the progress field. The feature is enabled by default and can run without an application call to session_start(). A suitable interruption must occur after state publication, and the worker must survive to handle the consuming request. Application behavior and configuration determine those conditions; their prevalence was not measured.

PHP keeps extension globals across requests while allocations made with emalloc belong to a request. Those globals must not expose expired allocations to the next request.

CVE-2026-109618: unsafe exit on memory exhaustion

PHP parses request data and constructs request state before executing the application. A memory limit should terminate excessive work without exposing partially initialized objects to later cleanup. The relevant configuration is a PHP HTTP endpoint using mod_php, automatic input parsing, a finite request memory limit, and frontend behavior that allows the triggering input through. The attacker controls the request body and needs neither a PHP login nor permission to install server code.

The advisory describes multipart input with substantial internal memory amplification, including numerous part headers and empty file controls with nested names. It also describes bodies without a usable declared length. These are ways to reach OOM, meaning out of memory; they do not make every frontend configuration exploitable.

Vulnerability Details

CVE-2026-109619: stale state across requests

In PHP 8.2.34, [php_request_startup in main/main.c](https://github.com/php/php-src/blob/php-8.2.34/main/main.c#L1820-L1825) calls php_hash_environment before zend_activate_modules. Input processing can therefore invoke session upload progress before ordinary module RINIT. The [multipart callback in ext/session/session.c](https://github.com/php/php-src/blob/php-8.2.34/ext/session/session.c#L3062-L3120) requires a session identifier and progress key, then reaches php_session_initialize through its [progress update](https://github.com/php/php-src/blob/php-8.2.34/ext/session/session.c#L2960-L2991). That [initialization reads stored session data](https://github.com/php/php-src/blob/php-8.2.34/ext/session/session.c#L458-L482) and decodes it.

Request A enters [php_var_unserialize_init in ext/standard/var_unserializer.re](https://github.com/php/php-src/blob/php-8.2.34/ext/standard/var_unserializer.re#L60-L92). When serialize_lock and level are both zero, it allocates a context and publishes its pointer and nesting level:

```c
BG(unserialize).data = d;
BG(unserialize).level = 1;
```

Matching destruction normally frees the context, decrements the level and clears the pointer:

```c
if (BG(serialize_lock) || BG(unserialize).level == 1) {
	var_destroy(&d);
	efree(d);
}
if (!BG(serialize_lock) && !--BG(unserialize).level) {
	BG(unserialize).data = NULL;
}
```

For example, [memory-limit handling](https://github.com/php/php-src/blob/php-8.2.34/Zend/zend_alloc.c#L371-L395) invokes zend_bailout. Its nonlocal jump after publication can bypass matching destruction. Request shutdown subsequently [releases the request heap](https://github.com/php/php-src/blob/php-8.2.34/main/main.c#L1924-L1929), leaving the persistent globals referring to expired memory. In request B, an early decoder initialization with serialize_lock zero and a residual nonzero level takes this branch:

```c
d = BG(unserialize).data;
++BG(unserialize).level;
```

The php session decoder subsequently calls var_tmp_var. Its [tmp_var implementation](https://github.com/php/php-src/blob/php-8.2.34/ext/standard/var_unserializer.re#L157-L189) reads last_dtor through the returned pointer. Checking that a pointer is nonnull does not establish that its allocation remains alive.

[Ordinary malformed session input](https://github.com/php/php-src/blob/php-8.2.34/ext/session/session.c#L990-L1035) normally reaches decoder destruction. The surrounding [session cancellation handler](https://github.com/php/php-src/blob/php-8.2.34/ext/session/session.c#L250-L272) does not reset BG(unserialize). We therefore need the particular interrupted lifetime, rather than merely invalid input or an arbitrary fatal error.

CVE-2026-109618: unsafe exit on memory exhaustion

The decisive behavior in PHP 8.2.34 is the allocator’s immediate nonlocal exit. Zend/zend_alloc.c, zend_mm_safe_error(), reports the error and calls zend_bailout(); Zend/zend.c, _zend_bailout(), ultimately executes LONGJMP(*EG(bailout), FAILURE). This transfers control to an enclosing recovery point without finishing intervening C operations. [Allocator](https://github.com/php/php-src/blob/php-8.2.34/Zend/zend_alloc.c#L371-L396), [bailout](https://github.com/php/php-src/blob/php-8.2.34/Zend/zend.c#L1175-L1189)

The following statements come from the two separate functions identified above:

```c
zend_bailout();

LONGJMP(*EG(bailout), FAILURE);
```

As the advisory explains, request memory may already be reachable while initialization is unfinished. An allocation failure at that moment can leave it invalid; the failed allocation need not belong to that same object. The problem is the combination of early exit and subsequent use, rather than memory exhaustion alone.

The mod_php lifecycle preserves that second step. In sapi/apache2handler/sapi_apache2.c, php_apache_request_ctor() calls php_request_startup(); startup failure causes another bailout inside the handler’s protected block. After that block, the top-level request path still calls php_apache_request_dtor(), which invokes php_request_shutdown(). Shutdown includes destructors, output processing and destruction of request globals. These source transitions establish why failed startup does not prevent cleanup from encountering reachable state. [Constructor and destructor](https://github.com/php/php-src/blob/php-8.2.34/sapi/apache2handler/sapi_apache2.c#L513-L554), [handler](https://github.com/php/php-src/blob/php-8.2.34/sapi/apache2handler/sapi_apache2.c#L659-L725), [shutdown](https://github.com/php/php-src/blob/php-8.2.34/main/main.c#L1834-L1902)

Exploitability Analysis

CVE-2026-109619: stale state across requests

The supported primitive is reuse of an expired decoding context when publication, interruption, heap release, worker reuse and early consumption all align. The excerpt alone does not establish controlled writes, a reliable heap layout or code execution.

An important constraint changes the FPM sequence: its [startup-failure branch](https://github.com/php/php-src/blob/php-8.2.34/sapi/fpm/fpm/fpm_main.c#L1871-L1878) exits the child. A producer that fails during startup cannot survive in that child to feed another request. The vendor-validated FPM route instead publishes state during application execution after successful startup, then uses upload progress as the later early consumer. mod_php also permits the documented multipart-startup producer. Multiple workers affect request placement without establishing protection.

CVE-2026-109618: unsafe exit on memory exhaustion

The source-supported primitive is interruption during incomplete initialization followed by processing of reachable invalid state. Turning that primitive into code execution depends on the affected object, controllable data, allocation layout, extensions and frontend behavior. The advisory reports successful mod_php exploitation with default PHP input and memory limits.

FPM supplies a meaningful counterexample to transplanting the startup chain unchanged. Its request loop finishes the failed request, shuts down the module and returns FPM_EXIT_SOFTWARE when php_request_startup() fails, removing the child instead of continuing into ordinary request shutdown. Post-startup OOM paths may remain susceptible where application work reaches an unsafe interruption point, but that is conditional analysis. The advisory explicitly reports no complete FPM exploit. [FPM startup failure](https://github.com/php/php-src/blob/php-8.2.34/sapi/fpm/fpm/fpm_main.c#L1861-L1878)

| Property | CVE-2026-109618 | CVE-2026-109619 |
| --- | --- | --- |
| Core failure | An exceptional exit interrupts an internal operation | A reference survives the request that owned its memory |
| Invalid state | Initialization or temporary mutation is unfinished | The referenced request memory has been freed |
| Later consumer | Error handling and shutdown of the current request | Early handling of a later request in the same worker |
| Main correction | Defer OOM to designated handling points; exit on hard exhaustion | Clear references and initialize before early consumers |
| FPM distinction | Child exit blocks the identical startup-failure chain | A different path with a post-startup producer is vendor-confirmed |

Proof of Concept

No executable PoC, crash log, sanitizer report or command-execution result accompanies this report. No public target was tested. State transitions, call order and fix behavior are direct source evidence; complete RCE observations are attributed to the upstream advisories.

Source review explains why a stale reference can become reachable and why OOM can bypass state restoration. It does not establish controllable bytes, heap reuse or exploit reliability for a particular build.

Runtime controls remain unperformed: matched vulnerable and fixed builds, ordinary failure versus fatal interruption, a reused worker versus a restarted worker, and mod_php versus FPM startup failure. An ordinary decoding error, a single crashed request or entry into an upload callback would not by itself demonstrate the full lifecycle chain.

Remediation

Upgrade to the corresponding fixed release or a vendor build confirmed to contain the complete backport, then restart existing workers. A distribution may retain an older upstream version number after backporting the fix. [PHP security announcement](https://www.php.net/archive/2026.php#2026-10-21-5)

| PHP branch | Affected range listed by the vendor | First upstream fixed release |
| --- | --- | --- |
| 8.2 | Branch 8.2 releases below 8.2.35 | 8.2.35 |
| 8.3 | Branch 8.3 releases below 8.3.36 | 8.3.36 |
| 8.4 | Branch 8.4 releases below 8.4.27 | 8.4.27 |
| 8.5 | Branch 8.5 releases below 8.5.12 | 8.5.12 |

This table does not imply that versions outside those branches are safe or establish when the bugs first appeared. PHP 8.2.35 is the fixed implementation directly inspected here.

CVE-2026-109619: stale state across requests

PHP 8.2.35 adds [php_basic_early_rinit to php_request_startup](https://github.com/php/php-src/blob/php-8.2.35/main/main.c#L1815-L1817), before request data processing. Its [implementation in ext/standard/basic_functions.c](https://github.com/php/php-src/blob/php-8.2.35/ext/standard/basic_functions.c#L504-L514) includes:

```c
BG(serialize_lock) = 0;
memset(&BG(serialize), 0, sizeof(BG(serialize)));
memset(&BG(unserialize), 0, sizeof(BG(unserialize)));
```

[Ordinary RINIT still performs its reset](https://github.com/php/php-src/blob/php-8.2.35/ext/standard/basic_functions.c#L407-L413); the added reset closes the earlier access window. Deploy the complete vendor patch and restart workers. The [vendor's fixed releases](https://www.php.net/archive/2026.php#2026-10-21-5) are 8.2.35, 8.3.36, 8.4.27 and 8.5.12. Only 8.2.34 and 8.2.35 were independently sampled here; the first affected release and introduction were not established, and other branches were not individually inspected.

Disabling session upload progress administratively and restarting workers blocks the documented session route, but is not a generic mitigation for other state families. Regression coverage should exercise interrupted publication followed by consecutive requests and early callbacks.

The exact startup order places the added reset before sapi_activate(), so it runs before request input can reach these fields:

```c
zend_activate();
php_basic_early_rinit();
sapi_activate();
```

The MULTIPART_EVENT_START branch also resets session request globals when early upload handling begins. This line is from that branch. [Early session reset](https://github.com/php/php-src/blob/php-8.2.35/ext/session/session.c#L3056-L3064)

```c
php_rinit_session_globals();
```

CVE-2026-109618: unsafe exit on memory exhaustion

The fix separates soft and hard exhaustion. Soft-limit handling records EG(delayed_oom).state as ZEND_OOM_STATE_PENDING and sets vm_interrupt, allowing native operations to reach designated handling points. The VM interrupt helper and function-call API dispatch delayed OOM; zend_handle_delayed_oom() arranges unwind through zend_throw_unwind_exit() when an execution frame exists. A hard-limit breach terminates the process with _exit(137). [Pending state](https://github.com/php/php-src/blob/php-8.2.35/Zend/zend_alloc.c#L385-L418), [handling](https://github.com/php/php-src/blob/php-8.2.35/Zend/zend_alloc.c#L3471-L3523), [hard limit](https://github.com/php/php-src/blob/php-8.2.35/Zend/zend_alloc.c#L459-L531), [VM dispatch](https://github.com/php/php-src/blob/php-8.2.35/Zend/zend_vm_def.h#L9982-L9990), [API dispatch](https://github.com/php/php-src/blob/php-8.2.35/Zend/zend_execute_API.c#L1011-L1017)

The pending-state update and interrupt request are adjacent operations in zend_mm_delayed_verror():

```c
EG(delayed_oom).state = ZEND_OOM_STATE_PENDING;

zend_atomic_bool_store_ex(&EG(vm_interrupt), true);
```

This does not remove every zend_bailout(): the delayed handler retains bailout when no userland frame exists. VM interrupts are also not the sole handling point. The PHP_OUTPUT_LOCKED guard prevents error reporting from freeing an active output-handler stack; it is related protection, not a separately established exploit here. [Output guard](https://github.com/php/php-src/blob/php-8.2.35/main/main.c#L1304-L1309)

Request-size and multipart limits reduce exposure but do not replace updating. Regression coverage should exercise startup failure, delayed OOM during callbacks, safe unwind and hard-limit termination.

The output-handler condition also deserves a direct look. PHP 8.2.35 main/main.c checks that no handler is locked as running before it discards the output stack:

```c
if (zend_alloc_in_memory_limit_error_reporting()
        && !(php_output_get_status() & PHP_OUTPUT_LOCKED)) {
    php_output_discard_all();
}
```

[main/main.c, PHP 8.2.35](https://github.com/php/php-src/blob/php-8.2.35/main/main.c#L1304-L1309)

Summary

Both flaws concern when later code is allowed to observe PHP’s internal state. CVE-2026-109618 requires avoiding an abrupt exit while an object is temporarily invalid. CVE-2026-109619 requires preventing a later request from observing references to released request memory. Safe exit and earlier initialization address those separate boundaries.

The same startup failure has different consequences across SAPIs. Exposure depends on the reachable entry point, the operation publishing state, the later consumer and the worker lifetime. The reviewed source supports those causal relationships; complete exploitation remains an environment-specific runtime result.
