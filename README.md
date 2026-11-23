# xia XSS（仿瞎注）

> 仿照 [xia SQL(瞎注)](../xia_sql) 写的 Burp 反射型 XSS 探测插件，界面布局参考 [HaE](../HaE)。
> 原理：**逐个把参数值替换为纯随机字符串，返回包中出现该随机字符就标记 ✔**（存在反射，可能存在 XSS），最终确认需人工介入。

## 检测原理

1. **Content-Type 判定**：默认按**响应** `Content-Type` 属于 XSS 可解析类型才测试（XSS 能否被浏览器解析由响应决定）。默认可解析类型：
   `text/html`、`application/xhtml+xml`、`text/plain`、`text/javascript`、`application/javascript`、`application/x-javascript`、`text/ecmascript`、`application/ecmascript`、`text/xml`、`application/xml`、`application/*+xml`、`image/svg+xml`、`application/rss+xml`
   完整列表在「配置 → Content-Type 判定」中展示，**可直接修改**（逗号分隔、支持 `*` 通配）、一键恢复默认；另可切换四种判定依据：响应（推荐）/ 请求 / 任一 / 两者。
2. **参数替换**：逐个把 URL / Body（表单、JSON、XML）/ Cookie（可选开关）的参数值替换为**纯随机小写字母+数字**（默认长度 10，界面可配），无任何可读前缀。
3. **回显判断**：发送替换后的请求：
   * 随机字符出现在响应体或响应头 → `✔`
   * 自动排除误报：原始响应本来就含这串字符的不算
   * 兼容 UTF-16 等插入空字节的编码
   * 并分析**反射上下文**：`<script>` 内 / 标签属性（引号内外）/ HTML 注释内 / 正文等，辅助人工判断能否真正执行
4. **HaE 式命中标记**：命中时自动在 Burp 原始流量上打**青色高亮 + 备注**（`xia XSS ✔ 参数名 | 随机字符 | 上下文`），HTTP history 里可直接过滤定位。

## 界面布局（参考 HaE）

单个 Burp Tab「xia XSS」，内部两个子目录：

* **请求**：上部「原始流量 | 探测明细」双表格（分隔条可拖动），下部请求包/响应包**并排同时显示**，底部状态条（请求/探测/命中/扫描中计数 + 清空列表）。
* **配置**：五个分组面板——监控与处理 / Content-Type 判定 / 范围过滤 / 性能与操作 / 自定义 payload。

**快速定位**（参考 HaE）：

* 点探测明细任意一行 → 随机字符自动填入下方请求/响应包**自带搜索框**并高亮（反射失败时自动遍历编辑器组件树填入；仍失败则复制剪贴板兜底）
* 点击自动复制：明细行复制随机字符，主表行复制 URL，均带状态条提示
* 表格右键菜单：复制随机字符 / Payload / 参数名 / URL

## 配置项（修改即时生效，点「保存启动参数」持久化）

| 分组 | 配置项 |
|---|---|
| 监控与处理 | 启动插件（总开关）、监控 Proxy / Repeater / Scanner·Intruder·Target·Spider、测试 Cookie、排除静态资源类型、跳过二进制请求/响应、自动编码 payload、追加模式（保留原值）、允许响应缺少 Content-Type |
| Content-Type | 判定依据（响应/请求/任一/两者）、可解析类型列表（可改、可恢复默认） |
| 范围过滤 | 域名白名单（支持 `*.example.com`）、域名黑名单（**默认 `edu.cn,gov.cn`**）、排除路径、资源类型列表、请求方法、端口白/黑名单、跳过参数名 |
| 性能与操作 | 随机串长度（4-32）、单请求最多参数数、最大响应 KB、并发线程数、请求间隔 ms、保存/重载/应用线程数 |
| 自定义 payload | 启用开关、是否同时保留随机探测、`%s`/`{RAND}`=随机字符、`{V}`=参数原值、`#` 注释，随插件点「加载/重新加载 payload」持久化 |

### 默认排除规则

* **排除路径**（增删改/注册等写操作接口，默认关键词）：
  `add, create, new, insert, save, edit, update, modify, del, delete, remove, destroy, register, signup, upload, import, bind`
  匹配策略：关键词含 `/` 时对整个路径包含匹配（如 `/api/user/add`）；否则按 `/ _ - .` 分段精确匹配——`add` 命中 `/user/add`，不误伤 `/addressbook`。
* **资源类型列表**（URL 后缀，默认含前端与静态资源）：
  `js, ts, jsx, tsx, mjs, cjs, map, css, woff, woff2, ttf, eot, otf, jpg, jpeg, png, gif, ico, webp, bmp, mp3, mp4, avi, mov, wmv, pdf, zip, rar, 7z, gz, tar, exe, dll, doc, docx, xls, xlsx, ppt, pptx, apk, iso, bin, swf`
  （`svg` 不在默认列表——它是 XSS 可解析类型）
* **跳过参数名**：`token, csrf, _csrf, csrf_token, nonce, sign, signature, sig, captcha, verifycode, password, passwd, pwd, secret, __viewstate, __eventvalidation, file, upload`

## 开关与去重

* **总开关绝对生效**：关闭瞬间清空线程池排队任务，进行中的探测立即中止（主表状态标 `stopped`）；所有配置修改即时生效，无需点保存（保存仅用于持久化）。
* **去重**：`MD5(不带参数的URL + 方法 + 参数名/位置列表)`，同指纹只扫一次，跳过时有日志提示；右键 `Send to xia XSS` 强制重扫（跳过去重、不受静态/路径过滤限制）；「清空列表」重置去重记录。
* 每个过滤环节（白名单/黑名单/端口/方法/排除路径/静态类型/二进制/响应过大/Content-Type/去重）跳过时都有对应日志，方便定位"为什么没测"。

## 编译

```sh
# 无参数时自动下载 burp-extender-api jar
./compile.sh
# 或指定 Burp 自身 jar 作为 classpath
./compile.sh "/Applications/Burp Suite Professional.app/Contents/Resources/app/burpsuite_pro.jar"
```

生成 `xia_xss.jar`，在 Burp `Extender → Add` 加载。默认 JDK 1.8 编译（与 xia_sql 一致），产物兼容 Burp 当前版本。

## 配置文件

* `xia_XSS_config.ini`：启动参数（可用 `-Dxiaxss.config=<path>` 覆盖路径）
* `xia_XSS_diy_payload.ini`：自定义 payload（可用 `-Dxiaxss.payload=<path>` 覆盖）

## 注意

* 插件只检测**反射**，不验证 JS 是否真正执行；反射点在属性/JS 上下文时，用自定义 payload 功能人工构造闭合语句继续验证。
* 探测请求由插件直接发出（不经过 Proxy 监听），不会造成递归扫描。
* 仅用于**授权范围内**的安全测试。
