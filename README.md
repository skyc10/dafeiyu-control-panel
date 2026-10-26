# 大肥鱼管理面板

本机网页面板：跳转三个控制台、查看运行状态、执行固定启停动作。

## 启动

双击 `start.bat`。浏览器会自动打开带引导参数的页面；若未自动打开，使用终端里打印的「引导链接」。

- 地址：http://127.0.0.1:18100/
- 关闭命令窗口即停止面板，机器人容器不受影响。
- 重复双击 `start.bat` 不会启动第二个实例，会直接打开已运行的页面。

## 能做什么

| 功能 | 说明 |
| --- | --- |
| 控制台入口 | 桥接 13100、DSH 18080、SnowLuma 16082，以及扫码 noVNC 16081，均新标签页打开 |
| 状态展示 | Docker daemon、两个容器、DSH 响应、桥接就绪、QQ 登录 |
| 启动机器人 | 必要时拉起 Docker Desktop → 等 daemon → 启动 snowluma → 启动 fish-bot |
| 停止 AI 服务 | 只停 fish-bot，保留 snowluma 与 QQ 进程 |
| 关闭整套机器人 | 先 fish-bot 再 snowluma；登录态保存在命名卷，重启自动登录（已实测） |

只操作**已有容器**：不 build、不 pull、不 down、不删除容器或数据卷。容器缺失时只显示修复提示。

### 停止采用 30 秒优雅超时

`docker stop` 用 `--time 30`，给 QQ 留足退出时间。原因：容器内 PID 1 是 supervisord，其 `stopwaitsecs` 为默认 10 秒，超时后按 `killasgroup=true` 直接 SIGKILL 整个 QQ 进程组；QQ 有 20+ 进程且持有大量 SQLite WAL/journal，被强杀可能留下损坏的 WAL 或锁文件（此前出现过的退出码 137 即 128+9）。

改用 30 秒后实测：两个容器退出码均为 **0**，`-wal` / `-shm` 文件在停止后归零（SQLite 完成 checkpoint 正常关闭），重启后自动登录无需扫码。

**配置不会因 stop 丢失**：所有配置都在命名卷（`qq-client-config`、`qq-gateway-data`、`qq-client-data`、`fish-bot-dsh`）上，`docker stop` 只发信号、不碰卷。只有 `docker rm -v` 或 `volume rm` 才会删数据，面板没有这两个操作。

## 状态口径

面板把三件事分开显示，不混为一谈：

1. **容器是否运行** — `docker ps` 的实际状态与退出码。
2. **服务是否就绪** — DSH 18080、桥接 13100、SnowLuma 16082 的 HTTP 可达性。
3. **QQ 是否在线** — 只取桥接 `/api/status` 运行时上报的 `snowluma.connected` 与 `accountOnline`。取不到时显示「未知」，**不会**用历史日志里的登录记录推断当前状态。

因此「容器运行」不等于「QQ 已登录」：容器在跑但未扫码时，登录状态显示「等待扫码」或「未知」。

## 令牌处理

- DSH 地址：后端从 fish-bot 容器内 `/data/dsh-url.txt` 即时读取，并把容器内地址改写为宿主 `127.0.0.1:18080` 后返回。
- 桥接令牌：优先 `/data/bridge-state/console-token`，不存在时读 `/data/bridge-config.json` 的 `consoleToken`。
- SnowLuma：自动登录后把令牌拼进地址（详见下节）。
- noVNC 扫码页：读出明文密码后用 URL fragment 自动填入（详见下节）。
- 令牌只经本机后端传递，不写日志、不进 localStorage、不缓存到前端。
- DSH 每次重启后重新读取，因此重启后点一次即可拿到新地址。

## SnowLuma 免密登录

SnowLuma WebUI 必须登录才能使用，密码以 `scrypt(N=16384, r=8, p=1)` 哈希存在 `config/webui.json`，无法反推。面板这样处理：

1. 读取 `webui.json` 的 `passwordHash` / `passwordSalt`。
2. 从容器日志里取程序自己打印的初始密码（形如 `initial credentials: user=admin password=…`，只取最后一次，兼容重启后重新生成）。日志尾巴可能被 QQ 崩溃转储淹没，取不到时自动回退到全量扫描。
3. **用同样的 scrypt 参数复算哈希**，与 `webui.json` 比对。只有一致才认为该密码仍然有效。
4. 拼成 `http://127.0.0.1:16082/?token=<密码>`。

**关键细节**：这个 `token` 参数名的值是**密码**，不是会话令牌。前端启动时若未登录，会取该参数并直接作为 `password` 调 `/api/login`（源码里是 `Zn()` → `se.login(n)` → `{password: n}`）。若把 `/api/login` 返回的会话令牌塞进去，前端会拿令牌当密码去登录并失败。

若你已经在 SnowLuma 里改过密码，第 3 步会失败，面板会明确提示「当前密码未知」而不是拿旧密码反复尝试（登录接口有失败次数限制，反复试会被锁）。此时请手动登录 SnowLuma，面板入口仍会给出普通地址。

> 初始密码每次重启都会重新生成，直到你在页面里改过一次为止。面板会在入口区提示是否需要改密。

## noVNC 扫码页免密

远程桌面（noVNC）需要密码才能连接。该密码是**明文**存在 `config/vnc-password`（root 600），由容器入口生成并持久化，重启后复用同一个值。面板读出后拼到地址的 **fragment** 里：

```
http://127.0.0.1:16081/#password=<密码>&autoconnect=1
```

用 `#` 而不是 `?` 的原因：fragment 不会随请求发到服务器，也不进 Referer，泄露面最小。noVNC 的 `getConfigVar` 优先读 hash、其次读 query，两种都支持。

noVNC 会把密码记进浏览器 localStorage，之后重新打开该页面会自动填充。

> 若读不到密码（例如文件权限异常），面板会给出普通地址并提示手动输入，不会让入口失效。

## 安全边界

- 仅监听 `127.0.0.1:18100`。
- 全部 `/api/*` 需要会话 Cookie（`HttpOnly` + `SameSite=Strict`），由启动入口的引导参数建立。
- POST 额外校验 `Host`、`Origin` 和自定义头 `X-Panel-Action`，跨站请求一律 403。
- 子进程一律参数数组启动，不拼接 shell；不提供任意命令、任意文件、任意 URL 接口。
- 页面 CSP 禁止内联脚本与外部资源，不允许被 iframe 引用。

## 任务与互斥

- 启停操作在后台线程执行，返回任务 ID，页面轮询进度。
- 同一动作重复点击会复用进行中的任务；启动与停止互斥，冲突时直接提示。
- 失败时显示已完成步骤、当前实际状态和原因。
- 面板重启后按实际状态重新判断，不自动重放旧操作。

## 故障处理

| 现象 | 处理 |
| --- | --- |
| 端口 18100 被占用 | 面板直接报错退出，不会杀进程也不会改端口。自行释放端口后重试 |
| Docker 不可用 | 状态区标红；「启动机器人」会尝试拉起 Docker Desktop 并等待就绪（上限 180 秒） |
| 容器缺失 | 动作直接失败并提示按部署文档修复，不自动重建 |
| 取不到令牌 | 对应入口返回明确原因（如 DSH 未启动完成、桥接配置缺 `consoleToken`） |
| snowluma 退出码 137 | 多为被强制终止（如手动 stop 或超时）；面板只如实显示退出码，不推测根因 |

## 文件结构

```
management-panel/
├─ server.py          本机服务、状态探测、固定动作、任务管理
├─ static/            页面、样式、前端脚本
├─ start.bat          双击启动（GBK 编码，见下）
├─ README.md
├─ docs/roadmap.md    性格 / 记忆 / 心情的后续设计备忘
└─ runtime/           本地运行数据（Git 忽略）：会话密钥、面板日志
```

> `start.bat` 必须保存为 **GBK/ANSI 编码**：cmd.exe 按系统代码页解析批处理，UTF-8 中文会让脚本解析错乱。
> `.gitattributes` 已标记 `start.bat -text`，防止 Git 转换损坏。修改该文件时请保持编码。

## 后续规划

页面中「性格设置」「AI 记忆」两个区块是**布局预留**，使用虚构示例数据，标注「后续规划 · 未实现」，不读取真实数据、不提供保存操作。设计备忘见 `docs/roadmap.md`。

## 配套项目

机器人部署代码在另一个仓库：`dafeiyu-deploy`（Compose、镜像构建、入口脚本、配置模板）。

两个仓库分工：

| 仓库 | 内容 |
| --- | --- |
| `dafeiyu-deploy` | Docker 部署：编排、Dockerfile、entrypoint、配置模板、运维脚本 |
| `dafeiyu-control-panel` | 本机网页面板：状态探测、固定启停、控制台跳转 |

运行期数据（配置、登录态、聊天与记忆）都在 Docker 命名卷里，两个仓库都不含这些内容。
