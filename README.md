# mihomo-watchdog

拨号 / TLS 失败时，给 mihomo 策略组切下一个叶子。切成功可发 Bark。

日志来自 mihomo `GET /logs` WebSocket，不是 `docker logs`。刚连上时滑窗是空的。

## 编译

```bash
make
```

产出当前目录的 `mihomo-watchdog`。只有 `watchdog.c`，无第三方依赖。

push / PR 跑 `make`。打 `v*` tag 会发 GitHub Release（linux-amd64 二进制）。

## 跑

```bash
./mihomo-watchdog --interval 8 --window 10 --fails 3 --cooldown 20
```

| 参数 | 默认 | 含义 |
|---|---|---|
| `--interval` | 8 | 每轮间隔（秒） |
| `--window` | 10 | 失败滑窗（秒） |
| `--fails` | 3 | 窗内失败次数阈值 |
| `--cooldown` | 20 | 同一组两次切换最小间隔（秒） |
| `--group NAME` | 自动发现 | 只看这些组，可重复 |
| `--once` | 关 | 跑一轮退出 |
| `--dry-run` | 关 | 只打印，不切、不改 yaml |
| `--no-close-cursor` | 关 | 切 `🤖 Cursor自动` 时不断已死连接 |

不传 `--group` 时：只纳管名字以 `自动` 结尾的 `Selector` 站点组（不含 `🤖 自动` 与各 `♻️ 地区自动` Fallback 组，也不接管 `🚀 默认代理`）。跳过 `🤖 AGY 美国自动`、`♻️ 自动选择`、`🌐 IPv6 自动`。

默认出口平时走 `🤖 自动` 地区 Fallback 链，由 mihomo 内核自动切区与恢复回切；看门狗不再每轮主动探活切默认代理。

## 环境变量

密钥和 API 只放进程环境（systemd `Environment=`），不要写进仓库。

| 变量 | 默认 | 说明 |
|---|---|---|
| `MIHOMO_API` | `http://127.0.0.1:19090` | 外部控制器，只支持 `http://` |
| `MIHOMO_PROXY` | `http://127.0.0.1:17890` | 探活和 Bark 用的 mixed-port |
| `MIHOMO_SECRET_FILE` | （源码里有本机默认路径） | 里面一行 API secret |
| `MIHOMO_CONFIG` | 同上 | 本机 `config.yaml`，demote 时改 filter |
| `MIHOMO_RELOAD_PATH` | `/root/.config/mihomo/config.yaml` | `PUT /configs` 时容器内路径 |
| `MIHOMO_LOG_LEVEL` | `warning` | `/logs` 级别，只能字母数字 |
| `BARK_KEY` | 空 | 空则不通知 |
| `BARK_GROUP` | `mihomo` | Bark 分组 |
| `BARK_DEVICE` | 空 | 填 `{device}` |
| `BARK_TITLE` | 见下 | 标题模板 |
| `BARK_BODY` | 见下 | 正文模板 |

`BARK_*` 也可放工作目录文件（环境变量优先）：`bark-device`、`bark-title`、`bark-body`。systemd 请设 `WorkingDirectory` 到这些文件所在目录。

## Bark 模板

占位符：`{device}` `{group}` `{old}` `{new}`。

未配 `BARK_TITLE` 时：有 device 用 `{device} | mihomo 切换`，否则 `mihomo 切换`。  
未配 `BARK_BODY` 时：`{group}: {old} → {new}`。

```text
# bark-device
书房主机

# bark-title
{device} | mihomo 切换

# bark-body
{group}: {old} → {new}
```

先走代理发 `api.day.app`，失败再直连。

## systemd 示例

```ini
[Unit]
Description=mihomo site-auto watchdog
After=docker.service
Wants=docker.service

[Service]
Type=simple
User=你的用户
ExecStart=/path/to/mihomo-watchdog --interval 8 --window 10 --fails 3 --cooldown 20
Restart=always
RestartSec=5
WorkingDirectory=/path/to/mihomo-data-parent
Environment=MIHOMO_API=http://127.0.0.1:19090
Environment=MIHOMO_SECRET_FILE=/path/to/api-secret.txt
Environment=MIHOMO_CONFIG=/path/to/config.yaml
Environment=BARK_KEY=
Environment=BARK_GROUP=mihomo

[Install]
WantedBy=multi-user.target
```

改间隔后 `daemon-reload` 再重启服务。不要和 Python `mihomo-cli watchdog` 同时跑。

## 切组时做什么

1. 失败够阈值：`PUT /proxies/{组}` 切下一个叶子。
2. PUT 弹回（常见于 fallback 组）：把当前叶子从该组 `filter` 拿掉，备份 `config.yaml.bak.<时间戳>`，再 `PUT /configs?force=true`。
3. 切 `🤖 Cursor自动` 时默认断开已死旧连接。

被看门狗纳管的站点组用 **select**，不要用 fallback 当 watchdog 切目标。

## 不要

1. 把 Bark key、真实主机地址写进文档或源码。
2. 全量探活 / apply 放宽 filter 时让 watchdog 还在切；先停再跑，结束再启。
