# sysmon_tools

Windows 桌面浮窗，只读查看本机谁在吃 CPU / 内存 / GPU，哪些服务、队列、定时任务和批处理在跑；超阈值时把当时的占用进程记到 `logs/`。

## 运行

Python 3.10+，依赖 `psutil`、`pywin32`；要看 Redis 面板再装 `redis`。

```
pythonw sysmon.py            # 打开浮窗
python  sysmon.py --selftest # 不开窗口，各采集项跑一轮打印结果
```

浮窗状态行右侧的「迷你 / 展开」按钮切换只显示四个指标的小窗（双击指标区也可以）。

## 本机配置

代码里不写任何本机信息。端口、Windows 服务、HTTP 检查、Redis 键名、进程归属规则、锁 / 日志 / 状态文件目录都写在本地 `settings.json`（已 gitignore，不进仓库），格式见 `settings.example.json`。没配置的面板不显示。

## 只读约束

- 没有结束进程；不连任何数据库；Redis 只发读命令（SCAN / GET / MGET / HLEN / ZCARD / SCARD），连不上 1 秒放弃、不重试。
- 读别人的文件带 `FILE_SHARE_DELETE` 打开，不挡对方改名 / 删除 / 原子替换；锁文件只看目录项。
- 采样在后台低优先级线程，单项失败只在状态栏标红；线程退出会被重启；只允许一个实例。
- 只写本目录下的 `logs/`（按天、每天上限 20 MB、保留 14 天）和 `settings.json`（只回写窗口位置、置顶、所在页）。

## 日志（不进仓库）

- `logs/spikes-YYYYMMDD.jsonl`：CPU / 内存 / GPU / 显存连续 2 次超阈值（默认 90 / 85 / 90 / 85）时的前 6 名进程及归属。
- `logs/history-YYYYMMDD.jsonl`：每分钟一行总量和前三名。
- `logs/sysmon-error.log`：工具自身异常。
