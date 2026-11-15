# dv-bridge

通过已经登录的 ETX/X11 会话，在 Windows 与 Linux 之间进行受控文件收发、五路 Terminal Worker 派单和可选的原位波形查询。不新增网络监听端口，不依赖 GitHub Runner。

项目仓库：[yyou-light/dv-bridge](https://github.com/yyou-light/dv-bridge)。当前基线版本：`0.1.0`。

## 包含什么

| 能力 | 当前基线 |
| --- | --- |
| 常驻文件端点 | 配对、UTF-8 文本读取/批量增量读取、受控搜索、事务上传与恢复 |
| Worker | `work01`～`work05`，独立请求号、签名命令、任务与输出资源占用 |
| 批量客户端 | 批量派单、合并状态、批量结果；已完成提交复用，不确定提交不重派 |
| 波形 | 可选客户端及受限任务适配；需匹配的空闲 Worker，以及自行提供的 xverif/Verdi/NPI 后端 |
| 剪贴板 | 保存可恢复内容、中断后等待 30 秒静默、原请求重试；仍为共享剪贴板 |
| 监控频率 | 有仿真运行时每 300 秒合并查询，空闲不查询 Worker |

不包含业务工程、实际配置/身份、商业 EDA 软件、GitHub Runner 管理、旧一次性协议、Confluence 下载和独立 Window Station 实验。新用户使用自己的账号、路径、队列和密钥。

## 开始使用

先阅读[快速上手](docs/QUICKSTART.md)。首次安装需要将一份只包含公共源码、路径设置及客户端公钥的个人引导包放到已有访问权限的 Linux 目录。私钥留在各自本机。

```text
Windows: python scripts/configure.py windows
Linux:   python3 scripts/configure.py linux
Linux:   python3 scripts/start.py endpoint
Windows: python scripts/start.py pair <Linux 输出的 SERVER_FINGERPRINT>
```

日常重启不重装。在已有图形 ETX 终端启动端点；在各 Worker 终端按需选择编号：

```bash
python3 scripts/start.py endpoint
python3 scripts/start.py worker work01
python3 scripts/start.py worker work02
python3 scripts/start.py worker work03
python3 scripts/start.py worker work04
python3 scripts/start.py worker work05
```

`python3` 应为配置的 Python 3.10+ 解释器；可替换为它的绝对路径。端点返回 `ready` 后可关闭启动终端，承载通道的 ETX 会话保持可用；Worker 终端保持运行。Worker 注册本身不启动仿真。

## 目录

```text
etx/             Linux 协议、常驻端点、文件事务和固定任务
local/           Windows 核心传输
worker-runtime/  唯一 Worker 队列与仿真/FSDB 适配
clients/         唯一 PowerShell 入口、CLI、可选 MCP
scripts/         初始配置、短启动入口、发布包构建
config/          通用配置示例与源码摘要清单
tests/           合成单元测试与惰性委托测试
docs/            配置、运维、性能与已知限制
```

## 验证与打包

从仓库根目录执行，不访问真实剪贴板、不启动业务仿真：

```text
python -m unittest discover -s tests -v
python scripts/build_release.py --check
python scripts/build_release.py
```

发布 ZIP 只使用 `release-files.txt` 的明确清单，不遍历真实配置和运行目录。修改源码后须重新构建摘要清单，并保留 LF 换行。

## 验收边界

来源部署已完成五路真实合成派单、文件往返和指定波形查询；本基线增加账号/路径配置化和独立初装入口。配置化分享版的测试结果见[基线状态](docs/BASELINE.md)，不得把来源部署结果冒充另一账号、另一站点的实机验收。

已知限制、依赖和跨节点锁注意事项见[运维与限制](docs/OPERATIONS.md)。本仓库尚未设置开源许可证。
