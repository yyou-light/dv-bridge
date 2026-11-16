# 快速上手

## 前置条件

- Windows、Windows PowerShell 5.1、Python 3.10+ 和支持 CMS/OAEP 的 OpenSSL。
- 已获准使用且已经登录的 ETX 图形会话，启用与 Windows 的文本剪贴板同步。
- Linux Python 3.10+，带 Tk/X11 支持；当前账号可读写自己的安装/队列目录。
- 跑业务 case 时另需自己的工程、LSF、`simmer` 和 EDA 环境。本包不提供这些软件或许可证。

Windows 建议将源码放在 `D:\proj\etx-clipboard-bridge` 这样的独立项目目录。不要放入云盘同步目录。

## 首次安装一次

1. Windows 在源码根目录运行 `python scripts/configure.py windows`。填写 Linux 账号、安装根、工程根、回归根和 Python 路径。可选环境脚本。OpenSSL 不在 PATH 时加 `--openssl <本机程序路径>`。
2. 配置程序生成 `.private/bootstrap/etx-clipboard-bridge-setup.zip`。通过你已有、获准的文件传递方式将它放到刚才填写的 Linux 安装目录并解压。该个人引导包含路径配置及客户端公钥，**不含客户端私钥**；不要将个人引导包上传到公共仓库。
3. 在 Linux 解压目录运行 `python3 scripts/configure.py linux`。它核对账号与目录、验证发布文件摘要，生成 Linux 独立身份和端点配置，并输出 `SERVER_FINGERPRINT`。
4. 在已有图形 ETX 终端运行 `python3 scripts/start.py endpoint`，确认返回 `ready`。随后 Windows 运行 `python scripts/start.py pair <SERVER_FINGERPRINT>`。只需传递公钥指纹，不发送密码或私钥。
5. 按需在不同终端运行 `python3 scripts/start.py worker work01` 等。最多五个不同编号，每个终端一条，保持运行。CLI 用 `workers` 查询新的登记，不使用别人的 Worker ID。

首次配置需要自己准确填写路径；日常启动不再编辑 JSON。若默认 `python3` 版本不足，以上命令换成选定解释器的绝对路径。

## 日常任务

所有 CLI 操作先提供一个随机的 32 位十六进制操作号，结果保存在 `.work/x11/`。当前任务授权仍由操作者负责。

```text
python clients/etx_cli.py --operation-id <操作号> workers
python clients/etx_cli.py --operation-id <操作号> read --remote <准确文本路径> --name local.txt
python clients/etx_cli.py --operation-id <操作号> status-many --request-id <原任务号1> --request-id <原任务号2>
```

跑 case 是单独操作，需要明确授权：

```text
python clients/etx_cli.py --operation-id <操作号> submit --case <准确case名> --seed 0 --profile work01
```

多路使用 `submit-many --jobs-file <私有JSON路径>`。列表每项为 `{"case":"demo_case","seed":0,"profile":"work01"}`，最多五个不同编号，任务文件放在 `.private/x11/session/`。示例不是预装 case，不要自动运行。

## 重启恢复

在实际图形 ETX 中启动 `scripts/start.py endpoint`，它使用当前主机和 DISPLAY，保留身份和事务。只对已核实身份的本实例旧接收进程进行优雅交接，不终止 ETX 会话。发现其他节点仍有活跃端点时会停止并报告。

Worker 可以在可访问工程和队列的 ETX 节点启动。不要重复启动仍在线的编号，不因重启而清队列。`needs_review` 需要核对原任务和资源；不同编号可继续使用。
