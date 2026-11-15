# 配置

实际配置位于 `.private/site.json`，Linux 由当前账号持有且权限为 `0600`。公共仓库仅提供 `config/site.example.json`。环境变量 `ETX_X11_SITE` 可以显式指定同样受保护的配置文件。

| 字段 | 含义 |
| --- | --- |
| `remote.user` | Linux 账号，启动时核对当前身份 |
| `remote.install_root` | Linux 中本发布包的准确安装根 |
| `remote.project_root` / `regression_root` | 工程工作目录及原生日志/结果根 |
| `remote.queue_root` / `lock_root` | 此实例自己的队列与锁；所有参与者使用一致的配置 |
| `remote.python` / `openssl` | Linux 工具路径，单个程序名或准确路径，不是 Shell 命令 |
| `remote.environment_script` / `lsf_module` | 可选项目环境脚本和 LSF 模块 |
| `remote.lsf_queue` / `target` / `simulator` | 现有 LSF/simmer 适配的队列、target 与输出命名信息 |
| `remote.fsdb_name` | 本 flow 的 FSDB 文件名，默认 `waves.fsdb` |
| `permissions.read_roots` / `write_roots` | 显式文件范围；写范围必须在读范围内，不能为 `/` |
| `permissions.wave_fsdbs` | 已授权、已完成 FSDB 的准确路径，禁止父目录代替白名单 |
| `wave.enabled` / `root` / `release` | 可选外部后端与准确发布摘要；默认关闭 |
| `wave.compatibility_patch` | `none` 或已验证的 `time-loop-v1`，不能静默适配未知后端 |
| `monitor_interval_seconds` | 跟进运行任务的默认间隔，当前为 `300` 秒 |

文件范围来自操作者自己的配置，不自动开放整个 NFS 或安装/凭据目录。Linux 账号、路径、工具和波形后端须按自己的站点填写；共享目录可见不代表已有派单权限。

配置文件中的 `simulator` 用于现有输出命名，不代表包已支持所有仿真器。业务执行适配目前沿用 LSF + `simmer`；其他 flow 要单独适配并验收。

Windows 和 Linux 的私钥分别生成，不打入公共发布包。Windows `.private/` ACL 限制到当前身份及 SYSTEM；Linux 配置、身份和队列使用当前用户的私有权限。

波形适配要求使用者已有兼容的 xverif 后端、LSF 和许可，且配置两端相同的准确 FSDB 清单。后端的厂商软件、库和许可证均不在本仓库。来源部署验收的是 `verdi/Y-2026.03-1S`；实际版本由外部后端配置，本工具不会自动切换，其他版本须另行验证。
