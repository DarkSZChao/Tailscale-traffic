# Git 工具

克隆仓库后，在仓库根目录运行一次对应脚本；可以重复运行。

Windows PowerShell：

```powershell
powershell -ExecutionPolicy Bypass -File .git-tools/setup.ps1
```

Git Bash / WSL / macOS / Linux：

```sh
sh .git-tools/setup.sh
```

也支持从任意目录使用脚本的完整路径运行，自动定位所属仓库。

安装脚本仅修改当前仓库的本地 Git 配置：

- `core.ignorecase = false`：让 Git 区分文件名大小写。
- `core.hooksPath = .git-tools/hooks`：启用自定义钩子。
- `setup.sh` 同时为钩子添加执行权限。

`hooks/pre-commit` 在提交前将当前时间写入根目录 `VERSION` 文件并自动暂存。时间使用本机时区。

`.git/config` 不随仓库同步，其他电脑克隆后也需要运行安装脚本。
