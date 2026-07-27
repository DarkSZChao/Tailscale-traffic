# Tailscale 流量控制面板

一个部署在 Tailscale Linux 出口节点上的轻量流量面板，按朋友和设备统计上传、下载与每月总用量。

![Python](https://img.shields.io/badge/Python-3.12-3776AB)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)
![License](https://img.shields.io/badge/License-MIT-c7f36b)

## 为什么需要它

Tailscale 官方的 [Network flow logs](https://tailscale.com/docs/features/logging/network-flow-logs) 包含出口流量字节计数，但目前只适用于 Premium 和 Enterprise 套餐，而且管理控制台不提供实时用量页面。

Tailscale 流量控制面板不依赖付费 API。它在 VPS 本机的 Linux 转发链上自动发现并按 Tailscale IP 计数，再通过 `tailscaled` 的 LocalAPI WhoIs 把 IP 映射为账号与设备。即使朋友来自外部 tailnet、没有出现在普通的 `tailscale status` 列表里，也能被识别：

- 分别统计上传和下载；
- 按账号合并同一朋友的多台设备；
- 区分本 Tailnet 设备与通过节点分享接入的外部设备；
- 可为用户总量或单台设备设置月度限额，超限后自动封锁；
- SQLite 按天持久化，面板按自然月汇总；
- 可设置月流量额度、查看月底预测；
- 可在面板中给账号设置备注名；
- 只记录字节数，不记录内容、域名或目标 IP。

## 前提

- Linux VPS，Tailscale 已在宿主机运行并配置成出口节点；
- 使用内核网络模式，存在 `tailscale0` 网卡；
- Docker Engine 与 Docker Compose v2；
- 宿主机的 Tailscale socket 路径为 `/var/run/tailscale/tailscaled.sock`；
- 当前出口节点主要用于互联网出口。如果还在同一节点配置了子网路由，经过 `tailscale0` 的子网转发流量也会计入。

## 部署

```bash
git clone <你的仓库地址>
cd <仓库目录>
cp .env.example .env
nano .env
docker compose up -d --build
```

`.env` 至少要修改：

```dotenv
DASHBOARD_PASSWORD=换成一个足够长的随机密码
MONTHLY_QUOTA_GB=3000
TZ=America/Los_Angeles
```

容器启动后，面板监听 **4658** 端口。建议只从 Tailscale 网络访问：

```text
http://你的VPS的Tailscale-IP:4658
```

如果 VPS 使用 UFW，可以仅允许 Tailscale 网卡访问面板：

```bash
sudo ufw allow in on tailscale0 to any port 4658 proto tcp
```

打开面板后只需输入 `DASHBOARD_PASSWORD`，不需要用户名。不要把未加 TLS 的 4658 端口直接开放到公网；普通 HTTP 不会加密登录时提交的密码。通过 Tailscale IP 访问时，链路由 Tailscale 加密。

## 查看状态

```bash
docker compose ps
docker compose logs -f --tail=100
```

正常时页面右上角显示“采集正常”。首次启动只能从程序创建计数规则以后开始记录，无法补回此前的历史流量。

如果页面显示采集异常，优先检查：

```bash
ls -l /var/run/tailscale/tailscaled.sock
ip link show tailscale0
docker compose logs --tail=100
```

## 数据与升级

所有持久数据位于：

```text
./data/traffic.db
```

备份这个文件即可保留历史记录。升级代码：

```bash
git pull
docker compose up -d --build
```

停止容器不会删除数据，宿主机里的计数链也会保留，重新启动后会继续计算差值。宿主机重启导致计数器归零时，程序会自动从新值继续累计。

## 统计口径

- “上传”：朋友设备进入出口节点、准备发往公网的 IP 层字节；
- “下载”：公网响应准备从出口节点发往朋友设备的 IP 层字节；
- “总计”：上传 + 下载；
- VPS 服务商可能按网卡层、仅出站、十进制 GB 或 GiB 计费，因此本面板与账单会有少量差异；
- 每台设备第一次出现在出口节点状态里后，程序才会为它建立独立计数。
- 用户限额使用该用户所有设备的当月总量；设备限额从本版本部署后开始按设备累计。
- 达到限额时封锁设备的 IPv4 和 IPv6。手动解锁仅跳过当月，次月自动重新执行规则。

## 安全说明

容器使用宿主机网络并具有 `NET_ADMIN` 能力，这是读取、维护计数规则和执行限额封锁所必需的。没有配置限额规则时不会封锁任何设备。程序创建以下自有链和集合：

- `TSM_UPLOAD`
- `TSM_DOWNLOAD`
- `tsm_upload4` / `tsm_download4`
- `tsm_upload6` / `tsm_download6`
- `tsm_block4` / `tsm_block6`
- `tsm_block4_next` / `tsm_block6_next`（用于原子更新封锁名单）

请只使用可信镜像构建和可信仓库代码。

## 本地演示

没有 Linux Tailscale 出口节点时，可以用演示数据预览页面：

```bash
docker build -t tailscale-traffic .
docker run --rm -p 4658:4658 \
  -e TSM_DEMO=true \
  -e DASHBOARD_PASSWORD=demo \
  tailscale-traffic
```

然后访问 `http://127.0.0.1:4658`，输入密码 `demo`。

## Windows 本地真实流量测试

Windows 出口节点使用 Tailscale userspace 转发，无法使用 Linux
`iptables` 采集器。本项目提供独立的 Windows 测试采集器，它读取
`tailscale debug capture` 的 IP 层数据，只累计 Tailscale IP 与公网 IP
之间的出口流量，不记录包内容、域名或目标地址。

1. 在 Windows Tailscale 中启用“作为出口节点运行”，并在管理后台批准；
2. 让另一台设备选择这台 Windows 电脑作为出口节点；
3. 安装依赖后，在 PyCharm 中右键运行 `run_windows.py`；
4. 访问 `http://127.0.0.1:4658`，使用 `.env` 中的面板密码登录。

Windows 测试数据单独保存在 `data/windows-traffic.db`。此模式用于本地验证；
VPS 正式部署仍推荐使用默认的 Linux 防火墙采集器。Windows 模式可以测试
限额界面和超限判断，但不会实际封锁设备。
