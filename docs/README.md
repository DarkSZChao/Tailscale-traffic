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
- 按设备和日期聚合访问网站、近似连接次数及上传下载流量；
- SQLite 按天持久化，面板按自然月汇总；
- 可设置月流量额度、查看月底预测；
- 可在面板中给账号设置备注名；
- 通过出口 DNS、HTTP Host 和 TLS SNI 尽力识别域名；
- 网站明细只保存按天聚合的域名或目标 IP，不记录 URL、请求内容或单条连接。

## 前提

- Linux VPS，Tailscale 已在宿主机运行并配置成出口节点；
- 使用内核网络模式，存在 `tailscale0` 网卡；
- Docker Engine 与 Docker Compose v2；
- 宿主机的 Tailscale socket 路径为 `/var/run/tailscale/tailscaled.sock`；
- 内核已启用 conntrack 流量计数；
- 当前出口节点主要用于互联网出口。如果还在同一节点配置了子网路由，经过 `tailscale0` 的子网转发流量也会计入。

## 部署

```bash
git clone <你的仓库地址>
cd <仓库目录>
```

网站流量明细需要 conntrack 字节计数。首次部署前执行：

```bash
sudo sysctl -w net.netfilter.nf_conntrack_acct=1
```

要在 VPS 重启后继续生效，将下面内容写入
`/etc/sysctl.d/99-tailscale-traffic.conf`：

```text
net.netfilter.nf_conntrack_acct=1
```

完成配置后启动：

```bash
docker compose up -d --build
```

如果从旧的单容器版本升级，首次切换需要移除旧容器，数据目录不会被删除：

```bash
docker compose down --remove-orphans
docker compose up -d --build
```

Compose 会启动两个相互独立的容器：

- `collector` 长期运行，负责流量采集和限额封锁；
- `dashboard` 提供控制面板，可以独立更新和重启。

dashboard 容器内部监听 8000，并映射到宿主机所有地址的 **4656** 端口。
请使用防火墙限制为仅允许可信来源访问：

```text
http://你的VPS的Tailscale-IP:4656
```

例如使用 UFW 只允许从 Tailscale 接口访问：

```bash
sudo ufw allow in on tailscale0 to any port 4656 proto tcp
```

首次打开面板时会要求设置密码，不需要用户名，也不再使用 `.env`。
密码只以安全哈希保存在 `traffic.db` 中。之后可以在“设置”页面修改密码；
修改后其他浏览器中的旧会话会自动失效。

不要把未加 TLS 的 4656 端口直接开放到公网；普通 HTTP 不会加密登录时
提交的密码。通过 Tailscale IP 访问时，链路由 Tailscale 加密。

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
docker compose logs collector --tail=100
```

## 数据与升级

持久化文件位于：

```text
./config.yaml        # 非敏感运行设置
./data/traffic.db    # 流量、密码哈希、会话密钥
```

采集器和面板通过文件锁安全读写 `config.yaml`，不会读取到写入一半的配置；
流量和认证数据通过 SQLite WAL 共享。备份前先停止服务，再复制整个 `data`
目录和根目录的配置文件：

```bash
docker compose stop
cp -a data data.backup
cp -a config.yaml config.yaml.backup
docker compose start
```

升级全部服务：

```bash
git pull
docker compose up -d --build
```

只更新控制面板，不中断采集：

```bash
docker compose up -d --build dashboard
```

停止容器不会删除数据，宿主机里的计数链也会保留，采集器重新启动后会继续计算差值。宿主机重启导致计数器归零时，程序会自动从新值继续累计。面板修改限额后，采集器会在下一轮采集时执行，默认最多延迟约 10 秒。

月度总额度、采集间隔、网站记录保留天数和统计时区均在“设置”页面管理，
并保存在 `./config.yaml`。网站明细采集固定启用。
collector 会自动读取更新后的配置。密码哈希和会话密钥仍只保存在
`traffic.db`。从旧版本升级时，数据库中的运行配置会自动迁移到 YAML，
迁移成功后删除旧配置表。

网站明细默认保留 180 天，按“日期 + 设备 + 域名”聚合，不保存 URL、
请求路径或单条连接。

设备列表默认隐藏“密钥已过期且所选月份流量为 0”的节点。开启“显示
Expired 设备”后可查看这些历史节点；过期但所选月份有流量的设备始终显示，
并保留 `Expired` 标记。

用户卡片中的设备列表默认收起，点击用户左侧的小三角可以展开或再次隐藏；
面板自动刷新时会保留当前展开状态。

Tailscale 会隐藏外部共享节点的真实主机名。未设置设备备注时，面板按 IPv4
最后一段显示为 `SHARED-DEVICE-xxx`；设备备注按稳定设备 ID 保存在
`traffic.db`，清空备注即可恢复默认名称。

域名识别采用三种轻量来源：

- 将 VPS 出口 DNS 响应保存为最多 5 分钟的公共 IP→域名候选映射；
- 对明文 HTTP 新连接读取 `Host` 请求头；
- 对 TCP HTTPS 新连接读取 TLS ClientHello 中未加密的 SNI。

抓包套接字附加了内核过滤器，只将 DNS 响应及可能包含 HTTP Host/TLS SNI
的连接起始包交给 Python。视频和下载连接建立后的数据包不会进入解析流程。
连接级域名映射和 DNS 映射均为有界内存缓存，不写入原始数据包。

## 统计口径

- “上传”：朋友设备进入出口节点、准备发往公网的 IP 层字节；
- “下载”：公网响应准备从出口节点发往朋友设备的 IP 层字节；
- “总计”：上传 + 下载；
- VPS 服务商可能按网卡层、仅出站、十进制 GB 或 GiB 计费，因此本面板与账单会有少量差异；
- 每台设备第一次出现在出口节点状态里后，程序才会为它建立独立计数。
- 用户限额使用该用户所有设备的当月总量；设备限额从本版本部署后开始按设备累计。
- 达到限额时封锁设备的 IPv4 和 IPv6。手动解锁仅跳过当月，次月自动重新执行规则。
- 网站访问次数按新连接近似统计，不代表浏览器页面打开次数；
- DNS、HTTP Host 和 TLS SNI 都属于尽力识别。QUIC/HTTP3、ECH、VPN
  套 VPN、分段握手或直接连接 IP 时仍可能只显示目标 IP；
- CDN IP 可能同时服务多个域名，公共 DNS 回退可能偶尔显示同一 IP 最近解析的
  其他域名；同一连接的 TLS SNI/HTTP Host 会优先于公共 DNS；
- 网站明细依赖周期性 conntrack 快照，识别流量可能低于设备总流量。

## 安全说明

只有 `collector` 容器使用宿主机网络并具有 `NET_ADMIN`、`NET_RAW`
能力，这是读取流量、捕获 DNS/连接握手元数据、维护计数规则和执行限额封锁
所必需的。
`dashboard` 使用普通 bridge 网络，不接触宿主机防火墙和 Tailscale
socket。没有配置限额规则时不会封锁任何设备。采集器创建以下自有链和集合：

- `TSM_UPLOAD`
- `TSM_DOWNLOAD`
- `tsm_upload4` / `tsm_download4`
- `tsm_upload6` / `tsm_download6`
- `tsm_block4` / `tsm_block6`
- `tsm_block4_next` / `tsm_block6_next`（用于原子更新封锁名单）

请只使用可信镜像构建和可信仓库代码。
