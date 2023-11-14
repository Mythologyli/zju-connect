# ZJU Connect

> 🚫 **免责声明**
>
> 本程序**按原样提供**，作者**不对程序的正确性或可靠性提供保证**，请使用者自行判断具体场景是否适合使用该程序，**使用该程序造成的问题或后果由使用者自行承担**！

---

**本程序基于 [EasierConnect](https://github.com/lyc8503/EasierConnect)（现已停止维护）完成，感谢原作者 [lyc8503](https://github.com/lyc8503)。**

**QQ 交流群：946190505**，欢迎来自 ZJU 的使用者加入交流。

### 使用方法

#### 直接运行

*Windows 用户可以使用 GUI 版 [ZJU Connect for Windows](https://github.com/mythologyli/zju-connect-for-Windows)。*

1. 在 [Release](https://github.com/mythologyli/zju-connect/releases) 页面下载对应平台的最新版本。

2. 以 macOS 为例，解压出可执行文件 `zju-connect`。

3. macOS 需要先解除安全限制。命令行运行：`sudo xattr -rd com.apple.quarantine zju-connect`。

4. 命令行运行：`./zju-connect -username <上网账户> -password <密码>`。

5. 此时 `1080` 端口为 Socks5 代理，`1081` 端口为 HTTP 代理。如需更改默认端口，请参考参数说明。

#### 作为服务运行

**请先直接运行，确保无误后再创建服务，避免反复登录失败导致 IP 被临时封禁！**

对于 Ubuntu/Debian、RHEL 系、Arch 等基于 Systemd 的 Linux 发行版，除按照上述方法运行外，亦可通过以下步骤将 ZJU Connect 安装为系统服务，实现自动重连功能：

1. 在 [Release](https://github.com/Mythologyli/ZJU-Connect/releases) 页面下载对应平台的最新版本，将可执行文件放置于 `/opt` 目录并赋予可执行权限。

2. 在 `/etc` 下创建 `zju-connect` 目录，并在目录中创建配置文件`config.toml`，内容参照仓库中的 `config.toml.example`。

3. 在 `/lib/systemd/system` 下创建 `zju-connect.service` 文件，内容如下：

   ```
   [Unit]
   Description=ZJU Connect
   After=network-online.target
   Wants=network-online.target
   
   [Service]
   Restart=on-failure
   RestartSec=5s
   ExecStart=/opt/zju-connect -config /etc/zju-connect/config.toml
   
   [Install]
   WantedBy=multi-user.target
   ```

4. 执行以下命令启用服务并设置自启：
   ```
   $ sudo systemctl start zju-connect
   $ sudo systemctl enable zju-connect
   ```

对于 macOS 平台，系统服务的安装与运行基于 `launchctl`，使用上与 `systemctl` 有一定差异，可通过下述方案实现后台自动重连、开机自启动等功能：

1. 在 [Release](https://github.com/mythologyli/zju-connect/releases) 页面下载对应 darwin 平台的最新版本。

2. 将可执行文件放置于 `/usr/local/bin/` 目录并赋予可执行权限。

3. 解除安全限制：`sudo xattr -rd com.apple.quarantine zju-connect`。

4. 参考 [com.zju.connect.plist](com.zju.connect.plist) 建立 macOS 系统服务配置文件，plist 文件为二进制文件，建议使用 PlistEdict Pro 编辑，其中关键配置参数如下：

   + `UserName`: 后台运行 zju-connect 的的用户默认为 `root`，建议修改为你自己的用户名
   + `ProgramArguments`: zju-connect 运行参数
   + `StandardErrorPath`: 输出 zju-connect 运行日志的目录（用于调试，可不指定）
   + `StandardOutPath`: 输出 zju-connect 运行日志的目录（用于调试，可不指定）
   + `RunAtLoad`: 是否开机自启动
   + `KeepAlive`: 是否后台断开重连

   详细参数配置可参考以下文档：

   + [plist 配置参数文档](https://keith.github.io/xcode-man-pages/launchd.plist.5.html#OnDemand)
   + [Apple开发者文档](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/Introduction.html#//apple_ref/doc/uid/10000172i-SW1-SW1)

5. 移动配置文件至 `/Library/LaunchDaemons/` 目录，同时执行以下命令:
   ```zsh
   $ cd /Library/LaunchDaemons
   $ sudo chown root:wheel com.zju.connect.plist
   ```

6. 执行以下命令启用服务并设置自启：
   ```zsh
   $ sudo launchctl load com.zju.connect.plist
   ```

7. 执行以下命令关闭自启动服务：
   ```zsh
   $ sudo launchctl unload com.zju.connect.plist
   ```

如需开关服务，可直接在 macOS 系统设置中的后台程序开关 zju-connect。

对于 OpenWrt 系统，可通过 procd init 脚本让 zju-connect 开机自启、后台运行，在代理插件中添加对应本机节点和分流规则即可正常使用。

1. 从 [Release](https://github.com/Mythologyli/ZJU-Connect/releases) 页面下载对应平台的最新 linux 版本，将可执行文件保存为 `/usr/bin/zju-connect` 并赋予可执行权限。

2. 参照仓库中的 `config.toml.example`，创建配置文件 `/etc/back2zju.toml`，配置好 socks/http 代理端口，因通过代理插件实现分流，建议将 zju-connect 的配置项 `proxy_all` 设置为 `true`。

3. 将以下内容保存为 `/etc/init.d/back2zju` 并赋予可执行权限：

   ```shell
   #!/bin/sh /etc/rc.common
   
   USE_PROCD=1
   START=60
   STOP=03
   
   PROGRAM="/usr/bin/zju-connect"
   NET_CHECKER="rvpn.zju.edu.cn"
   CONFIG_FILE="/etc/back2zju.toml"
   LOG_FILE="/var/log/back2zju.log"
   
   boot() {
   	ubus -t 10 wait_for network.interface.wan 2>/dev/null
   	sleep 10
   	rc_procd start_service
   }
   
   start_service() {
       ping -c1 ${NET_CHECKER} >/dev/null || ping -c1 ${NET_CHECKER} >/dev/null || return 1
       procd_open_instance
       procd_set_param command /bin/sh -c "${PROGRAM} -config ${CONFIG_FILE} >>${LOG_FILE} 2>&1"
       procd_set_param respawn 3600 5 3
       procd_set_param limits core="unlimited"
       procd_set_param limits nofile="200000 200000"
       procd_set_param file ${CONFIG_FILE}
       procd_close_instance
       logger -p daemon.warn -t back2zju 'Service has been started.'
   }
   
   reload_service() {
       stop
       start
       logger -p daemon.warn -t back2zju 'Service has been restarted.'
   }
   ```

4. 执行以下命令：

   ```shell
   /etc/init.d/back2zju enable
   /etc/init.d/back2zju start
   ```

   或通过 OpenWrt LuCi 网页的 `系统-启动项` 启用并启动 `back2zju`（也可在此处停用服务）。

   随后 zju-connect 将开始运行，支持开机自启动，其运行日志保存在 `/var/log/back2zju.log`

5. 在代理插件中添加对应本机节点和分流规则

   根据在 `/etc/back2zju.toml` 中的配置，在代理插件中添加本机节点。ip 填写 `127.0.0.1`，端口号/协议与 `/etc/back2zju.toml` 保持一致，若设置了 socks 用户名和密码也需要填写。

   然后在对应代理插件中添加分流规则，具体操作略。

   注意事项：

   1. ZJU 校园网使用的内网 IP 段是 `10.0.0.0/8`，可能需要将此 IP 段从代理插件的直连列表/局域网列表中移除并添加至代理列表。

   2. 请确保使用的 RVPN 服务器与 OpenWrt 直连。若未将 `rvpn.zju.edu.cn` 配置为直连，此域名可能匹配分流规则与其他 `zju.edu.cn` 流量一样被发往 zju-connect 代理，这会造成网络异常。

#### Docker 运行

```zsh
$ docker run -d --name zju-connect -v $PWD/config.toml:/home/nonroot/config.toml -p 1080:1080 -p 1081:1081 --restart unless-stopped mythologyli/zju-connect
```

也可以使用 Docker Compose。创建 `docker-compose.yml` 文件，内容如下：

```yaml
version: '3'

services:
   zju-connect:
      image: mythologyli/zju-connect
      container_name: zju-connect
      restart: unless-stopped
      ports:
         - 1080:1080
         - 1081:1081
      volumes:
         - ./config.toml:/home/nonroot/config.toml
```

并在同目录下运行

```zsh
$ docker compose up -d
```

### 参数说明

+ `server`: SSL VPN 服务端地址，默认为 `rvpn.zju.edu.cn`

+ `port`: SSL VPN 服务端端口，默认为 `443`

+ `username`: 网络账户。例如：学号

+ `password`: 网络账户密码

+ `disable-server-config`: 禁用服务端配置，一般不需要加此参数

+ `disable-zju-config`: 禁用 ZJU 相关配置，一般不需要加此参数

+ `disable-zju-dns`: 禁用 ZJU DNS 改用本地 DNS，一般不需要加此参数

+ `disable-multi-line`: 禁用自动根据延时选择线路。加此参数后，使用 `server` 参数指定的线路

+ `proxy-all`: 是否代理所有流量，一般不需要加此参数

+ `socks-bind`: SOCKS5 代理监听地址，默认为 `:1080`

+ `socks-user`: SOCKS5 代理用户名，不填则不需要认证

+ `socks-passwd`: SOCKS5 代理密码，不填则不需要认证

+ `http-bind`: HTTP 代理监听地址，默认为 `:1081`。为 `""` 时不启用 HTTP 代理

+ `tun-mode`: TUN 模式（实验性）。请阅读后文中的 TUN 模式注意事项

+ `add-route`: 启用 TUN 模式时根据服务端下发配置添加路由

+ `dns-ttl`: DNS 缓存时间，默认为 `3600` 秒

+ `disable-keep-alive`: 禁用定时保活，一般不需要加此参数

+ `zju-dns-server`: ZJU DNS 服务器地址，默认为 `10.10.0.21`

+ `secondary-dns-server`: 当使用 ZJU DNS 服务器无法解析时使用的备用 DNS 服务器，默认为 `114.114.114.114`。留空则使用系统默认 DNS，但在开启 `dns-hijack` 时必须设置

+ `dns-server-bind`: DNS 服务器监听地址，默认为空即禁用。例如，设置为 `127.0.0.1:53`，则可向 `127.0.0.1:53` 发起 DNS 请求

+ `dns-hijack`: 启用 TUN 模式时劫持 DNS 请求，建议在启用 TUN 模式时添加此参数

+ `debug-dump`: 是否开启调试，一般不需要加此参数

+ `tcp-port-forwarding`: TCP 端口转发，格式为 `本地地址-远程地址,本地地址-远程地址,...`，例如 `127.0.0.1:9898-10.10.98.98:80,0.0.0.0:9899-10.10.98.98:80`。多个转发用 `,` 分隔

+ `udp-port-forwarding`: UDP 端口转发，格式为 `本地地址-远程地址,本地地址-远程地址,...`，例如 `127.0.0.1:53-10.10.0.21:53`。多个转发用 `,` 分隔

+ `custom-dns`: 指定自定义DNS解析结果，格式为 `域名:IP,域名:IP,...`，例如 `www.cc98.org:10.10.98.98,appservice.zju.edu.cn:10.203.8.198`。多个解析用 `,` 分隔:

+ `twf-id`: twfID 登录，调试用途，一般不需要加此参数

+ `config`: 指定配置文件，内容参考 `config.toml.example`。启用配置文件时其他参数无效

### TUN 模式注意事项

1. 需要管理员权限运行

2. Windows 系统需要前往 [Wintun 官网](https://www.wintun.net)下载 `wintun.dll` 并放置于可执行文件同目录下

3. 为保证 `*.zju.edu.cn` 解析正确，建议配置 `dns-hijack` 劫持系统 DNS

4. macOS 暂不支持通过 TUN 接口访问 `10.0.0.0/8` 外的地址

### 计划表

#### 已完成

- [x] 代理 TCP 流量
- [x] 代理 UDP 流量
- [x] SOCKS5 代理服务
- [x] HTTP 代理服务
- [x] ZJU DNS 解析
- [x] ZJU 规则添加
- [x] 支持 IPv6 直连
- [x] DNS 缓存加速
- [x] 自动选择线路
- [x] TCP 端口转发功能
- [x] UDP 端口转发功能
- [x] 通过配置文件启动
- [x] 定时保活
- [x] TUN 模式
- [x] 自动劫持 DNS

#### To Do

- [ ] Fake IP 模式

### 贡献者

<a href="https://github.com/mythologyli/zju-connect/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=mythologyli/zju-connect" />
</a>

### 感谢

+ [EasierConnect](https://github.com/lyc8503/EasierConnect)

+ [socks2http](https://github.com/zenhack/socks2http)
