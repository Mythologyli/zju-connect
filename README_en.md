# ZJU Connect

> 🚫 **Disclaimer**
>
> This program is provided **as is**, and the author **does not guarantee the correctness or reliability of the program**. Please judge whether the specific scenario is suitable for using this program. **The problems or consequences caused by using this program are borne by the user**!

---

[中文](README.md) | English

**This program is based on [EasierConnect](https://github.com/lyc8503/EasierConnect) (now Archived), thanks to the original author [lyc8503](https://github.com/lyc8503).**

**QQ group: 946190505**, welcome to join the discussion.

### Usage

#### Run directly

*Windows users can use the GUI version [ZJU Connect for Windows](https://github.com/mythologyli/zju-connect-for-Windows) (There's only Chinese GUI).*

1. Download the latest version of the corresponding platform on the [Release](https://github.com/mythologyli/zju-connect/releases) page.

2. Take macOS as an example, unzip the executable file `zju-connect`.

3. macOS needs to remove security restrictions first. Run in the command line: `sudo xattr -rd com.apple.quarantine zju-connect`.

4. Run in the command line: `./zju-connect -username <username> -password <password>`.

5. At this time, port `1080` is the Socks5 proxy, and port `1081` is the HTTP proxy. If you need to change the default port, please refer to [Arguments](#Arguments).

#### Run as a service

**Please first run directly to ensure that there is no error before creating a service, so as to avoid repeated login failures resulting in temporary IP ban!**

For Linux distributions based on Systemd such as Ubuntu/Debian, RHEL, Arch, etc., in addition to running as described above, ZJU Connect can also be installed as a system service through the following steps to achieve automatic reconnection function:

1. Download the latest version of the corresponding platform on the [Release](https://github.com/mythologyli/zju-connect/releases) page, place the executable file in the `/opt` directory and grant executable permissions.

2. Create the `zju-connect` directory under `/etc`, and create the configuration file `config.toml` in the directory. The content refers to `config.toml.example` in the repository.

3. Create the `zju-connect.service` file under `/lib/systemd/system`, and the content is as follows:

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

4. Execute the following command to enable the service and set it to start automatically:
   ```shell
   sudo systemctl start zju-connect
   sudo systemctl enable zju-connect
   ```

For MacOS, system services are based on `launchd`, which is different from `systemd`. You can apply the following steps to achieve the same effect:

1. Download the latest version pf darwin platform on the [Release](https://github.com/mythologyli/zju-connect/releases) page.

2. Place the executable file in the `/usr/local/bin/` directory and grant executable permissions.

3. Remove security restrictions: `sudo xattr -rd com.apple.quarantine zju-connect`.

4. Create `plist` file referring to [com.zju.connect.plist](com.zju.connect.plist). Since `plist` is a binary file, it's recommended to edit using PlistEdict Pro. Here are some key configurations:

    + `UserName`: The default user for running zju-connect in the background is `root`, it's recommended to change to your own username.
    + `ProgramArguments`: zju-connect running parameters.
    + `StandardErrorPath`: The directory for outputting zju-connect running logs (for debugging, can be omitted).
    + `StandardOutPath`: The directory for outputting zju-connect running logs (for debugging, can be omitted).
    + `RunAtLoad`: Whether to start automatically at boot.
    + `KeepAlive`: Whether to reconnect in the background.

    For more details, please refer to the following documents:

   + [plist argument docs](https://keith.github.io/xcode-man-pages/launchd.plist.5.html#OnDemand)
   + [Apple Developer docs](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/Introduction.html#//apple_ref/doc/uid/10000172i-SW1-SW1)

5. Move the `plist` file to `~/Library/LaunchDaemons/` directory, and execute the following command:
   ```zsh
   cd /Library/LaunchDaemons
   sudo chown root:wheel com.zju.connect.plist
   ```

6. Execute the following command to enable the service and set it to start automatically:
   ```zsh
   sudo launchctl load com.zju.connect.plist
   ```

7. Execute the following command to disable the service:
   ```zsh
   sudo launchctl unload com.zju.connect.plist
   ```

If you need to turn on/off the service, you can directly turn on/off zju-connect in the background program switch in macOS system settings.

For OpenWrt system, you can use procd init script to make zju-connect start automatically and run in the background. Add corresponding node and routing rules in the proxy plugin to use.

1. Download the latest version of the corresponding platform on the [Release](https://github.com/mythologyli/zju-connect/releases) page, place the executable file in the `/usr/bin` directory and grant executable permissions.

2. Refer to `config.toml.example` in the repository, create the configuration file `/etc/back2zju.toml`, configure the socks/http proxy port, and because routing is implemented through the proxy plugin, it's recommended to set the zju-connect configuration item `proxy_all` to `true`.

3. Save the following content as `/etc/init.d/back2zju` and grant executable permissions:

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

4. Execute the following command:

   ```shell
   /etc/init.d/back2zju enable
   /etc/init.d/back2zju start
   ```

   Or enable and start `back2zju` in `System-Startup` page of OpenWrt LuCi web page (you can also disable the service here).

   Then zju-connect will start running, support boot self-starting, and its running log is saved in `/var/log/back2zju.log`.

5. Add corresponding node and routing rules in the proxy plugin to use.

   According to the configuration in `/etc/back2zju.toml`, add node in the proxy plugin. Fill in `127.0.0.1` for IP, and keep the port/protocol consistent with `/etc/back2zju.toml`. If you set the socks username and password, you also need to fill it in.

   Then add routing rules in the corresponding proxy plugin, the specific operation is omitted.

   Note:

    1. The internal IP range used by ZJU campus network is `10.0.0.0/8`, you may need to remove this IP range from the direct connection list/LAN list of the proxy plugin and add it to the proxy list.

    2. Please make sure that the RVPN server used is directly connected to OpenWrt. If `rvpn.zju.edu.cn` is not configured as a direct connection, this domain name may match the routing rules and other `zju.edu.cn` traffic will be sent to the zju-connect proxy, which will cause network anomalies.

#### Run in Docker

```shell
docker run -d --name zju-connect -v $PWD/config.toml:/home/nonroot/config.toml -p 1080:1080 -p 1081:1081 --restart unless-stopped mythologyli/zju-connect
```

You can also use Docker Compose. Create `docker-compose.yml` file with the following content:

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

And run the following command in the same directory:

```shell
docker compose up -d
```


<!-- ### 参数说明

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

+ `shadowsocks-url`: Shadowsocks 服务端 URL。例如：`ss://aes-128-gcm:password@server:port`。格式[参考此处](https://github.com/shadowsocks/go-shadowsocks2)

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
- [x] Shadowsocks 代理服务
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

+ [socks2http](https://github.com/zenhack/socks2http) -->

### Arguments

+ `server`: SSL VPN server address, default is `rvpn.zju.edu.cn`

+ `port`: SSL VPN server port, default is `443`

+ `username`: Network account. For example: student ID

+ `password`: Network account password

+ `disable-server-config`: Disable server configuration, generally no need to add this argument

+ `disable-zju-config`: Disable ZJU related configuration, generally no need to add this argument

+ `disable-zju-dns`: Disable ZJU DNS and use local DNS, generally no need to add this argument

+ `disable-multi-line`: Disable automatic line selection based on latency. After adding this argument, use the line specified by the `server` parameter

+ `proxy-all`: Whether to proxy all traffic, generally no need to add this argument

+ `socks-bind`: SOCKS5 proxy listening address, default is `:1080`

+ `socks-user`: SOCKS5 proxy username, leave blank if no authentication is required

+ `socks-passwd`: SOCKS5 proxy password, leave blank if no authentication is required

+ `http-bind`: HTTP proxy listening address, default is `:1081`. Set to `""` to disable HTTP proxy

+ `shadowsocks-url`: Shadowsocks server URL. For example: `ss://aes-128-gcm:password@server:port`. Format [refer to here](https://github.com/shadowsocks/go-shadowsocks2)

+ `dial-direct-proxy`: When a URL does not match RVPN rules and switches to direct connection, it uses a proxy, typically in scenarios where it works in conjunction with other proxy tools. Currently, only HTTP proxies are supported. For example: `http://127.0.0.1:7890`, setting it to empty string (`""`) will disable its use.

+ `tun-mode`: TUN mode (experimental). Please read the TUN mode precautions below

+ `add-route`: Add route according to the configuration issued by the server when TUN mode is enabled

+ `dns-ttl`: DNS cache time, default is `3600` seconds

+ `disable-keep-alive`: Disable periodic keep-alive, generally no need to add this argument

+ `zju-dns-server`: ZJU DNS server address, default is `10.10.0.21`

+ `secondary-dns-server`: Standby DNS server used when ZJU DNS server cannot be used, default is `114.114.114.114`. Leave blank to use the system default DNS, but must be set when `dns-hijack` is enabled

+ `dns-server-bind`: DNS server listening address, default is empty to disable. For example, set to `127.0.0.1:53`, then you can send DNS requests to `127.0.0.1:53`

+ `dns-hijack`: Hijack DNS requests when TUN mode is enabled, it's recommended to add this argument when TUN mode is enabled

+ `debug-dump`: Whether to enable debugging, generally no need to add this argument

+ `tcp-port-forwarding`: TCP port forwarding, format is `local address-remote address,local address-remote address,...`, for example `127.0.0.1:9898-10.10.98.98:80,0.0.0.0:9899-10.10.98.98:80`. Multiple forwarding is separated by `,`

+ `udp-port-forwarding`: UDP port forwarding, format is `local address-remote address,local address-remote address,...`, for example `127.0.0.1:53-10.10.0.21:53`. Multiple forwarding is separated by `,`

+ `custom-dns`: Specify custom DNS resolution results, format is `domain name:IP,domain name:IP,...`, for example `www.cc98.org:10.10.98.98,appservice.zju.edu.cn:10.203.8.198`. Multiple resolutions are separated by `,`

+ `custom-proxy-domain`: Specify custom domains which use RVPN proxy, format is `domain,domain,...`, for example `nature.com,science.org`. Multiple resolutions are separated by `,`

+ `twf-id`: twfID login, for debugging purposes, generally no need to add this argument

+ `config`: Specify the configuration file, the content refers to `config.toml.example`. Other parameters are ignored when the configuration file is enabled

### TUN mode precautions

1. Need to run with administrator privileges

2. Windows system needs to go to [Wintun official website](https://www.wintun.net) to download `wintun.dll` and place it in the same directory as the executable file

3. To ensure that `*.zju.edu.cn` is resolved correctly, it's recommended to configure `dns-hijack` to hijack the system DNS

4. macOS does not currently support accessing addresses outside of `10.0.0.0/8` through the TUN interface

### Schedule

#### Completed

- [x] Proxy TCP traffic
- [x] Proxy UDP traffic
- [x] SOCKS5 proxy service
- [x] HTTP proxy service
- [x] Shadowsocks proxy service
- [x] ZJU DNS resolution
- [x] ZJU rules addition
- [x] Support IPv6 direct connection
- [x] DNS cache acceleration
- [x] Automatic line selection
- [x] TCP port forwarding
- [x] UDP port forwarding
- [x] Start through configuration file
- [x] Periodic keep-alive
- [x] TUN mode
- [x] Automatical DNS hijack

#### To Do

- [ ] Fake IP mode

### Contributors

<a href="https://github.com/mythologyli/zju-connect/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=mythologyli/zju-connect" />
</a>

### Thanks

+ [EasierConnect](https://github.com/lyc8503/EasierConnect)

+ [socks2http](https://github.com/zenhack/socks2http)
