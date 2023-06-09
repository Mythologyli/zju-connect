# ZJU Connect

> 🚫 **免责声明**
> 
> 本程序**按原样提供**，作者**不对程序的正确性或可靠性提供保证**，请使用者自行判断具体场景是否适合使用该程序，**使用该程序造成的问题或后果由使用者自行承担**！

---

**本程序基于 [EasierConnect](https://github.com/lyc8503/EasierConnect)（现已停止维护）完成，感谢原作者 [lyc8503](https://github.com/lyc8503)。**

**[电报交流群](https://t.me/zjuers)**，欢迎来自 ZJU 的使用者加入交流。

### 使用方法

#### 直接运行

*Windows 用户可以使用 GUI 版 [ZJU Connect for Windows](https://github.com/mythologyli/zju-connect-for-Windows)。*

1. 在 [Release](https://github.com/mythologyli/zju-connect/releases) 页面下载对应平台的最新版本。

2. 以 Linux 平台为例，解压出可执行文件 `zju-connect`。

3. 命令行运行：`./zju-connect -username <上网账户> -password <密码>`。

4. 此时 `1080` 端口为 Socks5 代理，`1081` 端口为 HTTP 代理。

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

3. 参考 [com.zju.connect.plist](com.zju.connect.plist) 建立 macOS 系统服务配置文件，plist 文件为二进制文件，建议使用 PlistEdict Pro 编辑，其中关键配置参数如下：

   + `UserName`: 后台运行 zju-connect 的的用户默认为 `root`，建议修改为你自己的用户名
   + `ProgramArguments`: zju-connect 运行参数
   + `StandardErrorPath`: 输出 zju-connect 运行日志的目录（用于调试，可不指定）
   + `StandardOutPath`: 输出 zju-connect 运行日志的目录（用于调试，可不指定）
   + `RunAtLoad`: 是否开机自启动
   + `KeepAlive`: 是否后台断开重连
   
   详细参数配置可参考以下文档：
   
   + [plist 配置参数文档](https://keith.github.io/xcode-man-pages/launchd.plist.5.html#OnDemand)
   + [Apple开发者文档](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/Introduction.html#//apple_ref/doc/uid/10000172i-SW1-SW1)
   
4. 移动配置文件至 `/Library/LaunchDaemons/` 目录，同时执行以下命令:
   ```zsh
   $ cd /Library/LaunchDaemons
   $ sudo chown root:wheel com.zju.connect.plist
   ```

5. 执行以下命令启用服务并设置自启：
   ```zsh
   $ sudo launchctl load com.zju.connect.plist
   ```

6. 执行以下命令关闭自启动服务：
   ```zsh
   $ sudo launchctl unload com.zju.connect.plist
   ```

如需开关服务，可直接在 macOS 系统设置中的后台程序开关 zju-connect。

#### Docker 运行

```zsh
$ docker run -d --name zju-connect -v $PWD/config.toml:/home/nonroot/config.toml -p 1080:1080 -p 1081:1081 --restart unless-stopped Mythologyli/zju-connect
```

也可以使用 Docker Compose。创建 `docker-compose.yml` 文件，内容如下：

```yaml
version: '3'

services:
  zju-connect:
    image: Mythologyli/zju-connect
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

+ `dns-ttl`: DNS 缓存时间，默认为 `3600` 秒

+ `disable-keep-alive`: 禁用定时保活，一般不需要加此参数

+ `zju-dns-server`: ZJU DNS 服务器地址，默认为 `10.10.0.21`

+ `debug-dump`: 是否开启调试，一般不需要加此参数

+ `tcp-port-forwarding`: TCP 端口转发，格式为 `本地地址-远程地址,本地地址-远程地址,...`，例如 `127.0.0.1:9898-10.10.98.98:80,0.0.0.0:9899-10.10.98.98:80`。多个转发用 `,` 分隔

+ `udp-port-forwarding`: UDP 端口转发，格式为 `本地地址-远程地址,本地地址-远程地址,...`，例如 `127.0.0.1:53-10.10.0.21:53`。多个转发用 `,` 分隔

+ `twf-id`: twfID 登录，调试用途，一般不需要加此参数

+ `config`: 指定配置文件，内容参考 `config.toml.example`。启用配置文件时其他参数无效

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

#### To Do

### 贡献者

<a href="https://github.com/mythologyli/zju-connect/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=mythologyli/zju-connect" />
</a>

### 感谢

+ [EasierConnect](https://github.com/lyc8503/EasierConnect)

+ [socks2http](https://github.com/zenhack/socks2http)
