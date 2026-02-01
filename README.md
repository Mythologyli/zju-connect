# ZJU Connect

> 🚫 **免责声明**
>
> 本程序**按原样提供**，作者**不对程序的正确性或可靠性提供保证**，请使用者自行判断具体场景是否适合使用该程序，**使用该程序造成的问题或后果由使用者自行承担**！

---

中文 | [English](README_en.md)

**本程序基于 [EasierConnect](https://github.com/lyc8503/EasierConnect)（现已停止维护）完成，感谢原作者 [lyc8503](https://github.com/lyc8503)。**

**QQ 交流群：1037726410**，欢迎使用者加入交流。

### 使用方法

#### 使用 GUI 版客户端

+ 如果你是来自 ZJU 的用户：
  + Windows 用户推荐使用 [ZJU Connect for Windows](https://github.com/mythologyli/zju-connect-for-Windows)。
  + Linux/macOS 用户可以尝试使用 [Chenx Dust](https://github.com/chenx-dust) 开发的客户端 [EZ4Connect](https://github.com/chenx-dust/EZ4Connect)（推荐，支持 aTrust 协议）或 [kowyo](https://github.com/kowyo) 开发的客户端 [hitsz-connect-verge](https://github.com/kowyo/hitsz-connect-verge)。
    注意请设置服务器地址为 `rvpn.zju.edu.cn:443`。
+ 如果你是非 ZJU 的用户：

  可以尝试使用 [Chenx Dust](https://github.com/chenx-dust) 开发的客户端 [EZ4Connect](https://github.com/chenx-dust/EZ4Connect)（推荐，支持 aTrust 协议）或 [kowyo](https://github.com/kowyo) 开发的客户端 [hitsz-connect-verge](https://github.com/kowyo/hitsz-connect-verge)。

#### 直接运行

##### 使用 EasyConnect 协议

+ 如果你是来自 ZJU 的用户：

  1. 在 [Release](https://github.com/mythologyli/zju-connect/releases) 页面下载对应平台的最新版本。

  2. 以 macOS 为例，解压出可执行文件 `zju-connect`。

  3. macOS 需要先解除安全限制。命令行运行：`sudo xattr -rd com.apple.quarantine zju-connect`。

  4. 命令行运行：`./zju-connect -protocol easyconnect -username <上网账户> -password <密码>`。

  5. 此时 `1080` 端口为 Socks5 代理，`1081` 端口为 HTTP 代理。如需更改默认端口，请参考参数说明。

+ 如果你是非 ZJU 的用户：

  其他步骤与上述相同，运行参数请尝试设置为：

  `./zju-connect -server <服务器地址> -port <服务器端口> -username xxx -password xxx -disable-zju-config -skip-domain-resource -zju-dns-server auto`

  *详情见此[链接](https://github.com/Mythologyli/zju-connect/issues/65#issuecomment-2650185322)*

##### 使用 aTrust 协议

+ 如果你是来自 ZJU 的用户：

  其他步骤与 EasyConnect 相同，运行参数请设置为：

  `./zju-connect -protocol atrust -username <上网账户> -password <密码> -graph-code-file graph_code.jpg`

  之后按照提示操作。在过程中，你可能发现完成图形验证码较为困难。你可以使用 GUI 客户端完成登录后，保存 `client_data.json` 文件，之后运行 `./zju-connect -protocol atrust -username <上网账户> -password <密码> -client-data-file client_data.json`。

+ 如果你是非 ZJU 的用户：

  其他步骤与 ZJU 用户相同，请根据情况指定登录协议。详见参数说明。

#### 作为服务运行

[链接](docs/service.md)

#### Docker 运行

[链接](docs/docker.md)

### 警告

1. 当使用其他开启了 TUN 模式的代理工具，同时配合 zju-connect 作为下游代理时，请注意务必提供正确的分流规则，参考[此 issue](https://github.com/Mythologyli/zju-connect/issues/57)

### TUN 模式注意事项

1. 需要管理员权限运行

2. Windows 系统需要前往 [Wintun 官网](https://www.wintun.net)下载 `wintun.dll` 并放置于可执行文件同目录下

3. 为保证域名解析正确，建议配置 `dns-hijack` 劫持系统 DNS

4. 在使用 aTrust 协议时，如果不使用 Fake IP，直接通过 TUN 网卡的涉及域名的 TCP 流量可能会出错。建议配置 `dns-hijack` 和 `fake-ip`

### 参数说明

#### 通用参数

+ `protocol`: 登录协议，支持 `easyconnect`/`atrust`，默认为 `easyconnect`

+ `server`: VPN 服务端地址，默认为 `rvpn.zju.edu.cn`/`vpn.zju.edu.cn`

+ `port`: VPN 服务端端口，默认为 `443`

+ `username`: 网络账户。例如：学号

+ `password`: 网络账户密码

+ `disable-zju-config`: 禁用 ZJU 相关配置，非 ZJU 用户可能需要添加此参数

+ `disable-zju-dns`: 禁用远端 DNS 改用本地 DNS，一般不需要加此参数

+ `socks-bind`: SOCKS5 代理监听地址，默认为 `:1080`

+ `socks-user`: SOCKS5 代理用户名，不填则不需要认证

+ `socks-passwd`: SOCKS5 代理密码，不填则不需要认证

+ `http-bind`: HTTP 代理监听地址，默认为 `:1081`。为 `""` 时不启用 HTTP 代理

+ `shadowsocks-url`: Shadowsocks 服务端 URL。例如：`ss://aes-128-gcm:password@server:port`。格式[参考此处](https://github.com/shadowsocks/go-shadowsocks2)

+ `dial-direct-proxy`: 当 URL 未命中规则，切换到直连时使用代理，常用于与其他代理工具配合的场景，目前仅支持 http 代理。例如：`http://127.0.0.1:7890"`，为 `""` 时不启用

+ `tcp-tunnel-mode`: TCP 隧道模式，默认为 `false`。启用后仅可通过 TCP 隧道代理 TCP 流量。由于只有 aTrust 支持 TCP 隧道，此模式在 EasyConnect 下无效。启用后会禁用 TUN 模式

+ `tun-mode`: TUN 模式（实验性）。请阅读 TUN 模式注意事项

+ `add-route`: 启用 TUN 模式时根据服务端下发配置添加路由

+ `dns-ttl`: DNS 缓存时间，默认为 `3600` 秒

+ `disable-keep-alive`: 禁用定时保活，一般不需要加此参数

+ `zju-dns-server`: 远端 DNS 服务器地址，默认为 `auto`。设置为 auto 时使用从服务端获取的 DNS 服务器，如果未能获取则禁用远端 DNS

+ `secondary-dns-server`: 当使用远端 DNS 服务器无法解析时使用的备用 DNS 服务器，默认为 `114.114.114.114`。留空则使用系统默认 DNS，但在开启 `dns-hijack` 时必须设置

+ `dns-server-bind`: DNS 服务器监听地址，默认为空即禁用。例如，设置为 `127.0.0.1:53`，则可向 `127.0.0.1:53` 发起 DNS 请求

+ `dns-hijack`: 启用 TUN 模式时劫持 DNS 请求，建议在启用 TUN 模式时添加此参数

+ `fake-ip`: 启用 Fake IP 功能，与 dns-hijack 配合使用，建议在启用 TUN 模式时添加此参数

+ `debug-dump`: 是否开启调试，一般不需要加此参数

+ `tcp-port-forwarding`: TCP 端口转发，格式为 `本地地址-远程地址,本地地址-远程地址,...`，例如 `127.0.0.1:9898-10.10.98.98:80,0.0.0.0:9899-10.10.98.98:80`。多个转发用 `,` 分隔

+ `udp-port-forwarding`: UDP 端口转发，格式为 `本地地址-远程地址,本地地址-远程地址,...`，例如 `127.0.0.1:53-10.10.0.21:53`。多个转发用 `,` 分隔

+ `custom-dns`: 指定自定义 DNS 解析结果，格式为 `域名:IP,域名:IP,...`，例如 `www.cc98.org:10.10.98.98,appservice.zju.edu.cn:10.203.8.198`。多个解析用 `,` 分隔

+ `config`: 指定配置文件，内容参考 `config.toml.example`。启用配置文件时其他参数无效

#### EasyConnect 相关参数

+ `totp-secret`: TOTP 密钥，可用于自动完成 TOTP 验证。如服务端无需 TOTP 验证或希望手动输入验证码，可不填

+ `cert-file`: p12 证书文件路径，如果服务器要求证书验证，需要配置此参数

+ `cert-password`: 证书密码

+ `disable-server-config`: 禁用服务端配置，一般不需要加此参数

+ `skip-domain-resource`: 不使用服务端下发的域名资源分流，一般不需要加此参数

+ `disable-multi-line`: 禁用自动根据延时选择线路。加此参数后，使用 `server` 参数指定的线路

+ `proxy-all`: 是否代理所有流量，一般不需要加此参数

+ `custom-proxy-domain`: 指定自定义域名使用 RVPN 代理，格式为 `域名,域名,...`，例如 `nature.com,science.org`。多个域名用 `,` 分隔

+ `twf-id`: twfID 登录，调试用途，一般不需要加此参数

#### aTrust 相关参数

+ `auth-type`: aTrust 登录验证类型，支持 `auth/psw`（密码验证）、`auth/cas`（CAS 验证）、`auth/smsCheckCode`（短信验证码验证），默认为 `auth/psw`

+ `login-domain`: 登录域，默认为 `Radius`

+ `client-data-file`: 客户端数据文件路径，可用于保存登录状态，避免重复验证

+ `graph-code-file`: 图形验证码文件路径，登录时会将图形验证码保存至该文件

+ `cas-ticket`: CAS 验证票据，默认为空，此时进入交互式验证

+ `phone`: 短信验证码登录时使用的手机号

+ `update-best-nodes-interval`: 自动选择最优线路的更新间隔，单位为秒，默认为 `300` 秒。设置为 `0` 则禁用自动选择最优线路

+ `auth-info`: 仅获取 aTrust 验证信息而不登录，一般不需要加此参数。可用于查看服务端支持的验证方式

+ `sid`: aTrust SID，调试用途，一般不需要加此参数

+ `device-id`: aTrust 设备 ID，调试用途，一般不需要加此参数

+ `sign-key`: aTrust 签名密钥，调试用途，一般不需要加此参数

+ `resource-file`: aTrust 资源文件，调试用途，一般不需要加此参数

### 计划表

#### 已完成

- [x] 代理 TCP 流量
- [x] 代理 UDP 流量
- [x] SOCKS5 代理服务
- [x] HTTP 代理服务
- [x] Shadowsocks 代理服务
- [x] 远端 DNS 解析
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
- [x] 短信验证
- [x] TOTP 验证
- [x] 证书验证
- [x] aTrust 协议支持
- [x] Fake IP

#### To Do

### 贡献者

<a href="https://github.com/mythologyli/zju-connect/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=mythologyli/zju-connect" />
</a>

### 感谢

+ [EasierConnect](https://github.com/lyc8503/EasierConnect)

+ [socks2http](https://github.com/zenhack/socks2http)

+ [![image](docs/yxvm.png)](https://yxvm.com/)

  [NodeSupport](https://github.com/NodeSeekDev/NodeSupport) 赞助了本项目