# ZJU Connect

> 🚫 **Disclaimer**
>
> This program is provided **as is**, and the author **does not guarantee the correctness or reliability of the program**. Please judge whether the specific scenario is suitable for using this program. **The problems or consequences caused by using this program are borne by the user**!

---

[中文](README.md) | English

**This program is based on [EasierConnect](https://github.com/lyc8503/EasierConnect) (now Archived), thanks to the original author [lyc8503](https://github.com/lyc8503).**

**QQ group: 1037726410**, welcome to join the discussion.

### Usage

#### Use a GUI client

+ If you are from ZJU:
  + Windows users are recommended to use [ZJU Connect for Windows](https://github.com/mythologyli/zju-connect-for-Windows)
  + Linux/macOS users can try the [EZ4Connect](https://github.com/chenx-dust/EZ4Connect) developed by [Chenx Dust](https://github.com/chenx-dust) (support aTrust) or the [hitsz-connect-verge](https://github.com/kowyo/hitsz-connect-verge) developed by [kowyo](https://github.com/kowyo)
    Please set the server address to `rvpn.zju.edu.cn:443`
+ If you are not from ZJU:

  You can try the [EZ4Connect](https://github.com/chenx-dust/EZ4Connect) developed by [Chenx Dust](https://github.com/chenx-dust) (support aTrust) or the [hitsz-connect-verge](https://github.com/kowyo/hitsz-connect-verge) developed by [kowyo](https://github.com/kowyo)

#### Run Directly

##### Using EasyConnect Protocol

+ If you are a ZJU user:
  1. Download the latest version for your platform from the [Release](https://github.com/mythologyli/zju-connect/releases) page.

  2. Taking macOS as an example, extract the executable file `zju-connect`

  3. macOS users need to remove security restrictions first. Run the following in your terminal: `sudo xattr -rd com.apple.quarantine zju-connect`

  4. Run the command: `./zju-connect -protocol easyconnect -username <Account> -password <Password>`

  5. By default, port `1080` is the Socks5 proxy and port `1081` is the HTTP proxy. To change these ports, please refer to the parameter descriptions.

+ If you are a non-ZJU user:

  The steps are the same as above, but try setting the running parameters as follows:

  `./zju-connect -server <Server Address> -port <Server Port> -username xxx -password xxx -disable-zju-config -skip-domain-resource -zju-dns-server auto`

  *For details, see this [link](https://github.com/Mythologyli/zju-connect/issues/65#issuecomment-2650185322).*

##### Using aTrust Protocol

+ If you are a ZJU user:
  Other steps are the same as the EasyConnect method, but set the running parameters to:
  `./zju-connect -protocol atrust -username <Account> -password <Password> -graph-code-file graph_code.jpg`
  Then follow the on-screen prompts.

  During this process, you may find it difficult to complete the graphical CAPTCHA. You can instead use the GUI client to complete the login, save the `client_data.json` file, and then run: `./zju-connect -protocol atrust -username <Account> -password <Password> -client-data-file client_data.json`

+ If you are a non-ZJU user:
  The steps are the same as for ZJU users; please specify the login protocol according to your situation. See the parameter descriptions for details.

#### Run as a service

[Link](docs/service_en.md)

#### Run in Docker

[Link](docs/docker_en.md)

### Warning

1. When using other proxy tools with TUN mode enabled and zju-connect as a downstream proxy, please be sure to provide the correct network diversion rules, refer to [this issue](https://github.com/Mythologyli/zju-connect/issues/57)

### TUN mode precautions

1. Need to run with administrator privileges

2. Windows system needs to go to [Wintun official website](https://www.wintun.net) to download `wintun.dll` and place it in the same directory as the executable file

3. EasyConnect Protocol: The recommended configuration is: `-tun-mode -add-route -dns-hijack`

4. aTrust Protocol: The recommended configuration is: `-tun-mode -add-route -dns-hijack -fake-ip`. Note: When using the aTrust protocol, direct TCP traffic involving domain names via the TUN interface may fail if DNS Hijacking or Fake IP is not enabled

### Arguments

#### General Arguments

+ `protocol`: Login protocol, supports `easyconnect`/`atrust`, default is `easyconnect`

+ `server`: VPN server address, default is `rvpn.zju.edu.cn`/`vpn.zju.edu.cn`

+ `port`: VPN server port, default is `443`

+ `username`: Network account. For example: student ID

+ `password`: Network account password

+ `disable-zju-config`: Disable ZJU related configuration, non-ZJU users may need to add this argument

+ `disable-zju-dns`: Disable remote DNS and use local DNS instead, generally no need to add this argument

+ `socks-bind`: SOCKS5 proxy listening address, default is `:1080`

+ `socks-user`: SOCKS5 proxy username, leave blank if no authentication is required

+ `socks-passwd`: SOCKS5 proxy password, leave blank if no authentication is required

+ `http-bind`: HTTP proxy listening address, default is `:1081`. Set to `""` to disable HTTP proxy

+ `shadowsocks-url`: Shadowsocks server URL. For example: `ss://aes-128-gcm:password@server:port`. Format [refer to here](https://github.com/shadowsocks/go-shadowsocks2)

+ `dial-direct-proxy`: When a URL does not match rules and switches to direct connection, use a proxy. Typically used in conjunction with other proxy tools, currently supports only HTTP proxy. For example: `http://127.0.0.1:7890`. Set to `""` to disable

+ `tcp-tunnel-mode`: TCP tunnel mode, default is `false`. When enabled, only TCP traffic can be proxied through the TCP tunnel. Since only aTrust supports TCP tunneling, this mode is ineffective under EasyConnect. Enabling this will disable TUN mode

+ `tun-mode`: TUN mode (experimental). Please read the TUN mode precautions below

+ `add-route`: Add routes according to the configuration issued by the server when TUN mode is enabled

+ `dns-ttl`: DNS cache time, default is `3600` seconds

+ `disable-keep-alive`: Disable periodic keep-alive, generally no need to add this argument

+ `zju-dns-server`: Remote DNS server address, default is `auto`. Set to `auto` to use the DNS server obtained from the server; disable remote DNS if it fails to obtain

+ `secondary-dns-server`: Standby DNS server used when the remote DNS server cannot resolve, default is `114.114.114.114`. Leave blank to use system default DNS, but must be set when `dns-hijack` is enabled

+ `dns-server-bind`: DNS server listening address, default is empty (disabled). For example, set to `127.0.0.1:53`, then you can send DNS requests to `127.0.0.1:53`

+ `dns-hijack`: Hijack DNS requests when TUN mode is enabled, it's recommended to add this argument when using TUN mode

+ `fake-ip`: Enable Fake IP mode. Works with dns-hijack. Don't enable it if you are using EasyConnect protocol

+ `debug-dump`: Whether to enable debugging, generally no need to add this argument

+ `tcp-port-forwarding`: TCP port forwarding, format is `local address-remote address,local address-remote address,...`, for example `127.0.0.1:9898-10.10.98.98:80,0.0.0.0:9899-10.10.98.98:80`. Multiple forwardings are separated by `,`

+ `udp-port-forwarding`: UDP port forwarding, format is `local address-remote address,local address-remote address,...`, for example `127.0.0.1:53-10.10.0.21:53`. Multiple forwardings are separated by `,`

+ `custom-dns`: Specify custom DNS resolution results, format is `domain:IP,domain:IP,...`, for example `www.cc98.org:10.10.98.98,appservice.zju.edu.cn:10.203.8.198`. Multiple resolutions are separated by `,`

+ `config`: Specify the configuration file, the content refers to `config.toml.example`. Other parameters are ignored when the configuration file is enabled

#### EasyConnect Related Arguments

+ `totp-secret`: TOTP secret, can be used to automatically complete TOTP verification. If the server doesn't require TOTP or you want to manually enter the code, leave blank

+ `cert-file`: p12 certificate file path, if the server requires certificate verification, this parameter needs to be configured

+ `cert-password`: Certificate password

+ `disable-server-config`: Disable server configuration, generally no need to add this argument

+ `skip-domain-resource`: Do not use the domain resource provided by the server for split tunneling, generally no need to add this argument

+ `disable-multi-line`: Disable automatic line selection based on latency. When added, use the line specified by the `server` parameter

+ `proxy-all`: Whether to proxy all traffic, generally no need to add this argument

+ `custom-proxy-domain`: Specify custom domains to use RVPN proxy, format is `domain,domain,...`, for example `nature.com,science.org`. Multiple domains are separated by `,`

+ `twf-id`: twfID login, for debugging purposes, generally no need to add this argument

#### aTrust Related Arguments

+ `auth-type`: aTrust login authentication type, supports `auth/psw` (password), `auth/cas` (CAS), `auth/smsCheckCode` (SMS verification code), default is `auth/psw`.
+ `login-domain`: Login domain, default is `Radius`.
+ `client-data-file`: Client data file path, used to save login status to avoid repeated verification.
+ `graph-code-file`: Graphic captcha file path, the captcha will be saved to this file during login.
+ `cas-ticket`: CAS verification ticket, defaults to empty, which triggers interactive verification.
+ `phone`: Phone number used for SMS verification code login.
+ `update-best-nodes-interval`: Interval for updating the optimal line automatically, in seconds, default is `300`. Set to `0` to disable automatic optimal line selection.
+ `auth-info`: Only get aTrust authentication information without logging in, generally no need to add this argument. Can be used to check supported authentication methods.
+ `sid`: aTrust SID, for debugging purposes, generally no need to add this argument.
+ `device-id`: aTrust device ID, for debugging purposes, generally no need to add this argument.
+ `sign-key`: aTrust signature key, for debugging purposes, generally no need to add this argument.
+ `resource-file`: aTrust resource file, for debugging purposes, generally no need to add this argument.

### Schedule

#### Completed

- [x] Proxy TCP traffic
- [x] Proxy UDP traffic
- [x] SOCKS5 proxy service
- [x] HTTP proxy service
- [x] Shadowsocks proxy service
- [x] Remote DNS resolution
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
- [x] SMS verification
- [x] TOTP verification
- [x] Certificate verification
- [x] aTrust protocol support
- [ ] Fake IP

#### To Do

### Contributors

<a href="https://github.com/mythologyli/zju-connect/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=mythologyli/zju-connect" />
</a>

### Thanks

+ [EasierConnect](https://github.com/lyc8503/EasierConnect)

+ [socks2http](https://github.com/zenhack/socks2http)

+ [![image](docs/yxvm.png)](https://yxvm.com/)

  [NodeSupport](https://github.com/NodeSeekDev/NodeSupport) sponsored this project