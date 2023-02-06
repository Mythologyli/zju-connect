# ZJU Connect

> 🚫 **免责声明**
> 
> 本程序**按原样提供**，作者**不对程序的正确性或可靠性提供保证**，请使用者自行判断具体场景是否适合使用该程序，**使用该程序造成的问题或后果由使用者自行承担**！

---

**本程序基于 [EasierConnect](https://github.com/lyc8503/EasierConnect)（现已停止维护）完成，感谢原作者 [lyc8503](https://github.com/lyc8503)。**

**[电报交流群](https://t.me/zjuers)**，欢迎来自 ZJU 的使用者加入交流。

### 使用方法

*Windows 用户可以使用 GUI 版 [ZJU Connect for Windows](https://github.com/Mythologyli/ZJU-Connect-for-Windows)。*

1. 在 [Release](https://github.com/Mythologyli/ZJU-Connect/releases) 页面下载对应平台的最新版本。

2. 以 Linux 平台为例，解压出可执行文件 `ZJUConnect`。

3. 命令行运行：`./ZJUConnect -username <上网账户> -password <密码>`。

4. 此时 `1080` 端口为 Socks5 代理，`1081` 端口为 HTTP 代理。

### 参数说明

+ `server`: SSL VPN 服务端地址，默认为 `rvpn.zju.edu.cn`

+ `port`: SSL VPN 服务端端口，默认为 `443`

+ `username`: 网络账户。例如：学号

+ `password`: 网络账户密码

+ `disable-server-config`: 禁用服务端配置，一般不需要加此参数

+ `disable-zju-config`: 禁用 ZJU 相关配置，一般不需要加此参数

+ `disable-zju-dns`: 禁用 ZJU DNS 改用本地 DNS，一般不需要加此参数

+ `proxy-all`: 是否代理所有流量，一般不需要加此参数

+ `socks-bind`: SOCKS5 代理监听地址，默认为 `:1080`

+ `socks-user`: SOCKS5 代理用户名，不填则不需要认证

+ `socks-passwd`: SOCKS5 代理密码，不填则不需要认证

+ `http-bind`: HTTP 代理监听地址，默认为 `:1081`

+ `dns-ttl`: DNS 缓存时间，默认为 `3600` 秒

+ `debug-dump`: 是否开启调试，一般不需要加此参数

+ `twf-id`: twfID 登录，调试用途，一般不需要加此参数

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

#### To Do

- [ ] 自动选择线路
- [ ] 通过配置文件启动
- [ ] 内置端口转发功能

### 贡献者

<a href="https://github.com/Mythologyli/ZJU-Connect/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=Mythologyli/ZJU-Connect" />
</a>

### 感谢

+ [EasierConnect](https://github.com/lyc8503/EasierConnect)

+ [socks2http](https://github.com/zenhack/socks2http)