# ZJU Connect

> 🚫 **免责声明**
> 
> 本程序**按原样提供**，作者**不对程序的正确性或可靠性提供保证**，请使用者自行判断具体场景是否适合使用该程序，**使用该程序造成的问题或后果由使用者自行承担**！

---

**本程序基于 [EasierConnect](https://github.com/lyc8503/EasierConnect)（现已停止维护）完成，感谢原作者 [lyc8503](https://github.com/lyc8503)。**

**[电报交流群](https://t.me/zjuers)**，欢迎来自 ZJU 的使用者加入交流。

### 使用方法

*Windows 用户可以使用 GUI 版 [ZJU Connect for Windows](https://github.com/Mythologyli/ZJU-Connect-for-Windows)。*

1. 在 [Release](https://github.com/Mythologyli/ZJU-Connect/releases) 页面下载对应平台的最新版本。Windows x64 用户请下载 `ZJUConnect-windows-amd64.zip`。

2. 以 Windows 平台为例，解压出可执行文件 `ZJUConnect.exe`。

3. 在命令行运行：`./ZJUConnect.exe -username 学号 -password 密码 -server rvpn.zju.edu.cn -parse -parse-zju -use-zju-dns`。

4. 此时 `1080` 端口为 Socks5 代理，`1081` 端口为 HTTP 代理。

### 参数说明

+ `username`: 学号

+ `password`: 网络账户密码

+ `server`: rvpn.zju.edu.cn

+ `parse`: 是否解析服务端配置，一般需要加此参数

+ `parse-zju`: 是否使用 ZJU 相关配置，一般需要加此参数

+ `use-zju-dns`: 是否使用 ZJU DNS 服务器，一般需要加此参数

+ `proxy-all`: 是否代理所有流量，一般不需要加此参数

+ `socks-user`: Socks5 代理用户名，不填则不需要认证

+ `socks-passwd`: Socks5 代理密码，不填则不需要认证

+ `config`: 指定配置文件，内容参考config.toml.example  

### 计划表

#### 已完成

- [x] 代理 TCP 流量
- [x] 代理 UDP 流量
- [x] Socks5 代理服务
- [x] HTTP 代理服务
- [x] ZJU DNS 解析
- [x] ZJU 规则添加
- [x] 支持 IPv6 直连
- [x] DNS 缓存加速
- [x] 通过配置文件启动

#### To Do

- [ ] 自动选择线路
- [ ] 内置端口转发功能

### 贡献者

<a href="https://github.com/Mythologyli/ZJU-Connect/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=Mythologyli/ZJU-Connect" />
</a>

### 感谢

+ [EasierConnect](https://github.com/lyc8503/EasierConnect)

+ [socks2http](https://github.com/zenhack/socks2http)
