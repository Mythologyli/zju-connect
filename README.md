# ZJU Connect

> 🚫 **[Disclaimer]**
> 本程序**按原样提供**, 作者**不对程序的正确性或可靠性提供保证**, 请使用者自行判断具体场景是否适合使用该程序, *
*使用该程序造成的问题或后果由使用者自行承担**.

---

**本程序基于 [EasierConnect](https://github.com/lyc8503/EasierConnect)
（现已停止维护）完成，感谢原作者 [lyc8503](https://github.com/lyc8503)。**

### 使用方法

1. 在 [Release](https://github.com/Mythologyli/ZJU-Connect/releases) 页面下载对应平台的最新版本。Windows x64
   用户请下载 `ZJUConnect-windows-amd64.zip`。

2. 以 Windows 平台为例，解压出可执行文件 `ZJUConnect.exe`。

3. 在命令行运行：`./ZJUConnect.exe -username 学号 -password 密码 -server rvpn.zju.edu.cn -parse -parse-zju -use-zju-dns`。

4. 此时 `1080` 端口为 Socks5 代理，`1081` 端口为 HTTP 代理。

### 计划表

#### 已完成

- [x] 代理 TCP 流量
- [x] Socks5 代理服务
- [x] HTTP 代理服务
- [x] ZJU DNS 解析
- [x] ZJU 规则添加
- [x] 支持 IPv6 直连

#### To Do

- [ ] DNS 缓存加速
- [ ] 代理 UDP 流量

### 感谢

+ [EasierConnect](https://github.com/lyc8503/EasierConnect)

+ [socks2http](https://github.com/zenhack/socks2http)