## 作为服务运行

**请先直接运行，确保无误后再创建服务，避免反复登录失败导致 IP 被临时封禁！**

### Linux

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
   
### macOS

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

### OpenWrt

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