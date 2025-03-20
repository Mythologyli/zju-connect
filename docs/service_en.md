## Run as a service

**Please first run directly to ensure that there is no error before creating a service, so as to avoid repeated login failures resulting in temporary IP ban!**

### Linux

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

### macOS

For macOS, system services are based on `launchd`, which is different from `systemd`. You can apply the following steps to achieve the same effect:

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

### OpenWrt

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