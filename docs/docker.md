## Docker 运行

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

另外，你还可以使用 [configs top-level elements](https://docs.docker.com/compose/compose-file/08-configs/) 将 zju-connect 的配置文件直接写入 docker-compose.yml，如下：

```yaml
services:
   zju-connect:
      container_name: zju-connect
      image: mythologyli/zju-connect
      restart: unless-stopped
      ports: [1080:1080, 1081:1081]
      configs: [{ source: zju-connect-config, target: /home/nonroot/config.toml }]

configs:
   zju-connect-config:
      content: |
         username = ""
         password = ""
         # other configs ...
```

并在同目录下运行

```zsh
$ docker compose up -d
```