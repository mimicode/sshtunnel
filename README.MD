## 使用方法
    sshtunnel -c config.json
## 配置文件
```json
[
  {
    "addr": "192.168.1.10:2222",  
    "user": "root",
    "pass": "",
    "name": "其它服务器",
    "identity_file": "~/.ssh/id_rsa",
    "open": true,
    "tunnels": [
      {
        "remote": "127.0.0.1:5432",
        "local": "127.0.0.1:5432",
        "open": true,
        "name": "progsql"
      }
    ]
  }
]
```