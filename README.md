# init-system
CentOS 7 系统初始化脚本

> 注意：需要在 run.sh 脚本同级目录创建 src 目录，用来存放 jdk 与 node_exporter 压缩包

```bash
[root@localhost ~]# tree init-system/
init-system/
├── run.sh
└── src
    ├── jdk-8u202-linux-x64.tar.gz
    └── node_exporter-1.1.2.linux-amd64.tar.gz

1 directory, 3 files
```

## 完成的任务
1. 系统初始化配置
2. 安装 Prometheus 的 Node Exporter 组件
3. 安装 jdk8
4. 安装 salt-minion
