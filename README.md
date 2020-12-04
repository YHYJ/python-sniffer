# python-sniffer

Packet sniffing and forwarding tool

---

## Table of Contents

<!-- vim-markdown-toc GFM -->

* [依赖](#依赖)
* [运行](#运行)

<!-- vim-markdown-toc -->

---

<!-- Object info -->

---

## 依赖

见[requirements.txt](./requirements.txt)

使用以下命令安装依赖：

```shell
pip install -r requirements.txt
```

## 运行

1. 首先运行[list_nic.py](./list_nic.py)获取所有网络接口信息，运行结果示例如下：

  ![NIC info](https://gitee.com/YJ1516/MyPic/raw/master/picgo/list_nic.png)

2. 然后根据实际情况修改配置文件[sniffer.toml](./sniffer.toml)

  > 配置指导已经写到了sniffer.toml的注释信息里

3. 最后运行[sniffer.py](./sniffer.py)即可，运行结果示例如下：

  > 帮助信心运行`python sniffer.py -h`查看
