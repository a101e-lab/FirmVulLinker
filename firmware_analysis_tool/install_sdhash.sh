#!/bin/bash

# 更新包管理器
sudo apt-get update

# 安装必要的依赖
sudo apt-get install -y build-essential git libssl-dev libprotobuf-dev protobuf-compiler

# 克隆sdhash的GitHub仓库
git clone https://github.com/sdhash/sdhash.git

# 进入克隆的目录
cd sdhash

# 编译并安装sdhash
make
sudo make install

# 验证安装
sdhash -h