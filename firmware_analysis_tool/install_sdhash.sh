#!/bin/bash

# 更新包管理器
sudo apt-get update

# 安装必要的依赖
sudo apt-get install -y build-essential git libssl-dev libprotobuf-dev protobuf-compiler

# 克隆sdhash的GitHub仓库（如果不存在）
if [ ! -d "sdhash" ]; then
    git clone https://github.com/sdhash/sdhash.git
fi

# 进入克隆的目录
cd sdhash

# 重新生成protobuf文件以兼容新版本
echo "重新生成protobuf文件..."
protoc --cpp_out=sdbf/ blooms.proto

# 编译并安装sdhash
make
sudo make install

# 验证安装
sdhash -h