# AVB-HyperChain-Signer
### AVB 聚合式自动链路签名引擎

AVB HyperChain Signer 是一个面向严肃固件修改流程的 Android Verified Boot (AVB) 全链路签名引擎。

它可以自动完成：

- 检测签名算法
- 匹配正确的 PEM 私钥
- 处理 Algorithm != NONE 的镜像（分区自签）
- 处理 Algorithm == NONE 的分区（父 vbmeta 聚合签名）
- 在重建前移除重复描述符
- 安全重建并重新签名父 vbmeta 镜像
- 保持原始分区镜像大小不变（仅 RAW dump）
- 原地签名并自动备份

无需猜测。无需手工编辑描述符。避免 vbmeta 意外溢出。

---

## 核心理念

Android AVB 并不是给单个镜像签名这么简单。

它的本质是维护一条**有效的信任链**：

```
vbmeta
 ├── boot
 ├── vendor_boot
 └── vbmeta_system
        ├── system
        └── product
```

如果不理解分区在链路中的位置就直接修改，设备很可能变砖。

本工具确保：

- 选择正确的密钥
- 复用正确的算法
- 重建正确的父 vbmeta
- 聚合前移除重复描述符
- 最终输出大小与原始分区大小完全一致

---

## 功能特性

- 从文件或目录自动发现密钥
- 基于 SHA1 公钥指纹匹配
- 强制 RAW 分区输入（拒绝 sparse 镜像）
- 重建 vbmeta 前执行描述符去重
- 针对 Algorithm NONE 分区自动检测父 vbmeta
- 原地签名并创建带时间戳的备份
- 保留原始镜像文件名与大小
- 不进行额外压缩或重采样
- 面向 EDL / BROM / 9008 RAW 分区 dump 场景设计

---

## RAW 分区要求

本工具假设：

- 镜像是完整的 RAW 分区 dump
- 文件大小等于分区大小
- 不是 sparse 镜像
- 没有裁剪尾部零填充

若检测到 sparse 镜像，工具会拒绝继续执行。

请先使用以下命令转换：

```
simg2img input.img output_raw.img
```

---

## 安装

环境要求：

- Python 3.8+
- 同目录下存在 `avbtool.py`
- 有效的 PEM 私钥

目录示例：

```
project/
 ├── avb_chain_autosign.py
 ├── avbtool.py
 ├── pem/
 └── vbmeta*.img
```

---

## 使用方法

### 场景 1 — 分区自签（Algorithm != NONE）

示例：已打补丁并带 root 的 boot。

```
python avb_chain_autosign.py \
  --keys ./pem \
  --orig_img ./boot_b.img \
  --img_patched ./boot_patched.img
```

执行流程：

- 从原始镜像提取算法与密钥指纹
- 对补丁镜像进行原地重签名
- 自动创建备份

---

### 场景 2 — 父级签名分区（Algorithm == NONE）

示例：已打补丁的 vendor_boot。

```
python avb_chain_autosign.py \
  --keys ./pem \
  --orig_img ./vendor_boot_b.img \
  --img_patched ./vendor_boot_patched.img \
  --vbmeta_dir .
```

执行流程：

1. 检测到 Algorithm NONE
2. 定位引用该分区的父 vbmeta
3. 移除该分区的旧描述符
4. 构建新描述符
5. 重建并重签名父 vbmeta
6. 将结果填充到原 vbmeta 分区大小
7. 原地覆盖父 vbmeta

无重复描述符。
无大小溢出。
无需手工干预。

---

## 安全模型

- 始终创建 `.bak_TIMESTAMP` 备份
- 不会缩小或扩展分区大小
- 拒绝 sparse 镜像
- 拒绝无法匹配的密钥
- 拒绝缺失父 vbmeta 的情况

---

## 为什么要做这个工具

传统 AVB 工作流通常需要：

- 手工检查描述符
- 手工追踪链路
- 手工执行 make_vbmeta_image 重建
- 手工进行大小填充
- 反复试错刷机

本工具将整套流程自动化。

它适用于：

- 高阶 Android Modding
- 安全启动研究
- AVB 链路重建
- 自动化固件流水线

---

## 技术亮点

- 在 vbmeta 内进行二进制级描述符过滤
- 基于头部感知的描述符尺寸重写
- 描述符区块零填充
- 确定性的输出大小保持
- 通过 `make_vbmeta_image` 进行父级聚合
- 全自动 SHA1 指纹密钥选择

---

## 警告

本工具默认你：

- 理解 AVB 信任链
- 在已解锁 bootloader 的设备上操作
- 使用 RAW 分区 dump

错误使用可能导致设备变砖。

---

## 许可证

MIT License

---

## 代号

AVB 聚合式全自动链路签名工具

---

## 作者意图

面向确定性、链路安全的 AVB 修改流程而构建。

零猜测。
零重复。
零大小溢出。
