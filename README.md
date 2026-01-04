# 基于SM9的可验证秘密共享（VSS）方案

## 项目概述

本项目实现了一个基于SM9标识密码算法的可验证秘密共享（Verifiable Secret Sharing, VSS）方案。该方案不仅实现了传统的(t,n)门限秘密共享，还加入了可验证机制，允许参与方验证分发者和份额的有效性，从而增强系统的鲁棒性。

## 主要特性

### 核心功能
- **完整的VSS协议**: 包括初始化、分发、验证、重构四个阶段
- **可验证性**: 每个参与方可以独立验证收到的份额
- **鲁棒性**: 可以容忍最多n-t个恶意参与方
- **门限特性**: 只需要t个有效份额即可重构秘密
- **基于SM9**: 使用国密SM9标识密码算法

### 安全特性
- **保密性**: 少于t个份额不泄露任何秘密信息
- **可验证性**: 恶意分发者无法让诚实方接受无效份额
- **一致性**: 所有有效份额来自同一多项式
- **鲁棒性**: 即使存在恶意方，诚实方仍能正确重构

### 工程特性
- **模块化设计**: 清晰的代码架构，易于扩展
- **完整测试**: 包含单元测试、集成测试、性能测试
- **生产就绪**: 错误处理、日志记录、配置管理
- **容器化部署**: 提供完整的 Docker 支持，一键部署
- **详细文档**: API文档、协议规范、部署指南

## 快速开始

### 环境要求

### 方式一：本地环境
- Python 3.10+
- Windows 11 + WSL2 或 Linux/macOS

### 方式二：Docker 环境（推荐）
- Docker 20.10+
- Docker Compose 2.0+

### 安装步骤

1. 克隆项目
```bash
git clone https://github.com/jenry666666/sm9-vss.git
cd sm9-vss
```

2. 创建虚拟环境
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows
```

3. 安装依赖
```bash
pip install -r requirements.txt
```

4. 运行测试
```bash
pytest tests/ -v
```

### 基本使用示例

```python
from src.vss.core import SM9VSS

# 创建VSS实例 (3,5)门限
vss = SM9VSS(threshold=3, n_participants=5)

# 注册参与方
participants = ["Alice", "Bob", "Charlie", "David", "Eve"]
for pid in participants:
    vss.register_participant(pid)

# 分发秘密
secret = 123456789
distribution = vss.distribute(secret, "Alice")

# 验证分发
from src.vss.verification import VSSVerifier
verifier = VSSVerifier(vss)
is_valid, errors = verifier.verify_distribution(
    "Alice", distribution.shares, distribution.commitment
)

# 重构秘密
reconstructed, invalid = vss.reconstruct(
    distribution.shares, distribution.commitment
)

print(f"原始秘密: {secret}")
print(f"重构秘密: {reconstructed}")
print(f"验证结果: {is_valid}")
```

## 项目结构

```
sm9-vss-project/
├── src/                          # 源代码
│   ├── crypto/                   # 密码学组件
│   │   ├── sm9.py               # SM9算法实现
│   │   └── bilinear_pairing.py  # 双线性对
│   ├── vss/                      # VSS核心
│   │   ├── core.py              # VSS协议实现
│   │   ├── verification.py      # 验证机制
│   │   └── reconstruction.py    # 重构算法
│   ├── network/                  # 网络通信
│   │   ├── protocol.py          # 网络协议
│   │   └── messages.py          # 消息格式
│   └── utils/                    # 工具函数
├── tests/                        # 测试代码
│   ├── unit/                    # 单元测试
│   ├── integration/             # 集成测试
│   └── performance/             # 性能测试
├── examples/                     # 示例代码
├── docs/                         # 文档
├── configs/                      # 配置文件
├── logs/                         # 日志文件
├── Dockerfile                    # Docker镜像配置
├── docker-compose.yml            # 服务编排配置
└── .dockerignore                 # Docker构建忽略文件
```

## 测试与验证

### 运行测试套件

```bash
# 运行所有测试
pytest tests/ -v

# 运行特定测试
pytest tests/unit/test_vss.py -v
pytest tests/integration/test_full_protocol.py -v
```

### 演示场景

项目包含多个演示场景：

1. **基础演示** (`examples/basic_demo.py`):
   - 诚实分发与重构
   - 恶意分发者检测
   - 份额篡改检测
   - 性能表现展示

## 性能指标

| 场景   | 参与者数 | 分发时间(ms) | 重构时间(ms) | 内存使用(MB) |
| ------ | -------- | ------------ | ------------ | ------------ |
| 小型   | 5        | 45.2         | 12.5         | 15.3         |
| 中型   | 10       | 98.7         | 25.3         | 28.7         |
| 大型   | 20       | 210.5        | 52.1         | 56.2         |
| 超大型 | 50       | 520.8        | 135.6        | 132.4        |

## 安全分析

### 形式化安全属性

1. **完备性**: 如果所有参与方都诚实执行协议，那么：
   - 每个诚实参与方都接受自己的份额
   - 任意t个诚实参与方可以正确重构秘密

2. **可靠性**: 在计算性Diffie-Hellman假设下，恶意分发者无法让诚实参与方接受无效份额

3. **保密性**: 对于任意少于t个参与者，他们无法获得关于秘密s的任何信息

4. **鲁棒性**: 即使存在最多n-t个恶意参与者，诚实参与者仍能正确重构秘密

## 部署指南

### 方式一：本地部署

```bash
# 运行主程序
python main.py

# 运行演示
python examples/basic_demo.py
```

### 方式二：Docker 部署（推荐）

#### 前置要求
确保已安装 Docker 和 Docker Compose：
```bash
docker --version
docker-compose --version
```

#### 快速开始

1. **构建镜像**
```bash
docker-compose build
```

2. **运行应用**
```bash
# 启动主服务
docker-compose up -d

# 查看日志
docker-compose logs -f sm9-vss
```

3. **运行测试**
```bash
# 进入容器运行测试
docker-compose exec sm9-vss pytest tests/ -v
```

4. **运行演示**
```bash
# 进入容器运行演示
docker-compose exec sm9-vss python examples/basic_demo.py
```

#### 常用 Docker 命令

```bash
# 查看运行状态
docker-compose ps

# 停止服务
docker-compose down

# 停止并删除卷
docker-compose down -v

# 重新构建并启动
docker-compose up -d --build

# 查看容器日志
docker-compose logs -f

# 进入容器
docker-compose exec sm9-vss bash
```

#### Docker 配置文件说明

- `Dockerfile`: Docker 镜像配置
- `docker-compose.yml`: 服务编排配置
- `.dockerignore`: Docker 构建忽略文件

## 扩展与定制

### 添加新的密码学算法

1. 在 `src/crypto/` 中添加新的算法实现
2. 实现相应的接口
3. 更新配置文件和工厂类

### 集成到现有系统

项目提供了清晰的API接口，可以轻松集成到：
- 区块链系统
- 多方计算平台
- 密钥管理系统
- 安全存储系统

## 贡献指南

欢迎贡献代码！请遵循以下步骤：

1. Fork项目仓库
2. 创建特性分支
3. 提交更改
4. 推送到分支
5. 创建Pull Request

### 开发规范

- 代码风格: 遵循PEP 8
- 类型提示: 使用Python类型提示
- 文档: 所有公共API必须有文档字符串
- 测试: 新功能必须包含测试用例

## 许可证

本项目采用MIT许可证。

## 参考文献

1. GM/T 0044-2016 SM9标识密码算法
2. Shamir, A. (1979). How to share a secret.
3. Feldman, P. (1987). A practical scheme for non-interactive verifiable secret sharing.
4. Pedersen, T. P. (1991). Non-interactive and information-theoretic secure verifiable secret sharing.

