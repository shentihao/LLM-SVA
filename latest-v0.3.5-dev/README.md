# LLM-SVA v0.2

基于大语言模型与程序语义分析的源代码漏洞智能审计原型。

核心思路：

> 程序分析提供证据，大语言模型负责语义推理，Source-Sink 路径负责结果验证。

当前版本优先支持 Java，目标是先跑通：
1. Java 源码扫描
2. Tree-sitter AST 解析
3. 基于规则的 Source/Sink 候选生成
4. OpenAI-compatible LLM 调用
5. 结构化 JSON 漏洞判断
6. Source-Sink 路径验证
7. 置信度计算
8. JSON/CSV 审计结果输出

## 1. 环境

建议 Python 3.10+。

```bash
python -m venv .venv
source .venv/bin/activate       # macOS/Linux
# Windows PowerShell:
# .\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

## 2. 配置 LLM

复制：

```bash
cp .env.example .env
```

填写：

```text
LLM_BASE_URL=https://your-openai-compatible-endpoint/v1
LLM_API_KEY=your-key
LLM_MODEL=your-model
```

如果暂时没有 LLM，也可以运行：

```bash
python main.py --input examples
```

此时会执行本地候选发现、路径验证和本地评分，不调用远程模型。

## 3. 运行

扫描 examples：

```bash
python main.py --input examples --output data/results
```

扫描你自己的 Java 项目：

```bash
python main.py --input /path/to/java/project --output data/results
```

只分析 SQL Injection：

```bash
python main.py --input examples --cwe CWE-89
```

启用 LLM：

```bash
python main.py --input examples --output data/results --llm
```

## 4. 输出

`data/results/findings.json`：
完整结构化审计结果。

`data/results/findings.csv`：
便于论文实验统计。

## 5. 当前原型边界

v0.1 的 CFG、Call Graph 和跨方法 Data Flow 还是轻量实现，主要用于论文第一版原型和流程验证。

如果后续要做正式实验，建议继续升级：
- Java 类型解析
- 方法调用解析
- 跨方法数据流
- Source-Sink 知识库
- 污点传播
- 修复前后重新审计
- Juliet / Devign 数据集自动化评测
- 多 LLM 对比和消融实验


## v0.2 新增

- AST-backed intra-procedural taint analysis
- assignment propagation
- string concatenation propagation
- sink argument verification
- lightweight CFG skeleton
- data-flow event recording

运行：

```bash
python main_v2.py --input examples --output data/results-v2
```


## 核对说明（v0.2.1）

v0.2.1 修正了依赖版本范围，并进一步明确：
- Tree-sitter 是 AST 解析层；
- 当前 CFG 是轻量 statement-level skeleton；
- 当前污点分析是 method-level/intra-procedural；
- 尚未实现完整 Java 类型解析、跨方法调用图和全程序污点传播。

因此当前版本适合“原型验证”，不能把 v0.2 的结果直接当作论文最终实验结果。
