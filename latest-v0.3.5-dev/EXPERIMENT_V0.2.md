# LLM-SVA v0.2 实验说明

## 目标

v0.1 的 Source-Sink 判断主要依赖字符串出现和同方法位置关系。

v0.2 增加：

1. Tree-sitter AST
2. 方法级结构定位
3. 局部变量污点传播
4. 赋值传播
5. 字符串拼接传播
6. Sink 参数追踪
7. 轻量 CFG 骨架
8. 可解释的 Data-flow Event

因此论文中可以开始形成：

Source → Variable → Variable → Sink

而不是：

Source API appears + Sink API appears

## 运行

```bash
python main_v2.py --input examples --output data/results-v2
```

## 预期

VulnerableSql2.java 应产生 SQL Injection candidate，并显示：

request.getParameter
→ id
→ sql
→ executeQuery

SafeSql2.java 可以被识别为存在 Source/Sink，但因为没有形成
到 executeQuery 参数的危险污点路径，不应被直接确认。

## 下一版

v0.3 建议：

- 跨方法 Call Graph
- 参数/返回值污点传播
- Spring Controller source 建模
- JdbcTemplate / MyBatis sink 建模
- sanitizer/validator 知识库
- CFG 分支传播
- exception path
- program slicing

之后再接 Juliet/Devign 做论文正式实验。
