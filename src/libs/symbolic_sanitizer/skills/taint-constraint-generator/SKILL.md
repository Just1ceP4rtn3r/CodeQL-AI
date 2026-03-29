---
name: taint-constraint-generator
description: |
  基于 SARIF 结果和 sink 类型生成污点约束条件，用于 angr 符号执行分析。
  当需要从 CodeQL/SARIF 结果中提取污点信息并生成符号执行约束时使用此 skill。
  支持命令注入、SQL注入、缓冲区溢出、整数溢出、格式化字符串、路径遍历等漏洞类型。
---

# 污点约束生成器 (Taint Constraint Generator)

## 用途

根据 CodeQL SARIF 结果和 sink 函数信息，自动生成适用于 angr 符号执行的污点约束条件。

## 输入格式

### SARIF 结果格式
```json
{
  "ruleId": "cpp/command-line-injection",
  "message": {
    "text": "User-controlled data reaches system()"
  },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": {"uri": "src/util.c"},
      "region": {"startLine": 42}
    },
    "logicalLocations": [{
      "name": "sanitize_cmd",
      "kind": "function"
    }]
  }]
}
```

### 关键字段
- `ruleId`: 规则ID，用于判断漏洞类型
- `message.text`: 消息文本，可能包含函数名
- `locations`: 代码位置信息
- `logicalLocations`: 逻辑位置（函数、类等）

## Sink 类型检测

根据 `ruleId` 和函数名自动检测 sink 类型：

| 类型 | 规则ID关键词 | 函数名示例 | 有害字符 |
|------|-------------|-----------|---------|
| command_injection | command, cmd, system, exec, shell | system, popen, execve | ; \| & \` $ ( ) { } < > |
| sql_injection | sql | sqlite, mysql_query | ' " ; - /* */ OR AND |
| buffer_overflow | buffer, overflow, memcpy | memcpy, strcpy, strcat | (长度检查) |
| integer_overflow | integer, arithmetic | atoi, strtol | (范围检查) |
| format_string | format | printf, sprintf | % n p x s |
| path_traversal | path, traversal, directory | fopen, open | . / \\ ~ |

## 输出格式

### 约束条件结构
```python
{
  "sink_type": "command_injection",
  "description": "命令注入 - 需要过滤shell元字符",
  "harmful_chars": [";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">"],
  "harmful_patterns": [],
  "max_length": 128,
  "min_length": 1,
  "ascii_only": true,
  "null_terminated": true
}
```

## 使用步骤

1. **提取规则信息**
   - 从 SARIF 中读取 `ruleId` 和 `message.text`
   - 从 `locations` 中提取 sink 函数名

2. **检测 Sink 类型**
   - 分析 `ruleId` 判断漏洞类别
   - 如果无法从 ruleId 判断，检查函数名关键词

3. **生成约束配置**
   - 根据 sink 类型选择有害字符集合
   - 设置合理的输入长度限制
   - 配置 ASCII 可打印字符限制

4. **生成 angr 代码**
   自动生成如下 angr 约束代码：
   ```python
   import claripy
   
   # 创建符号字节
   sym_bytes = [claripy.BVS(f'byte_{i}', 8) for i in range(64)]
   
   # ASCII 可打印约束
   for b in sym_bytes:
       state.solver.add(b >= 0x20)
       state.solver.add(b <= 0x7E)
   
   # 有害字符约束（输入必须包含至少一个有害字符）
   harmful_chars = [';', '|', '&']
   harmful = claripy.Or(*[b == ord(c) for c in harmful_chars for b in sym_bytes])
   state.solver.add(harmful)
   ```

## 示例

### 示例 1: 命令注入
**输入:**
```json
{
  "ruleId": "cpp/command-line-injection",
  "message": {"text": "User input reaches system()"},
  "locations": [{"logicalLocations": [{"name": "run_command"}]}]
}
```

**输出:**
```python
sink_type = "command_injection"
harmful_chars = {';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>'}
max_length = 128
```

### 示例 2: SQL 注入
**输入:**
```json
{
  "ruleId": "cpp/sql-injection",
  "message": {"text": "Tainted data in SQL query"},
  "locations": [{"logicalLocations": [{"name": "execute_query"}]}]
}
```

**输出:**
```python
sink_type = "sql_injection"
harmful_chars = {"'", '"', ';', '-', ' OR ', ' AND '}
max_length = 256
```

## 最佳实践

1. **优先使用 ruleId 判断类型**
   - ruleId 通常包含明确的漏洞类型信息
   - 仅当 ruleId 不明确时才使用函数名推断

2. **合理设置长度限制**
   - 命令注入: 128 字节
   - SQL 注入: 256 字节
   - 缓冲区溢出: 根据目标缓冲区大小设置

3. **约束完整性**
   - 始终添加 null 终止符约束
   - 限制为可打印 ASCII 字符（0x20-0x7E）
   - 确保输入非空

4. **输出验证约束**
   - 提供 `check_output_harmful()` 函数用于验证输出
   - 如果输出仍包含有害字符，则净化失败

## 完整生成代码模板

```python
def generate_constraints(sarif_result):
    # 1. 提取信息
    rule_id = sarif_result["ruleId"]
    message = sarif_result["message"]["text"]
    sink_name = sarif_result["locations"][0]["logicalLocations"][0]["name"]
    
    # 2. 检测类型
    sink_type = detect_sink_type(rule_id, message, sink_name)
    
    # 3. 获取有害字符
    harmful_chars_map = {
        "command_injection": {';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>'},
        "sql_injection": {"'", '"', ';', '-'},
        "format_string": {'%', 'n', 'p', 'x', 's'},
        "path_traversal": {'.', '/', '\\', '~'},
    }
    
    harmful_chars = harmful_chars_map.get(sink_type, set())
    
    # 4. 生成 angr 约束代码
    code = f'''
import claripy

# 创建符号输入（64字节）
sym_bytes = [claripy.BVS(f'byte_{{i}}', 8) for i in range(64)]

# ASCII 可打印约束
for b in sym_bytes:
    state.solver.add(b >= 0x20)
    state.solver.add(b <= 0x7E)

# Null 终止
state.solver.add(sym_bytes[-1] == 0)

# 有害字符约束
harmful = claripy.Or(*[
    b == ord(c) 
    for c in {list(harmful_chars)} 
    for b in sym_bytes[:-1]
])
state.solver.add(harmful)
'''
    
    return {
        "sink_type": sink_type,
        "harmful_chars": list(harmful_chars),
        "angr_code": code
    }
```