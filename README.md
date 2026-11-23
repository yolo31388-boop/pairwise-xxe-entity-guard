# pairwise-xxe-entity-guard

## 领域

安全

## 主题

XXE 实体防护

## 说明

禁用 DTD、限制实体展开与 OOB 阻断。

初始状态下 `security/xxe_entity_guard.py` 中所有函数抛出 `NotImplementedError`，测试全部失败。
修复实现后运行：

```bash
python -m pytest -q
```

期望全部通过。
