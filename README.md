# 本地证据保管链

这是一个从零实现的本地证据登记、分块封存、派生追踪、移交记录、链校验和导入导出系统。后端使用 Go 标准库实现，网页由服务端直接提供，不内置任何示例数据。

## 启动

```bash
go mod download
go test ./... -count=1
go run ./cmd/server --listen 127.0.0.1:5212
```

浏览器访问：

```text
http://127.0.0.1:5212
```

默认持久化目录是当前工作目录下的 `.evidence-data`。如需指定目录：

```bash
go run ./cmd/server --listen 127.0.0.1:5212 --data /path/to/evidence-data
```

## 持久化模型

- `events.log`：唯一提交点；每条事件 JSON 单行追加，包含前一条事件哈希和自身 SHA-256，追加后执行 `fsync`。
- `evidence/`：已接受根证据字节。
- `derived/`：预览、文本提取、解包或格式转换等派生物字节。
- `staging/<batch-id>/blocks/`：分块采集暂存块。
- `staging/<batch-id>/manifest.json`：所有块写入并算出最终哈希后原子刷盘的封存清单。
- `quarantine/`：哈希不匹配、损坏或人工隔离的暂存内容。
- `imports/`：导入的原始 ZIP 与验证后的 blob。
- `exports/`：导出 ZIP 包。

每次状态变化都会形成事件。文件名相同或内容相同都不会合并证据；采集来源不同会产生独立根节点和保管事件。写事件失败时不会更新内存状态，旧状态仍可读取。

## 页面操作

1. **直接登记**：上传文件，记录文件名、采集来源、说明和稀疏区间。服务端即时计算 MD5、SHA-1、SHA-256、SHA-512 和原始字节长度。
2. **分块封存**：先创建批次，再逐块上传。只有全部块写入、清单刷盘、拼接后的最终 SHA-256 与预期一致，才产生已接受根证据；否则批次进入被拒绝，块文件移动到隔离目录，失败记录保留。
3. **生成派生**：登记预览、解包、文本提取或转换输出，记录操作、工具名和版本、参数、输入片段范围、输出大小与哈希。
4. **移交**：每次移交生成新的移交节点和一条有向边，不覆盖原节点。
5. **验证链**：点击图中任意节点，选择“验证从根证据到此节点的完整链”。系统沿边回溯到根，重新读取字节并校验哈希；失败会追加失败历史，不会覆盖最近一次成功结果。
6. **时钟校正**：保存为独立事实，仅影响后续事件时间，不回写任何历史时间。
7. **导入导出**：导出包含证据清单、事件日志和可选派生物；清单包含自身规范化内容的 SHA-256。导入先验证 ZIP 路径、清单指纹、条目哈希、事件日志链和节点链，再登记。同一包重复导入只返回首次导入/重放结果，不产生新的移交事件。

所有变更接口都接受 `Idempotency-Key` HTTP 头。同一键重复到达时返回第一次确定的状态码、内容类型和响应体，并有 `Idempotent-Replayed: true` 响应头。

## 从一次被中断的写入恢复

假设批次 `batch_xxx` 有 3 块，进程在写入第 2 块之后退出：

1. 重新启动服务。启动时会扫描 `staging/` 并与 `events.log` 重建出的批次状态比对。
2. 如果块文件缺失或尚未写全，批次自动显示为 **恢复中**。已有第 1、2 块不会被覆盖，页面可继续上传第 3 块，然后提交最终 SHA-256 封存。
3. 如果进程是在所有块写入、清单已刷盘之后、事件提交前退出，重启会重新核对所有块与清单；匹配时自动继续封存，损坏时移动到 `quarantine/` 并标记为被拒绝。
4. 如果怀疑暂存内容不可信，可在批次卡片上选择“隔离暂存”，或调用：

```bash
curl -X POST http://127.0.0.1:5212/api/batches/batch_xxx/recover \
  -H 'Content-Type: application/json' \
  -d '{"action":"quarantine"}'
```

继续写入时使用普通块上传接口，序号仍然从 1 开始；重复序号会被拒绝。封存只有在最终 SHA-256 匹配后才可见为已接受证据。

## HTTP 示例

```bash
curl -i -X POST http://127.0.0.1:5212/api/evidence \
  -H 'Idempotency-Key: evidence-001' \
  -F filename=disk.img \
  -F source='workstation-01' \
  -F notes='initial acquisition' \
  -F 'sparse_ranges=[{"offset":0,"length":4096}]' \
  -F file=@/path/to/disk.img
```

创建批次：

```bash
curl -X POST http://127.0.0.1:5212/api/batches \
  -H 'Content-Type: application/json' \
  -d '{"filename":"disk.img","source":"drive-a","total_blocks":2}'
```

导出包：

```bash
curl -X POST http://127.0.0.1:5212/api/exports \
  -H 'Content-Type: application/json' \
  -d '{"include_derived":true}'
```

导入包：

```bash
curl -X POST http://127.0.0.1:5212/api/imports -F package=@exports/exp_xxx.zip
```

## 测试

```bash
go test ./... -count=1
```

测试覆盖直接登记、同名同内容不同来源、分块成功和失败、事件追加失败旧状态可读、幂等重放、派生物和移交链、完整/部分中断后的重启恢复、时钟校正、导出导入、重复包重放和 ZIP 路径穿越拒绝。
