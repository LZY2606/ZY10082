# ForensicBox — 本地只读证据保管链

一个从零实现的单机数字证据登记、分块封存、派生溯源、移交与导入/导出系统。
后端为 Go（仅标准库），前端为无构建步骤的原生网页，持久化为追加式事件日志
（WAL）+ 内容寻址的只读 blob 存储。

## 快速开始

```bash
go mod download
go test ./... -count=1
go run ./cmd/server --listen 127.0.0.1:5212
```

浏览器打开 <http://127.0.0.1:5212>。

数据默认写入 `./data`（可用 `--data` 或环境变量 `FORENSICBOX_DATA` 修改）。

## 它如何工作

- **即时多哈希**：每个块在服务端流式计算 `sha256 / sha512 / sha1`，封存时对
  重新拼装的整源流再算一遍并与申报值比对；同时记录原始字节长度、固定块粒度的
  稀疏（全零）区间和采集说明。
- **只追加事件**：每次状态变化（创建批次、写块、封存、失败、隔离、恢复、派生、
  移交、验证、时钟校正、导入、导出）都写入 `data/events.log`，带 CRC32 校验帧
  并 `fsync`。状态通过重放得到；写新事件失败时，上一次成功的状态仍可读取。
- **同名 ≠ 同证据**：每次采集都生成唯一批次/证据 ID；相同字节、相同文件名但
  采集来源不同，仍是独立证据节点（字节层复用同一个内容寻址 blob）。
- **派生节点**：预览（`preview`）、文本提取（`strings`）、格式转换（`hexdump`、
  `sha256` 报告）、解包（`ziplist`）都会产生新的只读 artifact，并记录工具名、
  固定版本字符串、参数、输入片段 `[start,end)` 与输出指纹；父证据永不修改。
- **有向图**：`有向图` 标签页把批次 → 证据 → 派生物 → 移交 → 包画成有向图，
  点选任意 artifact 节点后可“验证从根证据到所选节点的完整链”。
- **验证失败不覆盖成功**：每次校验（封存失败、链验证失败）都追加一条带时间戳
  的失败记录；最近一次成功结果不会被删除或覆盖。
- **幂等**：所有写操作接受 `Idempotency-Key` 请求头；同一键重复到达，返回第一
  次已确定的结果，不产生第二个事件。
- **时钟校正**：作为单独的 `clock_corrected` 事实保存，历史事件时间永不回写。
- **导出/导入**：导出为 `.fbx.zip`，含 `manifest.json`（清单）、
  `events.log.json`（事件日志）与可选派生 blob；导入时先完整验证（清单、每条
  blob 指纹、内容哈希、路径不逃逸、未声明条目）再一次性登记。重复导入同一包只
  返回首次结果，不重复产生移交事件。

## 状态分区

网页把采集批次分到四个区域，互斥显示：

- **待确认 pending**：批次已建，块未写全或尚未封存。
- **已接受 accepted**：全部块写入、清单刷盘、整源哈希匹配，证据已可见。
- **被拒绝 rejected**：封存或隔离失败；失败原因保留在卡片中。
- **恢复中 recovering**：进程中断后重启识别出的未完成批次。

## 从一次被中断的写入恢复

批量封存只有在「全部块写入 + 清单刷盘 + 最终哈希匹配」后才变为已接受。
若上传或封存过程中进程被杀死：

1. 块始终先写入 `data/staging/<session>/blocks/.tmp-*`，`fsync` 后再原子改名
   为 `NNNNNNNNN.blk`，所以磁盘上不会出现“写了一半”的正式块；遗留的
   `.tmp-*` 文件会被忽略。
2. 重新启动服务（同一 `--data` 目录）。启动时会扫描 `data/staging/`：
   - 对已知批次，把磁盘上已有但事件日志里缺失的块重新哈希并补登日志，批次状态
     从 `pending` 变为 `recovering`，并追加一条 `recovery_note` 事件（列出仍缺
     失的块）。
   - 无主目录移动到 `data/quarantine/orphan-*`。
   - 若 `events.log` 尾部是不完整/CRC 错误的帧，坏尾被截断并保存到
     `data/quarantine/events-tail-*.log`，之前已确认的事件全部保留。
3. 在网页「恢复中」区域对该批次选择：
   - **封存**：继续上传缺失块（前端可对同一文件重跑，已存在且哈希一致的块不会
     重复落盘），全部块齐备且整源哈希匹配后变为「已接受」；或
   - **隔离**：把暂存目录移动到 `data/quarantine/staging-<session>/` 并登记
     `session_quarantined` 事件，批次标记为「被拒绝」。

也可以用 API 恢复：

```bash
# 查询批次，blocks 中是已落盘的块
curl -s 127.0.0.1:5212/api/sessions/<SESSION_ID>
# 补传缺失块（索引从 0 开始）
curl -s -X PUT --data-binary @block7.bin \
  127.0.0.1:5212/api/sessions/<SESSION_ID>/blocks/7
# 全部块齐备后封存
curl -s -X POST -H 'Idempotency-Key: seal-<SESSION_ID>' \
  -H 'Content-Type: application/json' -d '{}' \
  127.0.0.1:5212/api/sessions/<SESSION_ID>/seal
```

## HTTP API 摘要

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/state` | 全量状态快照（分区列表、证据、移交、校验、包、事件） |
| GET | `/api/graph` | 来源/派生/移交有向图 |
| POST | `/api/sessions` | 创建采集批次 |
| PUT | `/api/sessions/{id}/blocks/{index}` | 写入一块（可用 `X-Block-SHA256` 等头声明块哈希） |
| POST | `/api/sessions/{id}/seal` | 校验并封存（失败也记录） |
| POST | `/api/sessions/{id}/quarantine` | 隔离未完成批次 |
| GET | `/api/artifacts/{id}/blob` | 下载只读原始字节 |
| POST | `/api/derive` | 生成派生物 `{parent_id, tool, args, start, end}` |
| POST | `/api/transfer` | 追加移交 `{artifact_id, from, to, reason}` |
| POST | `/api/verify` | 验证根证据 → `target_id` 的完整链 |
| POST | `/api/clock` | 记录时钟校正事实 |
| POST | `/api/export` | 生成导出包（直接下载 zip，响应头带包 ID 与内容哈希） |
| POST | `/api/import` | 上传 `.fbx.zip`，先验证后登记 |

所有 POST/PUT 均可带 `Idempotency-Key: <任意字符串>`。

## 目录布局

```
data/
  events.log                       # 追加式 CRC 帧事件日志（fsync）
  blobs/sha256/ab/cd/<hash>.bin    # 内容寻址、只读证据与派生物
  staging/<session>/blocks/*.blk   # 封存前的分块暂存（原子改名）
  packages/<pkg>.fbx.zip           # 导出包留存（重放下载不产生新事件）
  quarantine/                      # 坏 WAL 尾帧、无主目录、隔离的批次
```

## 测试

`go test ./... -count=1` 覆盖：多哈希与稀疏区间、封存失败后再成功且失败保留、
幂等键返回首次结果、同名同内容不同来源不合并、派生可复算与全链验证、中断重启
恢复并续传、WAL 坏尾截断隔离、写失败时旧状态可读、导出/导入往返与重放不产生
重复移交、篡改包/路径逃逸被拒、HTTP 全流程与块哈希冲突。
