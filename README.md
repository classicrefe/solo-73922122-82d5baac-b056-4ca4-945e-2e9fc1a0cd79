# 科研数据归档与独立见证系统

研究数据归档员交付采样 CSV 后，需要凭**独立第三方回执**发现原件被替换或漏失。
本系统由两个互不信任的服务组成：

| 服务 | 职责 | 持久化 | 端口 |
|---|---|---|---|
| **归档端 archive**（网页） | 按批号上传 ≤ 2 MiB 原件、本地保存、固定公钥验签、目录登记、下载、核查 | 独立卷 `archive_data`（原件 + 目录 SQLite） | 8000 |
| **见证端 witness** | 独立重算 SHA-256/长度并持久化，签发 Ed25519 回执；同号同文复用、异文拒绝 | 独立卷 `witness_data`（回执 SQLite + 私钥） | 8001 |

见证端持有 Ed25519 **私钥**；归档端只持有配套**公钥**（`keys/witness_ed25519.pub.pem`），
因此归档端无法伪造回执，只能验证。

## 1. 快速启动（Docker Compose）

```bash
# 1) 生成 Ed25519 密钥（仓库已附带一套演示密钥，生产环境务必重新生成）
./scripts/generate-keys.sh

# 2) 构建并启动两个服务（各自独立持久卷）
docker compose up --build -d
docker compose ps          # 两个 healthcheck 均为 healthy

# 3) 浏览器访问
#    归档网页:        http://localhost:8000
#    批次封存页:      http://localhost:8000/seals
#    独立核查页:      http://localhost:8000/verify
#    见证回执清单:    http://localhost:8001/receipts
```

> 说明：两个服务各有独立持久卷（`archive_data` / `witness_data`），互不共享；
> 封存清单同时保存在两端（见证端签发原件、归档端验签后落地），
> `docker compose down -v` 会同时清空。本仓库开发环境中无 Docker 守护进程，
> 该 Compose 文件按标准 `docker compose up --build -d` 编写，但**未在此环境实际启动验证**；
> 全部功能已通过 `scripts/self_test.py` 以真实 uvicorn 进程验证（见第 4 节）。

停止与清理：

```bash
docker compose down            # 停止，保留两个持久卷
docker compose down -v         # 同时删除持久卷（清空全部数据）
```

## 2. 核心流程与需求对应

### 上传（`POST /api/batches/{batch_id}/files`，网页首页）
1. 归档端流式读取，超过 **2 MiB 立即 413 拒绝**，本地计算长度与 SHA-256；
2. 原件先以原子替换（`.part` → 目标名）写入本地卷，**绝不覆盖已存在原件**；
3. 转发给见证端；见证端**自己重新**哈希（不信任归档端自报摘要），
   持久化 `批号、文件名、长度、SHA-256` 并签发 Ed25519 回执；
4. 归档端用**固定公钥**验签并核对批号/文件名/长度/摘要全部一致；
5. 验签通过才写入本地目录（状态 `registered`）。
   **本地原件、目录登记、已验签回执三者齐备**才把批次报为 `complete` 并开放下载。

### 同号同文复用、异文拒绝
- 见证端对 `(batch_id, filename)` 建唯一约束：同键同摘要 → 返回 `reused=true`
  的既有回执；同键异摘要/异长度 → **409 content_conflict**，历史记录不可覆盖；
- 归档端对同键异文同样 409，且保留已见证原件不动。

### 断连 / 崩溃后的接续（不重复归档）
- 见证不可达：原件保留在本地，目录记为 `pending`（网页显示“待核”），
  API 返回 **202**；**不会当作“未受理”盲目重投**。
- 见证受理后断连，或本地登记前进程退出（演示用故障注入）：
  重启时归档端同时扫描 ① 目录中的 pending 行 ② 磁盘上无目录记录的“孤儿原件”，
  先向见证端 `GET /batches/{id}` **查明**：有回执则验签后补登（复用，不重传）；
  见证明确 404 才重传本地原件；见证不可达则继续 pending。
- 每个批号一把进程内锁，双窗口并发重试在服务端串行化；
  见证端唯一约束是第二道防线，任何情况下都不会产生重复归档。
- 失败清理只移除临时 `.part` 文件，已见证原件永不被覆盖或删除。

### 批次封存 / 冻结整批（网页 `/seals`，`POST /api/batches/{id}/seal`）
科研归档员移交采样结果时，把整批文件冻结，防止迟到 CSV 混入：

1. **前置条件**：批内每个文件都必须已有本地原件、目录登记和**已验签回执**，
   且逐项一致；批次不能为空。任何 `pending`（在途）文件、或磁盘上无目录记录的
   孤儿原件都会让封存 **409 拒绝**，绝不在清单外悄悄漏掉文件。
2. **签署完整清单**：归档端把批号 + 每个文件的 `filename / length / sha256`
   交给见证端；见证端在**自己的数据库事务里**核对这组清单与它已持久化的回执
   **完全一致**（含个数），然后用 Ed25519 私钥签署整份清单（`sealed_at` 一并签名）。
3. **固定公钥验签后落地**：归档端用固定公钥验签，并再次比对本地原件哈希与
   签名清单**逐项一致**，才把清单写入本地封存表并开放
   `GET /api/batches/{id}/seal/download`（JSON：manifest + signature + 公钥指纹）。
4. **封存后永久拒绝添件**：该批新文件一律 409（归档端与见证端**双重**拦截，
   见证端用数据库事务保证“要么进入清单，要么被明确拒绝”，不存在清单外的新见证记录）；
   已收同文重传仍返回原回执并复用，不产生新记录。
5. **封存与上传交错**：封存先锁定批号、再快照文件清单；此时仍在途的文件会让
   封存因“未登记”而拒绝，上传若在封存提交后才到达则被 409 拒绝。两种结果都明确，
   绝不会出现“见证有记录但清单里没有”的空隙。
6. **双窗口重复封存只产生一份清单**：同一批号的封存在服务端串行化，
   见证端 `seals.batch_id` 主键 + 事务再兜底；重复请求返回同一签名清单。
7. **写入失败不留下半份清单**：清单与签名单条 UPDATE 落地；任何本地写失败
   都将状态置为不可下载的“未确认”，可重试同一操作。
8. **结果未查明时保持待核**：见证端响应丢失/超时、或本地登记前进程退出，
   状态保持 `seal_pending`（封存待核），**不报成功、不重新开放添件**；
   重启后自动（或网页“接续封存”/`POST /api/seals/resume`）向见证端**查明**
   并复用同一清单，绝不生成第二份。
9. **慢封存不挡其他批**：锁和慢调用都按批号隔离并在工作线程中执行，
   其他批的上传、查询不受影响。

### 独立核查（网页 `/verify`，`GET /api/verify`）
以**见证端已签发清单**为准（不是只扫本地目录），对每个回执逐项：
1. 固定公钥**验签**；
2. 重算本地原件 SHA-256/长度，与回执比对 → 报告 `tampered_original`（篡改）
   或 `missing_original`（缺件）；
3. 检查本地目录是否登记 → 报告 `catalog_missing`（目录漏登）；
4. 对每个已封存批次，重新验签本地保存的清单并与见证端当前清单逐字节比对，
   报告 `seal_invalid` / `seal_mismatch` / `seal_unresolved` / `seal_missing_at_witness`。

见证不可达时接口返回 **503 且 `passed=false`**，绝不报核查通过。

### 下载
仅 `registered` 文件可下载；下载前再次重算摘要并验签，损坏原件返回 409 拒绝。
已封存批次下载前还会复核封存清单，清单失效同样 409 拒绝。

## 3. 故障演示

### 3.1 断连/崩溃接续 + 原件损坏（脚本，需 compose 运行中）

```bash
./scripts/demo.sh
```

脚本自动完成：武装崩溃标记 → 上传（见证受理后归档容器退出）→
等待 Docker 重启策略拉起 → 启动自动接续、批次恢复 complete 且见证只有 1 条记录 →
篡改卷内原件 → 核查页报告 `tampered_original` 且下载被拒。

手动版（网页亦可）：

```bash
# 武装：下一次上传在“见证已受理、本地未登记”处退出
curl -X POST http://localhost:8000/api/admin/arm-crash
curl -X POST http://localhost:8000/api/batches/BATCH-DEMO/files \
     -F filename=readings.csv -F file=@demo-samples/readings.csv
# 连接被切断；docker compose ps 可见 archive 容器被 restart 自动拉起
# 重启后打开 http://localhost:8000/batches/BATCH-DEMO，状态自动恢复 complete

# 模拟见证不可达：停掉见证后上传，网页/接口显示“待核”
docker compose stop witness
curl -X POST http://localhost:8000/api/batches/BATCH-OFFLINE/files \
     -F filename=x.csv -F file=@demo-samples/readings.csv   # 202 pending
curl http://localhost:8000/api/verify                       # 503, passed=false
docker compose start witness
curl -X POST http://localhost:8000/api/reconcile            # 查明并接续
```

### 3.3 封存演示

```bash
# 正常封存：先传两个文件，再封存；清单可下载，封存后添件 409
B=BATCH-SEAL-$(date +%H%M%S)
curl -X POST http://localhost:8000/api/batches/$B/files \
     -F filename=a.csv -F file=@demo-samples/readings.csv
curl -X POST http://localhost:8000/api/batches/$B/files \
     -F filename=b.csv -F file=@demo-samples/readings.csv
curl -X POST http://localhost:8000/api/batches/$B/seal | python3 -m json.tool
curl -OJ http://localhost:8000/api/batches/$B/seal/download   # 已验签清单
curl -X POST http://localhost:8000/api/batches/$B/files \
     -F filename=late.csv -F file=@demo-samples/readings.csv   # 409，拒绝迟到文件

# 封存后崩溃接续：见证已签清单、归档端未落盘时退出，重启自动接续同一清单
curl -X POST http://localhost:8000/api/admin/arm-seal-crash
curl -X POST http://localhost:8000/api/batches/BATCH-SEAL-CRASH/seal || true
# 容器被 restart 策略拉起后：GET /api/batches/BATCH-SEAL-CRASH/seal 显示 sealed，
# 且见证端 /seals/BATCH-SEAL-CRASH 的签名与本地一致（只有一份清单）

# 网页操作：http://localhost:8000/seals 可封存、查状态、接续待核封存、取清单
```

### 3.2 原件损坏演示

```bash
docker exec research-archive sh -c \
  "printf 'CORRUPTED' >> /data/originals/BATCH-DEMO/readings.csv"
# 打开 http://localhost:8000/verify 点“开始核查” → 篡改，红色告警
```

## 4. 本地自测（无需 Docker）

`scripts/self_test.py` 会在临时目录中拉起**真实的 uvicorn 多进程**
（临时目录充当独立卷），覆盖 **96 项检查**：

```bash
pip install -r requirements.txt
python3 scripts/self_test.py
```

覆盖点：健康检查、空清单不误报通过、正常上传与验签下载、幂等复用、异文 409、
>2 MiB 拒绝、同批双窗口并发不重复归档、异批并行各自归档一次（无全局锁）、
见证后崩溃→重启自动接续、见证卷重启后回执与签名完整保持、
见证不可达 pending 且不重投、核查发现篡改/缺件/目录漏登、
伪造回执（他方 Ed25519 私钥）被固定公钥拒绝、见证停服时核查 503 不通过。

封存相关：清单覆盖批号与全部文件名/长度/SHA-256 并用固定公钥验签通过、
封存后新文件 409 且见证端无清单外记录、同文重传复用原回执、重复封存返回同一清单、
在途（pending）文件阻止封存、双窗口并发封存只产生一份清单、
慢封存不阻塞其他批上传/查询、见证后崩溃→重启恢复同一清单、
见证不可达时封存 503 待核且不重开添件、本地写失败不留可下载半份清单且可重试、
封存响应丢失（202 待核）后接续采用见证端同一清单、上传/封存交错无清单外见证记录、
核查页交叉复核每份封存清单。

> 注：CI 沙箱禁用 `kill(2)`，测试进程通过应用内 `POST /__selftest_shutdown`
> 优雅退出；`WITNESS_SEAL_DELAY_SECONDS`、`ARCHIVE_SEAL_TIMEOUT`、
> `arm-seal-crash`、`arm-seal-write-fail` 仅用于演示故障注入，生产可经反向代理屏蔽。

## 5. 目录结构

```
common/receipt.py          Ed25519 回执/封存清单的载荷、签名、验签（两端共享）
witness/                   独立见证服务（FastAPI + SQLite + 私钥 + 封存签发）
archive/                   归档网页（FastAPI + SQLite + 固定公钥 + 原件存储）
  templates/               上传/批次/封存/核查四个页面
keys/                      Ed25519 密钥对（演示用，生产请重新生成）
scripts/generate-keys.sh   密钥生成
scripts/self_test.py       96 项端到端自测
scripts/demo.sh            断连接续 + 原件损坏演示
docker-compose.yml         双服务 + 两个独立持久卷 + 健康检查 + 自动重启
Dockerfile                 单镜像双命令
```

## 6. 安全说明与边界

- 回执载荷为确定性 JSON（排序键、紧凑分隔），签名覆盖
  `version/batch_id/filename/length/sha256/issued_at`，并含公钥指纹防错钥；
- 封存清单同样为确定性 JSON，签名覆盖 `version/kind/batch_id/file_count/
  files[]/sealed_at`；验签时同时校验规范化字节、逐项字段类型、批号与本地
  原件清单，任何一项不符都判为不可信；
- 演示密钥随仓库提供仅为开箱即用；真实部署应在受信环境运行
  `generate-keys.sh` 重新生成，私钥只挂载进见证端；
- 当前为单节点 SQLite、HTTP 明文，生产部署应置于 TLS 反向代理之后，
  并按需给见证/归档管理接口加鉴权。
