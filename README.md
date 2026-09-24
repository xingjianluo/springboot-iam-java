# Spring Boot IAM 本地验证骨架（凭证生命周期 + 授权判定 + 审计链路）

一个**不依赖任何外部服务或真实凭据**的本地可验证实现：用内存状态模拟用户会话、策略与审计后端，
打通"凭证签发 / 刷新（轮换）/ 撤销 → 访问入口凭证校验 → RBAC+ABAC 授权判定 → 审计门禁 → 放行/拒绝"
的完整链路，并保证并发刷新、撤销竞态、显式拒绝优先级、审计失败等场景下**结果确定、失败原因可区分、可审计还原**。

## 1. 运行环境

- JDK 21+（已在 JDK 25 上验证），Maven 3.9+
- 无需数据库、Redis、第三方身份服务；凭证令牌为本地 `SecureRandom` 生成的模拟串

## 2. 快速开始

```bash
mvn spring-boot:run                     # 启动，默认 8080 端口
mvn test                                # 全部 52 个测试（含并发/竞态重复 40 次）
mvn test -Dtest=ConcurrentRefreshTest   # 只跑并发刷新
```

测试日志（`IAM-TEST` logger + 标准输出 `>>>` 前缀）会打印每次判定的**输入**与**判定依据**。

## 3. HTTP 接口（本地 curl 验证）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/credentials` | 签发凭证：`{"subject":"alice","ttlMillis":60000}` |
| POST | `/api/credentials/refresh` | 刷新（轮换）：`{"token":"..."}` |
| POST | `/api/credentials/revoke` | 撤销（整链）：`{"token":"...","reason":"..."}` |
| POST | `/api/resources/access` | 受保护资源入口：`{"token","resource","action","resourceAttributes","environment"}` |
| POST | `/api/admin/subjects` | 维护主体角色/属性（RBAC+ABAC 输入） |
| GET  | `/api/admin/subjects/{subject}` | 查询主体快照（含版本号） |
| POST | `/api/admin/policies` | 整体替换策略集（原子提交、版本递增） |
| GET  | `/api/admin/policies` | 查询当前策略快照 |
| POST | `/api/admin/audit/writable?writable=false` | 故障注入：模拟审计后端不可写 |
| GET  | `/api/admin/audit/{subject}` | 查询审计轨迹（输入、结果、判定依据） |

策略规则字段（`PolicyRule`）：`name`、`effect`（`ALLOW`/`DENY`）、`subject`、`resource`、`action`、
`anyRole`（角色集合，命中任一即可）、`subjectAttributes` / `resourceAttributes`（属性全等匹配，
`null` 字段表示通配）、`priority`。

### 3.1 端到端示例

```bash
# 1. 主体与策略：reader 可读 docs；dept=ops 显式禁止 delete
curl -s -XPOST localhost:8080/api/admin/subjects -H 'Content-Type: application/json' \
  -d '{"subject":"helen","roles":["reader"],"attributes":{"dept":"ops"}}'
curl -s -XPOST localhost:8080/api/admin/policies -H 'Content-Type: application/json' -d '[
  {"name":"deny-ops-delete","effect":"DENY","resource":"docs","action":"delete",
   "subjectAttributes":{"dept":"ops"},"priority":1},
  {"name":"allow-reader-read","effect":"ALLOW","resource":"docs","action":"read",
   "anyRole":["reader"],"priority":10}]'

# 2. 签发 -> 允许访问 -> 显式拒绝（403 AUTHZ_DENIED）
TOKEN=$(curl -s -XPOST localhost:8080/api/credentials -H 'Content-Type: application/json' \
  -d '{"subject":"helen","ttlMillis":60000}' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
curl -s -XPOST localhost:8080/api/resources/access -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN\",\"resource\":\"docs\",\"action\":\"read\"}"
curl -i -XPOST localhost:8080/api/resources/access -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN\",\"resource\":\"docs\",\"action\":\"delete\"}"

# 3. 刷新轮换：旧 token 立即失效；并发刷新只有一次成功
NEW=$(curl -s -XPOST localhost:8080/api/credentials/refresh -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN\"}" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
curl -i -XPOST localhost:8080/api/credentials/refresh -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN\"}"                       # 409 REFRESH_CONFLICT

# 4. 审计故障注入：受保护操作 fail-closed（503 AUDIT_UNAVAILABLE）
curl -s -XPOST 'localhost:8080/api/admin/audit/writable?writable=false'
curl -i -XPOST localhost:8080/api/resources/access -H 'Content-Type: application/json' \
  -d "{\"token\":\"$NEW\",\"resource\":\"docs\",\"action\":\"read\"}"
curl -s -XPOST 'localhost:8080/api/admin/audit/writable?writable=true'   # 恢复

# 5. 撤销：此后旧凭证一律 401 CREDENTIAL_REVOKED
curl -s -XPOST localhost:8080/api/credentials/revoke -H 'Content-Type: application/json' \
  -d "{\"token\":\"$NEW\",\"reason\":\"manual\"}"
curl -i -XPOST localhost:8080/api/resources/access -H 'Content-Type: application/json' \
  -d "{\"token\":\"$NEW\",\"resource\":\"docs\",\"action\":\"read\"}"

# 6. 审计轨迹（含 decisionBasis，可还原判定依据）
curl -s localhost:8080/api/admin/audit/helen
```

## 4. 凭证生命周期

```
 ISSUE ──► ACTIVE(v1) ──refresh──► 旧版本立即 ROTATED 失效 + 新版本 ACTIVE(v2) ──► ...
                │                                           │
                └────────────── revoke（作用于整条链）◄──────┘
                                   │
                                   ▼
              链上所有版本 REVOKED（含已被轮换的旧版本）
```

- **签发**：生成 `chainId`（凭证链）与首个令牌版本；审计写入成功后令牌才注册可用。
- **刷新 = 轮换**：同一临界区内完成"注册新版本 + 旧版本标记 ROTATED"，旧凭证**立即失效**；TTL 沿用原周期。
- **并发刷新**：链锁串行化（`ReentrantLock`，公平模式）。同一旧凭证被并发刷新时，
  只有第一个看到它仍为 ACTIVE 的请求成功，其余得到 **409 `REFRESH_CONFLICT`**
  （与 `CREDENTIAL_INVALID` / `CREDENTIAL_EXPIRED` / `CREDENTIAL_REVOKED` 明确区分）。
- **撤销**：撤销链上任一版本即撤销**整条链**，链上全部版本置 REVOKED；撤销幂等。
- **过期**：到达 `expiresAtMillis` 后，访问与刷新均得到 **401 `CREDENTIAL_EXPIRED`**。

## 5. 授权判定优先级

1. **先认证后授权**：凭证无效/过期/已撤销时直接在凭证阶段拒绝，不进入策略判定。
2. **快照一致性**：一次判定只取一次主体画像快照（角色+属性，带 `subjectVersion`）
   和一次策略集快照（带 `policyVersion`）；策略/角色变更以"整体替换 + 版本递增"发布，
   单次判定内不会读到中间状态。变更仅在**下一次判定边界**生效，边界内结论一致收敛，
   不存在短暂越权或永久沿用旧权限。
3. **显式 DENY 优先**：命中的规则中只要存在 DENY，立即拒绝，即使存在 priority 更高的 ALLOW。
4. 无 DENY 时取 priority 最高的 ALLOW 放行；**无任何匹配 => 默认拒绝**（`DEFAULT_DENY`）。
5. **失败语义（fail-closed）**：输入不完整、策略/主体依赖抛异常 => `INDETERMINATE`，按拒绝处理。
   三种拒绝原因（`DENY_RULE` / `DEFAULT_DENY` / `INDETERMINATE`）在响应与审计中可区分。

## 6. 并发与失败语义汇总

| 场景 | 行为 | 对外错误码（HTTP） |
| --- | --- | --- |
| 无凭证 / 非 Bearer | 拒绝 | `CREDENTIAL_MISSING`（401） |
| 令牌不存在 | 拒绝 | `CREDENTIAL_INVALID`（401） |
| 已过期 | 拒绝（访问/刷新一致） | `CREDENTIAL_EXPIRED`（401） |
| 已撤销（整链） | 撤销提交后任何在途/后续请求必拒 | `CREDENTIAL_REVOKED`（401） |
| 并发刷新的后来者 | 拒绝，原因可区分 | `REFRESH_CONFLICT`（409） |
| 显式 DENY 命中 | 拒绝，优先于 ALLOW | `AUTHZ_DENIED`（403） |
| 无匹配 / 无法判定 | 默认拒绝 / fail-closed | `AUTHZ_DENIED` 或 `AUTHZ_INDETERMINATE`（403） |
| 审计不可写（访问、签发、刷新、撤销） | **不放行 / 不提交变更** | `AUDIT_UNAVAILABLE`（503） |
| 未预期内部错误 | 仅服务端日志记录细节 | `INTERNAL_ERROR`（500） |

**撤销 vs 在途请求的确定性**：访问入口在校验凭证状态前先获取该凭证所在链的公平锁，
与刷新/刷新轮换/撤销使用**同一把锁**。二者交错时只有两种确定结果：请求先入临界区则在撤销前完成；
撤销先提交则请求必见 REVOKED。不存在"已撤销凭证仍继续访问"的窗口。
测试通过控制公平锁排队顺序，对两种交错各重复 20 次验证。

**审计门禁（fail-closed）**：
- 访问放行前必须成功追加 `ALLOWED` 审计；追加失败则请求不被放行。
- 签发：审计先写，失败则令牌永不注册。
- 刷新：审计作为提交门禁，失败时轮换**完全不提交**（旧凭证保持 ACTIVE，后续可正常刷新）。
- 撤销：审计先写，失败时不改变任何状态。
- 拒绝路径（凭证失效、策略拒绝）同样写审计；审计不可写时拒绝请求本身也会以 `AUDIT_UNAVAILABLE` 失败，绝不静默。

**异常不外透**：HTTP 响应体仅含 `{errorCode, message, traceId}`；底层异常类型、堆栈、
存储细节只写服务端日志。审计事件包含输入（subject/resource/action/token 摘要/版本）、
结果（`ALLOWED`/`REJECTED`/`ROTATED`/`REVOKED` 等）与 `decisionBasis`（命中规则、策略版本、
主体版本、失败原因），可在并发后还原完整判定依据。

## 7. 代码结构

```
common/      ErrorCode、ApiException、ErrorResponse（统一错误语义）
credential/  凭证链/版本状态、内存存储（链锁）、生命周期服务、安全随机标识
subject/     主体画像与版本化目录（RBAC 角色 + ABAC 属性快照）
authz/       策略规则、版本化策略仓库、判定引擎（DENY 优先、fail-closed）
audit/       审计事件、内存审计服务（可注入故障）
guard/       AccessGuard：统一入口（凭证 -> 快照 -> 授权 -> 审计门禁 -> 放行）
web/         REST 控制器、Bearer 解析、全局异常处理
```

## 8. 测试清单

| 测试类 | 覆盖点 |
| --- | --- |
| `ConcurrentRefreshTest` | 16 线程并发刷新恰好 1 次成功、其余 `REFRESH_CONFLICT`；旧凭证立即失效；链上版本连续；审计可还原 |
| `RevocationRaceTest` | 公平锁构造两种撤销/在途交错（各重复 20 次）、撤销后 32 并发访问全部拒绝、轮换链整体撤销 |
| `ExplicitDenyPriorityTest` | DENY 覆盖高优先级 ALLOW、ABAC 拒绝覆盖角色允许、策略/角色变更后版本化一致收敛、默认拒绝与 INDETERMINATE |
| `AuditFailureTest` | 审计故障下访问/签发/刷新均 fail-closed、旧凭证不被破坏、各入口错误码可区分 |
| `CredentialExpiryTest` | 过期在访问与刷新入口得到一致的 `CREDENTIAL_EXPIRED` 且被审计 |
| `WebEndToEndTest` | MockMvc 全链路：签发/允许/显式拒绝/伪造凭证/缺凭证/审计故障/撤销/审计轨迹；验证错误码与"细节不外透" |
