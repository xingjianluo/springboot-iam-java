# Spring Boot IAM 本地演示：凭证生命周期 + 授权判定 + 审计链路

一个**零外部依赖、可完全本地验证**的访问凭证与授权判定服务。使用内存结构模拟用户会话与
策略变更，保证凭证生命周期、权限判定和异常结果在各入口（Service / HTTP）下**结果一致、
原因可区分、行为可解释**。

- Java 21（在 25 上亦可构建）、Spring Boot 3.4.x、仅 `spring-boot-starter-web`
- 无数据库、无缓存、无真实第三方身份服务；凭证密文为本地随机生成的不透明令牌，非真实凭据

---

## 1. 快速开始

```bash
# 构建并运行全部测试（并发刷新 / 撤销竞态 / 显式拒绝 / 审计失败）
mvn test

# 启动服务
mvn spring-boot:run
# 默认端口 8080
```

---

## 2. 凭证生命周期

凭证模型（`iam.model.Credential`）为不可变快照：

| 字段 | 含义 |
| --- | --- |
| `credentialId` | 凭证稳定标识，**轮换后保持不变**，形成一条凭证链 |
| `secret` | 当次密文，每次刷新都会变化（`tok_` 前缀的随机令牌） |
| `subject` / `roles` | 归属主体与签发时绑定的角色快照 |
| `issuedAt` / `expiresAt` | 签发与过期时间 |
| `status` | `ACTIVE` / `ROTATED` / `REVOKED` |
| `version` | 凭证版本，从 0 开始，每轮换一次 +1 |

生命周期操作：

- **签发** `POST /iam/credentials`：生成新凭证。
- **刷新（轮换）** `POST /iam/credentials/refresh`（带 `Authorization: Bearer <secret>`）：
  原子地**换发新密文、旧密文立即失效**；`credentialId` 不变、`version` +1。
- **撤销** `POST /iam/credentials/{credentialId}/revoke`：终态操作，幂等。
- **访问** `POST /iam/access`：携带密文访问受保护资源。
- **账号级批量吊销** `POST /iam/accounts/{subject}/revoke-all`：一键结束该账号全部登录，见 §2.4。
- **账号会话汇总** `GET /iam/accounts/{subject}/sessions`：查看该账号当前登录情况，见 §2.5。

### 2.1 刷新的并发与失败语义

- 凭证存储对每个凭证用内置锁做**比较并轮换（CAS）**；存储层用一把变更锁串行化
  “旧密文索引摘除 + CAS 轮换 + 新密文挂载”，该动作是**一个原子操作**。
- 同一凭证的 N 个并发刷新：**恰好 1 次成功**，其余全部失败，原因码为 `REFRESH_CONFLICT`。
- 轮换一旦提交：旧密文立即无法解析（`INVALID_CREDENTIAL`），新密文立即可用。
- 与撤销交错时，锁内判定优先级为：**已撤销 > 已过期 > 版本竞争 > 成功**，结果确定。

### 2.2 撤销与在途请求的确定性

- 撤销是终态。撤销后**保留**密文到凭证 id 的映射并把状态置为 `REVOKED`，
  从而能把“已撤销”（`CREDENTIAL_REVOKED`）与“无效/已轮换”（`INVALID_CREDENTIAL`）区分开；
  状态检查保证已撤销凭证永远不会被放行。
- 访问链路在授权判定通过、准备放行前，会按 `credentialId` **重新读取凭证状态复查**，
  消除“判定后、放行前”被撤销/轮换/过期的竞态窗口。
- 撤销与访问并发：撤销**提交前**已线性化的请求可能放行；撤销一旦提交，之后的请求一律拒绝。
  不存在“已撤销凭证仍继续访问”的情况。
- 撤销与刷新并发 200 次迭代测试：轮换可能先发生，但最终态必定是 `REVOKED`，原密文要么
  `INVALID_CREDENTIAL`（被轮换）要么 `CREDENTIAL_REVOKED`，二者都不放行。

### 2.3 凭证失败原因可区分

| 场景 | 原因码 | HTTP |
| --- | --- | --- |
| 密文不存在 / 已被轮换失效 | `INVALID_CREDENTIAL` | 401 |
| 已过期 | `CREDENTIAL_EXPIRED` | 401 |
| 已撤销 | `CREDENTIAL_REVOKED` | 401 |
| 并发刷新竞争失败 | `REFRESH_CONFLICT` | 409 |
| 撤销未知 id | `UNKNOWN_CREDENTIAL_ID` | 404 |

凭证认证判定优先级：**存在性 → 撤销 → 过期 → 状态有效**。

### 2.4 账号级批量吊销（一键结束全部登录）

`POST /iam/accounts/{subject}/revoke-all` 把该账号**当前所有仍生效的凭证**一次吊销：

- **覆盖刷新派生的后代凭证**：刷新轮换共用同一 `credentialId` 链，批量吊销按链终止，
  即使某凭证在交错中刚被刷新出新密文，操作返回后该新密文同样不可用。
- **已过期 / 已吊销的被识别而非误报**：结果中 `expiredCount` 与 `alreadyRevokedCount`
  分别统计这两类，不计入本次 `revokedCount`。
- **原子性（整体成功或整体失败）**：审计写入与状态变更在存储变更锁内串联——
  **先写审计，审计写不进去则一个凭证都不改**，对外返回 `AUDIT_UNAVAILABLE`（503），
   绝不留下“吊销一半”的中间态，也不透出底层报错细节。
- **与并发刷新/访问交错的确定性**：批量吊销与单凭证刷新、撤销共用同一把存储锁。
  操作**返回之后**：该账号不存在仍可用的凭证（访问一律 401），
  也不存在“已吊销又被一次刷新重新续期”的窗口（刷新对 REVOKED 一律拒绝）。
  交错期间已线性化的访问/刷新可能成功，属于返回前的正常竞争。
- **幂等且可重复**：重复执行结果稳定。账号当前没有有效凭证时返回可区分的
  `NO_ACTIVE_CREDENTIALS`（404）——这是“没什么可做”的终态反馈，调用方可忽略；
  而 `AUDIT_UNAVAILABLE`（503）表示系统侧一时不可用，调用方应重试。两者不会混淆。
- **可辨识标识**：每次批量操作生成 `operationId`，同时写入响应与审计事件
  （`operation=REVOKE_ALL`），便于事后核对处置是否已收敛。

响应示例：

```json
{"operationId":"op_…","subject":"alice","revokedCount":2,
 "alreadyRevokedCount":1,"expiredCount":1,
 "revokedCredentialIds":["cred_…","cred_…"]}
```

### 2.5 账号会话汇总（查看当前登录情况）

`GET /iam/accounts/{subject}/sessions` 返回该账号**当前仍生效**的会话清单：

```json
{"subject":"alice","activeCount":2,
 "sessions":[{"credentialId":"cred_…","version":1,"issuedAt":…,"expiresAt":…}]}
```

- 只统计 `ACTIVE` 且未过期的凭证；已吊销、已过期的不在列。
- 每个会话带 `credentialId + version` 可辨识标识；批量吊销返回后可用本接口确认
  `activeCount` 收敛为 0。
- 存储维护 **主体索引**（subject → 该主体全部凭证 id），按主体定位的开销只与
  该主体名下凭证数相关；查询为**只读快照、不取变更锁**，批量吊销也只在存储锁内做
  O(该主体凭证数) 的工作——两者都不会长时间卡住正常的访问与刷新。

---

## 3. 授权判定（RBAC + ABAC）

策略（`iam.model.Policy`）命中需同时满足：

1. 资源前缀匹配（支持普通前缀 `docs/` 与通配前缀 `docs*`，`*` 匹配全部）；
2. 动作相等（策略未指定动作则不限制）；
3. 主体角色命中策略的 `anyOfRoles` 任一角色（为空则不限制角色）；
4. 策略的 `attributeEquals` 属性等值条件**全部**满足（为空则不限制属性）。

主体属性由授权存储的当前快照提供，调用方无法伪造或传入滞后属性。

### 3.1 判定优先级

1. **显式 DENY 优先于 ALLOW**：只要存在命中的 `DENY`，即拒绝，原因 `EXPLICIT_DENY`，
   并记录命中的拒绝策略 id；
2. 无命中的 DENY 但存在命中的 ALLOW：放行，原因 `ALLOW`；
3. 无任何策略命中：**默认拒绝**，原因 `NO_MATCHING_POLICY`，对外统一为 `POLICY_DENIED`（403）。

### 3.2 变更的一致收敛

- 策略集合与主体属性保存在 `InMemoryAuthzStore` 的 `AtomicReference<AuthzSnapshot>` 中，
  每次增删改都构造**全新不可变快照**并原子发布，修订号 `revision` 单调递增。
- 一次判定只读一个快照，因此不会出现“半新半旧”的越权窗口：
  修订边界前的请求一律按旧快照收敛，之后一律按新快照收敛；**不会短暂越权，也不会永久沿用旧权限**。

### 3.3 无法判定 / 依赖异常

- 授权存储可通过 `/test/authz-faulty/true` 模拟故障；读取快照失败时按**失败关闭**处理，
  返回 `AUTHZ_INDETERMINATE`（500），绝不放行，也不向外透出底层异常堆栈。

---

## 4. 审计链路与失败语义

- 所有凭证生命周期操作（ISSUE / REFRESH / REVOKE）与每次 ACCESS 判定都生成不可变
  `AuditEvent`，记录输入（主体、资源、动作）与**完整判定依据**（命中策略 id、策略修订号、
  凭证版本、拒绝原因）。
- 审计存储基于 `CopyOnWriteArrayList`，原子追加，**并发下记录不丢失、事件 id 唯一**，
  可通过 `GET /iam/audit` 完整还原判定过程；查询返回防御性拷贝，不可篡改。
- **审计不可写时，受保护操作失败关闭**：本应放行的请求返回 `AUDIT_UNAVAILABLE`（503），
  绝不放行；可用 `/test/audit-writable/false` 模拟，恢复后立即正常。
- 对于“本来就拒绝”的请求，审计不可写不改变拒绝结论（仍返回原始的 401/403 原因），
  因为拒绝从不依赖审计是否可用。

### 4.1 访问链路顺序

```
参数校验
 → 凭证认证（INVALID / EXPIRED / REVOKED）
 → 授权判定（EXPLICIT_DENY / NO_MATCHING_POLICY / AUTHZ_INDETERMINATE）
 → 放行前凭证复查（消除撤销 / 轮换 / 过期竞态）
 → 审计落盘（失败则 AUDIT_UNAVAILABLE，拒绝放行）
 → 放行
```

每个拒绝分支都会先尽力写审计，再抛出携带安全原因码的异常；统一异常处理器
（`web.GlobalExceptionHandler`）把业务异常映射为安全的 `{error, message}` 响应，
未知异常一律收敛为 `INTERNAL_ERROR`（500），**不向外透出底层异常细节**。

---

## 5. HTTP 接口一览

| 方法 & 路径 | 说明 |
| --- | --- |
| `POST /iam/credentials` | 签发凭证，body：`{subject, roles?, ttlMillis?}`（默认 1 小时） |
| `POST /iam/credentials/refresh` | 刷新轮换，Header：`Authorization: Bearer <secret>` |
| `POST /iam/credentials/{id}/revoke` | 撤销凭证 |
| `POST /iam/accounts/{subject}/revoke-all` | 账号级批量吊销（一键结束全部登录） |
| `GET  /iam/accounts/{subject}/sessions` | 账号当前有效会话汇总 |
| `POST /iam/access` | 访问判定，body：`{resource, action}`，Header：Bearer |
| `POST /iam/policies` | 新增/更新策略，body：`{policyId, effect(ALLOW/DENY), resourcePrefix, action, anyOfRoles?, attributeEquals?}` |
| `POST /iam/subjects` | 设置主体属性，body：`{subject, attributes}` |
| `GET  /iam/audit` | 查询全部审计事件 |
| `POST /test/audit-writable/{true|false}` | （仅本地验证）切换审计可写 |
| `POST /test/authz-faulty/{true|false}` | （仅本地验证）切换授权存储故障 |

---

## 6. 本地手工验证（curl）

```bash
BASE=http://localhost:8080

# 策略：reader 可读 docs/
curl -s -XPOST $BASE/iam/policies -H 'Content-Type: application/json' -d '{
  "policyId":"p-read","effect":"ALLOW","resourcePrefix":"docs/","action":"read",
  "anyOfRoles":["reader"]}'

# 显式拒绝策略：任何人不得读 docs/secret（即使命中上面的 ALLOW）
curl -s -XPOST $BASE/iam/policies -H 'Content-Type: application/json' -d '{
  "policyId":"p-deny-secret","effect":"DENY","resourcePrefix":"docs/secret","action":"read"}'

# 签发
ALICE=$(curl -s -XPOST $BASE/iam/credentials -H 'Content-Type: application/json' \
  -d '{"subject":"alice","roles":["reader"]}')
SECRET=$(echo $ALICE | sed -n 's/.*"secret":"\([^"]*\)".*/\1/p')
ID=$(echo $ALICE | sed -n 's/.*"credentialId":"\([^"]*\)".*/\1/p')

# 允许
curl -s -XPOST $BASE/iam/access -H "Authorization: Bearer $SECRET" \
  -H 'Content-Type: application/json' -d '{"resource":"docs/a","action":"read"}'

# 显式拒绝优先（403 POLICY_DENIED）
curl -i -XPOST $BASE/iam/access -H "Authorization: Bearer $SECRET" \
  -H 'Content-Type: application/json' -d '{"resource":"docs/secret/x","action":"read"}'

# 刷新轮换
NEW=$(curl -s -XPOST $BASE/iam/credentials/refresh -H "Authorization: Bearer $SECRET")
NEWSECRET=$(echo $NEW | sed -n 's/.*"secret":"\([^"]*\)".*/\1/p')
# 旧密文立即失效（401 INVALID_CREDENTIAL）
curl -i -XPOST $BASE/iam/access -H "Authorization: Bearer $SECRET" \
  -H 'Content-Type: application/json' -d '{"resource":"docs/a","action":"read"}'

# 撤销新凭证后再访问（401 CREDENTIAL_REVOKED）
curl -s -XPOST $BASE/iam/credentials/$ID/revoke
curl -i -XPOST $BASE/iam/access -H "Authorization: Bearer $NEWSECRET" \
  -H 'Content-Type: application/json' -d '{"resource":"docs/a","action":"read"}'

# 审计失败 -> 受保护操作失败关闭（503 AUDIT_UNAVAILABLE）
curl -s -XPOST $BASE/test/audit-writable/false
curl -i -XPOST $BASE/iam/access -H "Authorization: Bearer $SECRET" \
  -H 'Content-Type: application/json' -d '{"resource":"docs/a","action":"read"}'
curl -s -XPOST $BASE/test/audit-writable/true

# 查看审计链
curl -s $BASE/iam/audit

# ---- 账号级批量吊销 ----
# 同账号再签发一个凭证
curl -s -XPOST $BASE/iam/credentials -H 'Content-Type: application/json' \
  -d '{"subject":"alice","roles":["reader"]}'
# 查看当前登录情况（activeCount=2）
curl -s $BASE/iam/accounts/alice/sessions
# 一键结束全部登录（响应含 operationId 与各计数）
curl -s -XPOST $BASE/iam/accounts/alice/revoke-all
# 确认收敛（activeCount=0）
curl -s $BASE/iam/accounts/alice/sessions
# 重复执行 -> 404 NO_ACTIVE_CREDENTIALS（可忽略，非系统故障）
curl -i -XPOST $BASE/iam/accounts/alice/revoke-all
# 审计不可用 -> 503 AUDIT_UNAVAILABLE，且一个凭证都不会被改（整体失败）
curl -s -XPOST $BASE/iam/credentials -H 'Content-Type: application/json' \
  -d '{"subject":"bob","roles":["reader"]}'
curl -s -XPOST $BASE/test/audit-writable/false
curl -i -XPOST $BASE/iam/accounts/bob/revoke-all
curl -s -XPOST $BASE/test/audit-writable/true
curl -s $BASE/iam/accounts/bob/sessions   # activeCount 仍为 1
```

---

## 7. 自动化测试

| 测试类 | 关注点 |
| --- | --- |
| `CredentialRefreshConcurrencyTest` | 16 线程并发刷新仅 1 次成功、其余 `REFRESH_CONFLICT`；旧密文立即失效；串行轮换链一致 |
| `CredentialRevocationRaceTest` | 撤销与 24 路在途访问交错；撤销/刷新 200 次竞态迭代；REVOKED/EXPIRED/INVALID 可区分 |
| `AuthorizationPolicyTest` | 显式 DENY 优先、默认拒绝、RBAC/ABAC 命中、策略与属性变更按修订边界收敛、依赖故障失败关闭 |
| `AuditFailureTest` | 审计不可写时失败关闭（503）、拒绝原因不被覆盖、32 路并发审计不丢重且 id 唯一、审计只读不可篡改 |
| `AccountGovernanceTest` | 批量吊销与并发刷新（100 次竞态迭代）/并发访问交错、重复吊销、无有效凭证、审计不可用整体失败、会话汇总收敛与不阻塞 |
| `WebEndToEndTest` | 经 MockMvc 验证各 HTTP 入口状态码与错误码一致、响应不泄露底层细节；含批量吊销的 404/503 可区分与原子性 |

测试通过 `ManualClock` 可控推进时间以**确定性地触发过期**，不依赖真实等待；
日志中会打印每次判定的**输入与判定依据**（`log.info / log.warn`，见 surefire 输出）。
所有测试均为内存态、不依赖任何外部服务或真实凭据。

```bash
mvn -Dtest=CredentialRefreshConcurrencyTest,CredentialRevocationRaceTest,AuthorizationPolicyTest,AuditFailureTest,AccountGovernanceTest test
```
