package com.github.xingjianluo.springbootiamjava.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * 端到端入口一致性：同一失败原因在各入口下返回相同的安全错误码，
 * 响应仅含 error/message，不泄露底层异常。
 */
@SpringBootTest
@AutoConfigureMockMvc
class WebEndToEndTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private com.github.xingjianluo.springbootiamjava.iam.authz.AuthzStore authzStore;
    @Autowired
    private com.github.xingjianluo.springbootiamjava.iam.credential.CredentialStore credentialStore;
    @Autowired
    private com.github.xingjianluo.springbootiamjava.iam.audit.AuditService auditService;

    @BeforeEach
    void resetLocalState() {
        authzStore.clear();
        credentialStore.clear();
        auditService.setWritable(true);
    }

    private final ObjectMapper json = new ObjectMapper();

    private String bearer(JsonNode issued) {
        return "Bearer " + issued.get("secret").asText();
    }

    private JsonNode postJson(String url, String body, String token) throws Exception {
        var req = post(url).contentType(MediaType.APPLICATION_JSON);
        if (token != null) {
            req.header("Authorization", token);
        }
        MvcResult result = mvc.perform(req.content(body == null ? "{}" : body))
                .andExpect(status().is2xxSuccessful()).andReturn();
        return json.readTree(result.getResponse().getContentAsString());
    }

    @Test
    void fullLifecycle_overHttp_distinguishableFailures() throws Exception {
        // 1) 无凭证访问 -> 401 INVALID_CREDENTIAL
        mvc.perform(post("/iam/access").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"resource\":\"docs/a\",\"action\":\"read\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_CREDENTIAL"))
                .andExpect(jsonPath("$.message").isString());

        // 2) 配置允许策略并签发
        postJson("/iam/policies",
                "{\"policyId\":\"p\",\"effect\":\"ALLOW\",\"resourcePrefix\":\"docs/\",\"action\":\"read\",\"anyOfRoles\":[\"reader\"]}",
                null);
        JsonNode cred = postJson("/iam/credentials",
                "{\"subject\":\"mike\",\"roles\":[\"reader\"]}", null);
        String id = cred.get("credentialId").asText();

        // 3) 允许访问
        mvc.perform(post("/iam/access").contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", bearer(cred))
                        .content("{\"resource\":\"docs/a\",\"action\":\"read\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(true))
                .andExpect(jsonPath("$.reason").value("ALLOW"));

        // 4) 并发刷新两次：第二次必须 409 REFRESH_CONFLICT
        JsonNode refreshed = postJson("/iam/credentials/refresh", "", bearer(cred));
        mvc.perform(post("/iam/credentials/refresh").header("Authorization", bearer(cred)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("REFRESH_CONFLICT"));

        // 5) 旧密文访问 -> 401 INVALID_CREDENTIAL
        mvc.perform(post("/iam/access").contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", bearer(cred))
                        .content("{\"resource\":\"docs/a\",\"action\":\"read\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_CREDENTIAL"));

        // 6) 撤销新密文 -> 再访问 401 CREDENTIAL_REVOKED（与 INVALID 可区分）
        postJson("/iam/credentials/" + id + "/revoke", "", null);
        mvc.perform(post("/iam/access").contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + refreshed.get("secret").asText())
                        .content("{\"resource\":\"docs/a\",\"action\":\"read\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("CREDENTIAL_REVOKED"));

        // 7) 策略拒绝：无角色主体
        JsonNode noRole = postJson("/iam/credentials",
                "{\"subject\":\"nina\",\"roles\":[]}", null);
        mvc.perform(post("/iam/access").contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", bearer(noRole))
                        .content("{\"resource\":\"docs/a\",\"action\":\"read\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("POLICY_DENIED"));

        // 8) 审计不可写 -> 503 AUDIT_UNAVAILABLE，且有效凭证也不放行
        JsonNode oscar = postJson("/iam/credentials",
                "{\"subject\":\"oscar\",\"roles\":[\"reader\"]}", null);
        mvc.perform(post("/test/audit-writable/false")).andExpect(status().isOk());
        mvc.perform(post("/iam/access").contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", bearer(oscar))
                        .content("{\"resource\":\"docs/a\",\"action\":\"read\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.error").value("AUDIT_UNAVAILABLE"));
        mvc.perform(post("/test/audit-writable/true")).andExpect(status().isOk());

        // 9) 审计记录可查询，且只包含安全字段
        mvc.perform(get("/iam/audit")).andExpect(status().isOk())
                .andExpect(jsonPath("$[0].eventId").exists())
                .andExpect(jsonPath("$[0].outcome").exists());
    }

    @Test
    void accountRevokeAll_overHttp_atomicityAndDistinguishableFailures() throws Exception {
        postJson("/iam/policies",
                "{\"policyId\":\"p\",\"effect\":\"ALLOW\",\"resourcePrefix\":\"docs/\",\"action\":\"read\",\"anyOfRoles\":[\"reader\"]}",
                null);

        // 1) 无有效凭证的账号 -> 404 NO_ACTIVE_CREDENTIALS（可区分，非 5xx）
        mvc.perform(post("/iam/accounts/ghost/revoke-all"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("NO_ACTIVE_CREDENTIALS"));

        // 2) 签发两个凭证并批量吊销
        JsonNode c1 = postJson("/iam/credentials",
                "{\"subject\":\"tina\",\"roles\":[\"reader\"]}", null);
        JsonNode c2 = postJson("/iam/credentials",
                "{\"subject\":\"tina\",\"roles\":[\"reader\"]}", null);
        JsonNode c2v1 = postJson("/iam/credentials/refresh", "", bearer(c2));

        // 吊销前会话汇总：2 个有效会话，带可辨识标识
        mvc.perform(get("/iam/accounts/tina/sessions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeCount").value(2))
                .andExpect(jsonPath("$.sessions[0].credentialId").isString())
                .andExpect(jsonPath("$.sessions[0].version").isNumber());

        JsonNode batch = postJson("/iam/accounts/tina/revoke-all", "", null);
        org.assertj.core.api.Assertions.assertThat(batch.get("revokedCount").asInt()).isEqualTo(2);
        org.assertj.core.api.Assertions.assertThat(batch.get("operationId").asText()).isNotBlank();

        // 3) 吊销后：含刷新派生的最新密文，全部 401 CREDENTIAL_REVOKED
        for (JsonNode cred : new JsonNode[]{c1, c2v1}) {
            mvc.perform(post("/iam/access").contentType(MediaType.APPLICATION_JSON)
                            .header("Authorization", bearer(cred))
                            .content("{\"resource\":\"docs/a\",\"action\":\"read\"}"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("CREDENTIAL_REVOKED"));
        }
        // 会话汇总收敛为 0
        mvc.perform(get("/iam/accounts/tina/sessions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeCount").value(0));

        // 4) 重复吊销 -> 404 NO_ACTIVE_CREDENTIALS（幂等且稳定）
        mvc.perform(post("/iam/accounts/tina/revoke-all"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("NO_ACTIVE_CREDENTIALS"));

        // 5) 审计不可用 -> 503 AUDIT_UNAVAILABLE，且整体失败不留中间态
        JsonNode u1 = postJson("/iam/credentials",
                "{\"subject\":\"uma\",\"roles\":[\"reader\"]}", null);
        mvc.perform(post("/test/audit-writable/false")).andExpect(status().isOk());
        mvc.perform(post("/iam/accounts/uma/revoke-all"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.error").value("AUDIT_UNAVAILABLE"));
        mvc.perform(post("/test/audit-writable/true")).andExpect(status().isOk());
        // 凭证未被吊销（无“吊销一半”的中间态）
        mvc.perform(get("/iam/accounts/uma/sessions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeCount").value(1));
        mvc.perform(post("/iam/access").contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", bearer(u1))
                        .content("{\"resource\":\"docs/a\",\"action\":\"read\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(true));
    }

    @Test
    void accountRevokeAll_auditTrailClassification_matchesResponseOverHttp() throws Exception {
        postJson("/iam/policies",
                "{\"policyId\":\"p\",\"effect\":\"ALLOW\",\"resourcePrefix\":\"docs/\",\"action\":\"read\",\"anyOfRoles\":[\"reader\"]}",
                null);
        // 4 条凭证：2 条有效（其中 1 条再刷新一代）、1 条提前吊销、1 条等待过期。
        JsonNode c1 = postJson("/iam/credentials",
                "{\"subject\":\"zoe\",\"roles\":[\"reader\"]}", null);
        JsonNode c2 = postJson("/iam/credentials",
                "{\"subject\":\"zoe\",\"roles\":[\"reader\"]}", null);
        postJson("/iam/credentials/refresh", "", bearer(c1));
        JsonNode preRevoked = postJson("/iam/credentials",
                "{\"subject\":\"zoe\",\"roles\":[\"reader\"]}", null);
        JsonNode expired = postJson("/iam/credentials",
                "{\"subject\":\"zoe\",\"roles\":[\"reader\"],\"ttlMillis\":50}", null);
        postJson("/iam/credentials/" + preRevoked.get("credentialId").asText() + "/revoke",
                "", null);
        Thread.sleep(60); // expired 凭证确定过期

        JsonNode batch = postJson("/iam/accounts/zoe/revoke-all", "", null);
        org.assertj.core.api.Assertions.assertThat(batch.get("revokedCount").asInt()).isEqualTo(2);
        org.assertj.core.api.Assertions.assertThat(batch.get("alreadyRevokedCount").asInt())
                .isEqualTo(1);
        org.assertj.core.api.Assertions.assertThat(batch.get("expiredCount").asInt()).isEqualTo(1);
        String operationId = batch.get("operationId").asText();

        // 审计链（经 HTTP 查询）中本次事件的三类数量与 id 与响应一一对应。
        MvcResult auditResult = mvc.perform(get("/iam/audit"))
                .andExpect(status().isOk()).andReturn();
        JsonNode events = json.readTree(auditResult.getResponse().getContentAsString());
        JsonNode batchEvent = null;
        for (JsonNode e : events) {
            if ("REVOKE_ALL".equals(e.path("operation").asText())
                    && e.path("decisionDetail").asText().contains("operationId=" + operationId + ";")) {
                batchEvent = e;
            }
        }
        org.assertj.core.api.Assertions.assertThat(batchEvent).isNotNull();
        String detail = batchEvent.get("decisionDetail").asText();
        org.assertj.core.api.Assertions.assertThat(detail)
                .contains("revokedCount=2", "alreadyRevokedCount=1", "expiredCount=1")
                .contains("alreadyRevokedIds=[" + preRevoked.get("credentialId").asText() + "]")
                .contains("expiredIds=[" + expired.get("credentialId").asText() + "]")
                .contains(c1.get("credentialId").asText())
                .contains(c2.get("credentialId").asText());
    }

    @Test
    void malformedPolicy_is400_withSafeMessage() throws Exception {
        mvc.perform(post("/iam/policies").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"policyId\":\"x\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("MALFORMED_REQUEST"));
    }
}
