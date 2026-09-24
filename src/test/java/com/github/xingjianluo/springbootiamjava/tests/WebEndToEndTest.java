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
    void malformedPolicy_is400_withSafeMessage() throws Exception {
        mvc.perform(post("/iam/policies").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"policyId\":\"x\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("MALFORMED_REQUEST"));
    }
}
