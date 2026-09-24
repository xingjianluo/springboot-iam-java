package com.github.xingjianluo.springbootiamjava.tests;

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

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * HTTP 端到端：验证各入口错误码/HTTP 状态可区分，且响应体不泄露底层异常细节。
 */
@SpringBootTest
@AutoConfigureMockMvc
class WebEndToEndTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void resetState() throws Exception {
        // 恢复审计后端
        mockMvc.perform(post("/api/admin/audit/writable").param("writable", "true"))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/admin/subjects")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"subject":"helen","roles":["reader"],"attributes":{"dept":"ops"}}
                                """))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/admin/policies")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                [
                                  {"name":"deny-ops-delete","effect":"DENY","resource":"docs","action":"delete",
                                   "anyRole":null,"subjectAttributes":{"dept":"ops"},"resourceAttributes":null,"priority":1},
                                  {"name":"allow-reader-read","effect":"ALLOW","resource":"docs","action":"read",
                                   "anyRole":["reader"],"subjectAttributes":null,"resourceAttributes":null,"priority":10}
                                ]
                                """))
                .andExpect(status().isOk());
    }

    @Test
    void fullLifecycleAndDistinguishableErrorsOverHttp() throws Exception {
        // 1) 签发
        MvcResult issued = mockMvc.perform(post("/api/credentials")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"subject":"helen","ttlMillis":60000}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andReturn();
        String token = objectMapper.readTree(issued.getResponse().getContentAsString()).get("token").asText();

        // 2) 允许的访问
        mockMvc.perform(post("/api/resources/access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(accessBody(token, "docs", "read")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.outcome").value("ALLOWED"));

        // 3) 显式 DENY（ABAC：dept=ops 的 delete）=> 403 AUTHZ_DENIED
        MvcResult denied = mockMvc.perform(post("/api/resources/access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(accessBody(token, "docs", "delete")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("AUTHZ_DENIED"))
                .andReturn();
        assertFalse(denied.getResponse().getContentAsString().contains("Exception"));

        // 4) 伪造凭证 => 401 CREDENTIAL_INVALID
        mockMvc.perform(post("/api/resources/access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(accessBody("cred-unknown", "docs", "read")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("CREDENTIAL_INVALID"));

        // 5) 缺 token => 401 CREDENTIAL_MISSING
        mockMvc.perform(post("/api/resources/access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"resource":"docs","action":"read"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("CREDENTIAL_MISSING"));

        // 6) 审计后端故障 => 503 AUDIT_UNAVAILABLE，操作不提交
        mockMvc.perform(post("/api/admin/audit/writable").param("writable", "false"))
                .andExpect(status().isOk());
        MvcResult auditDown = mockMvc.perform(post("/api/resources/access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(accessBody(token, "docs", "read")))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.errorCode").value("AUDIT_UNAVAILABLE"))
                .andReturn();
        String auditBody = auditDown.getResponse().getContentAsString();
        assertFalse(auditBody.contains("UnavailableException"), "internal type must not leak");
        assertFalse(auditBody.contains("not writable"), "internal detail must not leak");

        // 7) 恢复后撤销 => 旧凭证 401 CREDENTIAL_REVOKED
        mockMvc.perform(post("/api/admin/audit/writable").param("writable", "true"))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/credentials/revoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"token":"%s","reason":"e2e-revoke"}
                                """.formatted(token)))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/resources/access")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(accessBody(token, "docs", "read")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("CREDENTIAL_REVOKED"));

        // 8) 审计轨迹可查且包含判定依据
        MvcResult audit = mockMvc.perform(get("/api/admin/audit/helen"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode events = objectMapper.readTree(audit.getResponse().getContentAsString());
        String auditText = events.toString();
        TestReport.log("http-audit-trail",
                "eventCount=" + events.size() + " hasBasis=" + auditText.contains("decisionBasis"));
        assertTrue(auditText.contains("ALLOWED"));
        assertTrue(auditText.contains("AUTHZ_DENIED"));
        assertTrue(auditText.contains("CREDENTIAL_REVOKED"));
        assertTrue(auditText.contains("e2e-revoke"));
    }

    private String accessBody(String token, String resource, String action) {
        try {
            return objectMapper.writeValueAsString(Map.of(
                    "token", token,
                    "resource", resource,
                    "action", action,
                    "resourceAttributes", Map.of(),
                    "environment", Map.of()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
