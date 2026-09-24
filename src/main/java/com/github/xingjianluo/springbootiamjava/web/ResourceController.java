package com.github.xingjianluo.springbootiamjava.web;

import com.github.xingjianluo.springbootiamjava.guard.AccessGuard;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/** 受保护资源入口：所有判定经 {@link AccessGuard} 统一收敛。 */
@RestController
@RequestMapping("/api/resources")
public class ResourceController {

    private final AccessGuard accessGuard;

    public ResourceController(AccessGuard accessGuard) {
        this.accessGuard = accessGuard;
    }

    @PostMapping("/access")
    public Map<String, String> access(@RequestBody(required = false) ApiDtos.AccessRequest request) {
        if (request == null) {
            return Map.of();
        }
        AccessGuard.GuardResult result = accessGuard.authorizeAccess(
                request.token(), request.resource(), request.action(),
                request.resourceAttributes(), request.environment());
        Map<String, String> body = new LinkedHashMap<>();
        body.put("subject", result.subject());
        body.put("resource", result.resource());
        body.put("action", result.action());
        body.put("decisionBasis", result.decisionBasis());
        body.put("outcome", "ALLOWED");
        return body;
    }
}
