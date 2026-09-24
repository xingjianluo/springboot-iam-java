package com.github.xingjianluo.springbootiamjava.web;

import com.github.xingjianluo.springbootiamjava.audit.AuditEvent;
import com.github.xingjianluo.springbootiamjava.audit.AuditService;
import com.github.xingjianluo.springbootiamjava.authz.PolicyRepository;
import com.github.xingjianluo.springbootiamjava.authz.PolicyRule;
import com.github.xingjianluo.springbootiamjava.authz.PolicySet;
import com.github.xingjianluo.springbootiamjava.subject.SubjectDirectory;
import com.github.xingjianluo.springbootiamjava.subject.SubjectProfile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** 本地管理入口：主体画像、策略、审计故障注入与审计轨迹查询。 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final SubjectDirectory subjectDirectory;
    private final PolicyRepository policyRepository;
    private final AuditService auditService;

    public AdminController(SubjectDirectory subjectDirectory,
                           PolicyRepository policyRepository,
                           AuditService auditService) {
        this.subjectDirectory = subjectDirectory;
        this.policyRepository = policyRepository;
        this.auditService = auditService;
    }

    @PostMapping("/subjects")
    public SubjectProfile upsertSubject(@RequestBody ApiDtos.SubjectUpsertRequest request) {
        return subjectDirectory.upsert(request.subject(), request.roles(), request.attributes());
    }

    @GetMapping("/subjects/{subject}")
    public SubjectProfile getSubject(@PathVariable String subject) {
        return subjectDirectory.snapshot(subject);
    }

    @PostMapping("/policies")
    public PolicySet replacePolicies(@RequestBody List<PolicyRule> rules) {
        return policyRepository.replaceAll(rules);
    }

    @GetMapping("/policies")
    public PolicySet currentPolicies() {
        return policyRepository.snapshot();
    }

    /** 模拟审计后端故障/恢复：false 后所有受保护操作 fail-closed。 */
    @PostMapping("/audit/writable")
    public Map<String, Boolean> setAuditWritable(@RequestParam boolean writable) {
        auditService.setWritable(writable);
        return Map.of("writable", auditService.isWritable());
    }

    @GetMapping("/audit/{subject}")
    public List<AuditEvent> auditOf(@PathVariable String subject) {
        return auditService.findBySubject(subject);
    }
}
