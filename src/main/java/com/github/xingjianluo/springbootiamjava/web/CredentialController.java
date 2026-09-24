package com.github.xingjianluo.springbootiamjava.web;

import com.github.xingjianluo.springbootiamjava.credential.CredentialService;
import com.github.xingjianluo.springbootiamjava.credential.CredentialView;
import com.github.xingjianluo.springbootiamjava.common.ApiException;
import com.github.xingjianluo.springbootiamjava.common.ErrorCode;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/credentials")
public class CredentialController {

    private final CredentialService credentialService;

    public CredentialController(CredentialService credentialService) {
        this.credentialService = credentialService;
    }

    @PostMapping
    public CredentialView issue(@RequestBody(required = false) ApiDtos.IssueRequest request) {
        if (request == null || request.subject() == null || request.subject().isBlank()) {
            throw new ApiException(ErrorCode.BAD_REQUEST, "subject is required");
        }
        return credentialService.issue(request.subject(), request.ttlMillis());
    }

    @PostMapping("/refresh")
    public CredentialView refresh(@RequestBody(required = false) ApiDtos.RefreshRequest request) {
        if (request == null || request.token() == null || request.token().isBlank()) {
            throw new ApiException(ErrorCode.CREDENTIAL_MISSING, "token is required");
        }
        return credentialService.refresh(request.token());
    }

    @PostMapping("/revoke")
    public CredentialView revoke(@RequestBody(required = false) ApiDtos.RevokeRequest request) {
        if (request == null || request.token() == null || request.token().isBlank()) {
            throw new ApiException(ErrorCode.CREDENTIAL_MISSING, "token is required");
        }
        return credentialService.revoke(request.token(), request.reason());
    }
}
