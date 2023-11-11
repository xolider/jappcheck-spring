package dev.vicart.jappcheck.spring.security

import org.springframework.security.authorization.AuthorizationDecision
import org.springframework.security.authorization.AuthorizationManager
import org.springframework.security.core.Authentication
import java.util.function.Supplier

class JAppCheckAuthorizationManager<T> : AuthorizationManager<T> {

    override fun check(authentication: Supplier<Authentication>?, `object`: T): AuthorizationDecision {
        return AuthorizationDecision(JAppCheckSecurityHolder.isGranted())
    }
}