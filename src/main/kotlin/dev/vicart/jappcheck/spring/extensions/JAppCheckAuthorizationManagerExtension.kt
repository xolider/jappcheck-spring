package dev.vicart.jappcheck.spring.extensions

import dev.vicart.jappcheck.spring.security.JAppCheckAuthorizationManager
import org.springframework.security.authorization.AuthorizationDecision
import org.springframework.security.authorization.AuthorizationManager
import org.springframework.security.web.access.intercept.RequestAuthorizationContext

fun AuthorizationManager<RequestAuthorizationContext>.withJAppCheck() : AuthorizationManager<RequestAuthorizationContext> {
    val jAppCheckAuthManager = JAppCheckAuthorizationManager<RequestAuthorizationContext>()
    return AuthorizationManager { auth, obj ->
        val parentDecision = this.check(auth, obj)
        val jAppCheckDecision = jAppCheckAuthManager.check(auth, obj)
        AuthorizationDecision(parentDecision?.isGranted ?: false && jAppCheckDecision.isGranted)
    }
}