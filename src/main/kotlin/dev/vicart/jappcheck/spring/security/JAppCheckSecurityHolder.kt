package dev.vicart.jappcheck.spring.security

object JAppCheckSecurityHolder {

    var token: String? = null

    fun isGranted(): Boolean = token != null
}