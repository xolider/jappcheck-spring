package dev.vicart.jappcheck.spring.filters

import dev.vicart.jappcheck.core.JAppCheck
import dev.vicart.jappcheck.spring.security.JAppCheckSecurityHolder
import jakarta.annotation.PostConstruct
import jakarta.servlet.FilterChain
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.filter.GenericFilterBean

/**
 * Spring filter to check the X-Firebase-AppCheck header for the App Check token
 * @author Clément Vicart
 * @since 1.0
 */
@Component
class JAppCheckFilter : GenericFilterBean() {

    @Value("\${jappcheck.projectId}")
    private lateinit var projectId: String

    /**
     * Initializes the JAppCheck library
     */
    @PostConstruct
    fun setup() {
        JAppCheck.initialize(projectId)
    }

    /**
     * Looks for AppCheck token in the headers and tries to validate it
     */
    override fun doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain) {
        if(!(request is HttpServletRequest && response is HttpServletResponse)) {
            chain.doFilter(request, response)
            return
        }

        if(request.getAttribute("jappcheck.filtered") == true) {
            chain.doFilter(request, response)
            return
        } else {
            request.setAttribute("jappcheck.filtered", true)
        }

        doAppCheckFiltering(request, response, chain)
    }

    private fun doAppCheckFiltering(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        JAppCheckSecurityHolder.token = null

        val token = request.getHeader("X-Firebase-AppCheck")

        if(token == null) {
            logger.warn("AppCheck token is null")
            chain.doFilter(request, response)
            return
        }

        try {
            JAppCheck.checkAppToken(token)
            JAppCheckSecurityHolder.token = token
        } catch (e: Exception) {
            logger.error(e.message)
        } finally {
            chain.doFilter(request, response)
        }
    }
}