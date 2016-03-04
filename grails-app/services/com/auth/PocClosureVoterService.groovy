package com.auth

import grails.plugin.springsecurity.access.vote.ClosureConfigAttribute
import grails.transaction.Transactional

import grails.plugin.springsecurity.annotation.SecuredClosureDelegate
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.Assert;

@Transactional
class PocClosureVoterService implements AccessDecisionVoter<FilterInvocation>, ApplicationContextAware {

    protected final Logger log = LoggerFactory.getLogger(getClass())

    protected ApplicationContext ctx

    public int vote(Authentication authentication, FilterInvocation fi, Collection<ConfigAttribute> attributes) {

        Assert.notNull(authentication, "authentication cannot be null")
        Assert.notNull(fi, "object cannot be null")
        Assert.notNull(attributes, "attributes cannot be null")

        //log.trace("vote() Authentication {}, FilterInvocation {} ConfigAttributes {}", new Object[] { authentication, fi, attributes });

        List allowedRolesOfRequestedUrl     = attributes as List                   // Allowed Roles of requested URL
        String requestedUrl                 = fi.getRequestUrl().toString()        // Requested URL
        Set userRoles                       = authentication.authorities as Set    // Roles assigned to user
        Set TotalAllowedRolesOfRequestedUrl = []                                   // Total allowed roles of requested URL

        ClosureConfigAttribute attribute = null

        for (ConfigAttribute a : attributes) {
            if (a instanceof ClosureConfigAttribute) {
                attribute = (ClosureConfigAttribute) a
                break
            }
        }

        // Add roles from RequestMap
        RequestMap requestMap = RequestMap?.findByUrl(requestedUrl)
        if (requestMap?.roles != null) {
            requestMap.roles.each { role ->
                TotalAllowedRolesOfRequestedUrl << role.authority
            }
        }

        // Add roles defined by @Secured annotation
        allowedRolesOfRequestedUrl.each { role ->
            TotalAllowedRolesOfRequestedUrl << role.toString()
        }

        if (TotalAllowedRolesOfRequestedUrl.intersect(userRoles)) {
            return ACCESS_GRANTED
        } else {

            if (attribute == null) {
                log.trace("No ClosureConfigAttribute found")
                return ACCESS_ABSTAIN
            }
            Closure<?> closure = (Closure<?>) attribute.getClosure().clone()
            closure.setDelegate(new SecuredClosureDelegate(authentication, fi, ctx))
            Object result = closure.call()

            if (result instanceof Boolean) {

                log.trace("Closure result: {}", result);
                return ((Boolean)result) ? ACCESS_GRANTED : ACCESS_DENIED
            }

            // TODO log warning
            return ACCESS_DENIED
        }
    }

    public boolean supports(ConfigAttribute attribute) {
        return attribute instanceof ClosureConfigAttribute
    }

    public boolean supports(Class<?> clazz) {
        return clazz.isAssignableFrom(FilterInvocation.class)
    }

    public void setApplicationContext(ApplicationContext applicationContext) {
        ctx = applicationContext
    }
}
