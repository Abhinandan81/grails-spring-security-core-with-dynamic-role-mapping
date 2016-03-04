## Grail's Spring Security Core Plugin With Dynamic Role Assignment - Implementation  ##
**reference link :**  		

 - 	http://grails-plugins.github.io/grails-spring-security-core/v2/index.html
 - http://grails-plugins.github.io/grails-spring-security-core/v2/guide/single.html#tutorials
 - https://github.com/Abhinandan81/grails-spring-security/tree/master
 
**Version specification :** Grail's  : 2.4.4 and Core Plugin :2.0.0


----------
Making @Secured annotations Dynamic : 
-------------
@Secured annotations we have used in  - https://github.com/Abhinandan81/grails-spring-security/tree/master
implementation is “*static*” annotation, means: we can not assign newly created roles or existing roles which were not added in the @Secured  annotations , to the list of users who can access the controller action(url) at run time.

***Create a new Domain Class as  :***

    		class RequestMap {
       		String url
       		static belongsTo = [Role]
       		static hasMany = [roles : Role]
       		static constraints = {
     	 	 	}
		    }

We have created many to many relationship between newly created RequestMap table and earlier created Role Table. url is the controller action url , on which we want to allocate role dynamically.


----------


***Add below things to resource.groovy :***

    // Place your Spring DSL code here
    beans = {
       closureVoter(PocClosureVoterService)
    }

Here : ***closureVoter*** is spring security core plugin service, which we are going to ***override***  
using our ***PocClosureVoterService*** service 

***Contents of PocClosureVoterService service :*** 

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


----------
**Scenario :** Suppose below action “*fetchExistingUserDetails*” (url = “/user/fetchExistingUserDetails” ) has only one role assigned . It means Only user with role “*ROLE_ADMIN*” can access this action.

    @Secured([‘ROLE_ADMIN’])	---> Static mapping
    def fetchExistingUserDetails(){
    	----------------
    }

What if I want to allow users with role “*ROLE_COMMON*” to be able to access this action. It means we need to dynamically allocate new role to @Secured list of annotations.

*Code Sample in service to add role dynamically Using above created domain class “RequestMap”*

       def addRoles(){
           try {
               /*adding new url if it’s not already exist , for which we want to 
               allocate role dynamically*/
               RequestMap requestMap = new RequestMap(url : 
               "/user/fetchExistingUserDetails")
               //finding role to assign for the URL
               Role role = Role.findByAuthority("ROLE_COMMON")
			    //Assigning “ROLE_COMMON” to URL  "/user/fetchExistingUserDetails"
               requestMap.addToRoles(role)
               requestMap.save()
               return true
           }catch (Exception e){
               return  false
           }
       }


----------


Now if you are try to access the url *“/user/fetchExistingUserDetails”* (to which statically  only user with role  "*ROLE_ADMIN*" were authorized to access) using the user having Role “*ROLE_COMMON*” it will be accessible as we have dynamically added the  *ROLE_COMMON* as a authorized role.