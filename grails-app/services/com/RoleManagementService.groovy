package com

import com.auth.Role
import grails.transaction.Transactional

@Transactional
class RoleManagementService {

    Boolean addNewRole(String newAuthority){
        try {
            Role role   =   new Role(authority: newAuthority).save(flush: true, failOnError: true)
            return true
        }catch (Exception e){
            return  false
        }
    }
}
