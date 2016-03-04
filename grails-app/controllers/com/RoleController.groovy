package com

import grails.plugin.springsecurity.annotation.Secured

class RoleController {
    def roleManagementService

    @Secured(['permitAll'])
    def newRole(){
        println "Adding new role -- >"
        Boolean roleAdditionStatus  =   roleManagementService.addNewRole("ROLE_COMMON")
        render  roleAdditionStatus
    }
}
