package com

import com.auth.RequestMap
import com.auth.Role
import com.auth.User
import com.auth.UserRole
import grails.transaction.Transactional

@Transactional
class UserManagementService {

    Boolean registerUser(String userName,String password){
        try {
            //New user registration process
            User user = new User(username: userName, password: password).save(flush: true, failOnError: true)
            //Deciding and finding role for the new user
            println "fetching role for new user"
            Role role = Role.findByAuthority("ROLE_COMMON")
            //Assigning role to newly created user
            UserRole.create(user, role, true)
            println "role added to the new user"
            return true
        }catch (Exception e){
            return  false
        }
    }

    def fetchUserDetails(){
        def userDetails =   User.findAll()
        return  userDetails
    }

    def addRoles(){
        try {
            //New user registration process
            RequestMap requestMap = new RequestMap(url : "/user/fetchExistingUserDetails")
            //Deciding and finding role for the new user
            Role role = Role.findByAuthority("ROLE_COMMON")
            //Assigning role to newly created user
            println "fetching role for new user 1: "+role

            requestMap.addToRoles(role)

//            println "fetching role for new user 2:"+requestMap

            requestMap.save()
            println "role added to the new user"
            return true
        }catch (Exception e){
            println e.printStackTrace()
            return  false
        }

    }
}
