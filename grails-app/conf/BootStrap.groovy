import com.auth.Role
import com.auth.User
import com.auth.UserRole

class BootStrap {

    def init = { servletContext ->
// adding new Users
        User admin = new User(username:'admin', password:'secret', enabled:true).save(flush: true, failOnError: true)

// adding new Roles
        Role adminRole = new Role(authority: 'ROLE_ADMIN').save(flush: true, failOnError: true)

// Assigning existing role to existing user
        new UserRole(user: admin, role: adminRole).save(flush: true, failOnError: true)

//Assigning roles dynamically to the action

    }
    def destroy = {
    }
}
