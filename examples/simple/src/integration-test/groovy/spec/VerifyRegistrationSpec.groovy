package spec

import grails.plugin.springsecurity.ui.RegistrationCode
import grails.plugins.rest.client.RestBuilder
import grails.plugins.rest.client.RestResponse
import grails.testing.mixin.integration.Integration
import spock.lang.Shared
import spock.lang.Specification
import test.User

@Integration
class VerifyRegistrationSpec extends Specification {

    @Shared RestBuilder rest = new RestBuilder()

    void "verify a call to the register/verifyRegistration endpoint properly updates the verified"() {
        given: "a username"
        String username = "username"

        when: "a user account is created and given a registration code"
        User user
        RegistrationCode registrationCode

        User.withNewTransaction {
            user = new User(username: username, password: "password", accountLocked: true).save()
            registrationCode = new RegistrationCode(username: username).save()
        }


        then: 'registration code token is populated'
        registrationCode.token
        user.accountLocked == true
        user.accountExpired == false
        user.enabled == true
        user.username == username

        when: "that user engages the verify registration action with their registration code's token"
        RestResponse resp = rest.get("http://localhost:${serverPort}/register/verifyRegistration?t=${registrationCode.token}")

        then: "that user account should be unlocked, not expired, and enabled"
        resp.status == 200

        when:
        User updatedUser = User.withNewTransaction(readOnly: true) {
            User.findByUsername(username)
        }

        then:
        updatedUser.username == username
        updatedUser.accountExpired == false
        updatedUser.enabled == true
        updatedUser.accountLocked == false

    }
}
