package ldap

import (
	"fmt"
	"testing"
)

func TestLdapAuthValid(t *testing.T) {

	fmt.Printf("[+] LdapAuth(domain,user, password, dc): \n")
	_, err := LdapAuth(
		"testad.net",                     // Domain
		"administrator",                  // Username
		"Pleasechangemefortheloveofgod!", // Password
		"192.168.146.147",                // DC ADDR
	)

	if err != nil {
		t.Fatalf(err.Error())
	}

}
