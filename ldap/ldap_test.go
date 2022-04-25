package ldap

import (
	"fmt"
	"testing"
)

func TestLdapAuthValid(t *testing.T) {

	fmt.Printf("[+] LdapAuth(domain,user, password, dc): \n")
	_, resp, autherr := LdapAuth(
		"testad.net",                      // Domain
		"administrator",                   // Username
		"Pleasechangemefortheloveofgod!!", // Password
		"192.168.146.143",                 // DC ADDR
	)

	if autherr != false {
		t.Fatalf("LdapAuth() error: %s\n ", resp)
	}

}
