package kerberos

import (
	"fmt"
	"testing"
)

func TestKerbAuthValid(t *testing.T) {

	fmt.Printf("[+] KerbAuth(domain,user, password, dc): \n")
	_, err := KerbAuth(
		"testad.net",                     // Domain
		"administrator",                  // Username
		"Pleasechangemefortheloveofgod!", // Password
		"192.168.146.147",                // DC ADDR
	)

	if err != nil {
		t.Fatalf(err.Error())
	}

}
