package kerberos

import (
	"fmt"
	"testing"
)

func TestKerbAuthValid(t *testing.T) {

	fmt.Printf("[+] KerbAuth(user, domain, password, dc): \n")
	_, resp, autherr := KerbAuth(
		"", // Username
		"", // Domain
		"", // Password
		"", // DC ADDR
	)

	if autherr != false {
		t.Fatalf("KerbAuth() error: %s\n ", resp)
	}

}
