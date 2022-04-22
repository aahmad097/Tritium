package kerberos

import (
	"fmt"
	"testing"
)

func TestKerbAuthValid(t *testing.T) {

	fmt.Printf("[+] KerbAuth(domain,user, password, dc): \n")
	_, resp, autherr := KerbAuth(
		"", // Domain
		"", // Username
		"", // Password
		"", // DC ADDR
	)

	if autherr != false {
		t.Fatalf("KerbAuth() error: %s\n ", resp)
	}

}
