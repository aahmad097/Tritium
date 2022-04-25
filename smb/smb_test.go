package smb

import (
	"fmt"
	"testing"
)

func TestSmbAuthValid(t *testing.T) {

	fmt.Printf("[+] SmbAuth(domain,user, password, dc): \n")
	_, resp, autherr := SmbAuth(
		"testad.net",                     // Domain
		"administrator",                  // Username
		"Pleasechangemefortheloveofgod!", // Password
		"192.168.146.143",                // DC ADDR
	)

	if autherr != false {
		t.Fatalf("SmbAuth() error: %s\n ", resp)
	}

}
