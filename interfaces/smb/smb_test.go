package smb

import (
	"fmt"
	"testing"
)

func TestSmbAuthValid(t *testing.T) {

	fmt.Printf("[+] SmbAuth(domain,user, password, dc): \n")
	_, err := SmbAuth(
		"testad.net",                     // Domain
		"administrator",                  // Username
		"Pleasechangemefortheloveofgod!", // Password
		"192.168.146.147",                // DC ADDR
	)

	if err != nil {
		t.Fatalf(err.Error())
	}

}
