package ldap

import (
	"fmt"
	"strings"

	lclient "gopkg.in/ldap.v2"
)

func LdapAuth(domain, username, password, dc string) ([]string, string, bool) {

	input := []string{domain, username, password, dc} // used for response handling
	lresp := ""                                       // used for response tracking
	lerr := false                                     // used for error tracking

	conn, err := lclient.Dial(
		"tcp",
		fmt.Sprintf("%s:%d", dc, 389),
	)
	if err != nil { // error dialing ldap server
		lresp = "[LDAP] Error Dialing Ldap Server"
		lerr = true
		goto End
	}

	err = conn.Bind(
		string(username+"@"+domain),
		password,
	)
	if err != nil {
		lresp = err.Error()
		if strings.Contains(lresp, "Invalid Credentials") {
			lresp = "[LDAP]: Invalid Username Or Password"
			goto End
		}
		lerr = true
		goto End
	}
	lresp = "[LDAP]: Valid Login!"

End:
	return input, lresp, lerr

}
