package ldap

import (
	"fmt"

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
		lresp = err.Error()
		lerr = true
		goto End
	}

	err = conn.Bind(
		string(username+"@"+domain),
		password,
	)
	if err != nil {
		lresp = err.Error()
		lerr = true
		goto End
	}
	lresp = "[VALID LOGIN!]"

End:
	return input, lresp, lerr

}
