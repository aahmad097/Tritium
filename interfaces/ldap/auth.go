package ldap

import (
	"fmt"
	"strings"

	lclient "gopkg.in/ldap.v2"
)

func LdapAuth(domain, username, password, dc string) ([]string, error) {

	ret := []string{domain, username, password, dc} // used for response handling
	var lerr error

	conn, err := lclient.Dial(
		"tcp",
		fmt.Sprintf("%s:%d", dc, 389),
	)
	if err != nil { // error dialing ldap server
		lerr = fmt.Errorf(string("[LDAP] FATAL: Error Dialing Ldap Server: " + err.Error()))
		goto End
	}

	err = conn.Bind(
		string(username+"@"+domain),
		password,
	)
	if err != nil {
		if strings.Contains(err.Error(), "Invalid Credentials") {
			ret = append(ret, "[LDAP]: Invalid Username Or Password")
			goto End
		}
		lerr = fmt.Errorf(string("[LDAP] FATAL: Error Binding to Host: " + err.Error()))
		goto End
	} else {
		ret = append(ret, "[LDAP]: Valid Login!")
		goto End
	}

End:
	return ret, lerr

}
