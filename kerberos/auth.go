package kerberos

import (
	"fmt"
	"strings"

	kclient "gopkg.in/jcmturner/gokrb5.v7/client"
	kconfig "gopkg.in/jcmturner/gokrb5.v7/config"
)

const (
	KERB_FMT_STRING = `[libdefaults]
	default_realm = ${REALM}
	dns_lookup_realm = false
	dns_lookup_kdc = true
	[realms]
	%s = {
		kdc = %s
	}`
)

func KerbAuth(domain string, username string, password string, dc string) ([]string, string, bool) {

	data := []string{domain, username, password, dc} // used for response handling
	resp := ""                                       // used for response tracking
	kerr := false                                    // used for error tracking

	kcfg_str := fmt.Sprintf(KERB_FMT_STRING, domain, dc)
	cfg, err := kconfig.NewConfigFromString(kcfg_str)

	cl := kclient.NewClientWithPassword(username, domain, password, cfg, kclient.DisablePAFXFAST(true))
	err = cl.Login()
	if err != nil {
		if strings.Contains(err.Error(), "Networking_Error: AS Exchange Error") {
			resp = "[FATAL: Networking Error - Cannot contact KDC]"
			kerr = true
			goto End
		} else if strings.Contains(err.Error(), "KRB_AP_ERR_SKEW") {
			resp = "[FATAL: Time delta between server and client too large]"
			kerr = true
			goto End
		} else if strings.Contains(err.Error(), "KRB5_REALM_UNKNOWN") {
			resp = "[FATAL: find KDC for requested realm]"
			kerr = true
			goto End
		} else if strings.Contains(err.Error(), "KRB5_KDC_UNREACH") {
			resp = "[FATAL: Cannot contact any KDC for requested realm]"
			kerr = true
			goto End
		} else if strings.Contains(err.Error(), "client does not have a username") {
			resp = "[Error: Blank Username]"
			kerr = true
			goto End
		} else if strings.Contains(err.Error(), "KDC_ERR_CLIENT_REVOKED") {
			resp = "[USER ACCOUNT LOCKED]"
		} else if strings.Contains(err.Error(), "KDC_ERR_PREAUTH_FAILED") {
			resp = "[Valid User But Invalid Password]"
		} else if strings.Contains(err.Error(), "KDC_ERR_C_PRINCIPAL_UNKNOWN") {
			resp = "[USER DOESN'T EXIST]"
		} else {
			resp = "[VALID LOGIN!]"
		}
	}

End:
	return data, resp, kerr
}
