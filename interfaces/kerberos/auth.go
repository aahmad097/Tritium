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

func KerbAuth(domain string, username string, password string, dc string) ([]string, error) {

	ret := []string{domain, username, password, dc} // used for response handling
	var kerr error

	kcfg_str := fmt.Sprintf(KERB_FMT_STRING, domain, dc)
	cfg, err := kconfig.NewConfigFromString(kcfg_str)

	cl := kclient.NewClientWithPassword(username, domain, password, cfg, kclient.DisablePAFXFAST(true))
	err = cl.Login()
	if err != nil {
		if strings.Contains(err.Error(), "Networking_Error: AS Exchange Error") {
			kerr = fmt.Errorf("[Kerberos] FATAL: Networking Error - Cannot contact KDC")
			goto End
		} else if strings.Contains(err.Error(), "KRB_AP_ERR_SKEW") {
			kerr = fmt.Errorf("[Kerberos] FATAL: Time delta between server and client too large")
			goto End
		} else if strings.Contains(err.Error(), "KRB5_REALM_UNKNOWN") {
			kerr = fmt.Errorf("[Kerberos] FATAL: find KDC for requested realm")
			goto End
		} else if strings.Contains(err.Error(), "KRB5_KDC_UNREACH") {
			kerr = fmt.Errorf("[Kerberos] FATAL: Cannot contact any KDC for requested realm")
			goto End
		} else if strings.Contains(err.Error(), "client does not have a username") {
			kerr = fmt.Errorf("[Kerberos] Error: Blank Username")
			goto End
		} else if strings.Contains(err.Error(), "KDC_ERR_CLIENT_REVOKED") {
			ret = append(ret, "[Kerberos] User Locked Out")
			goto End
		} else if strings.Contains(err.Error(), "KDC_ERR_PREAUTH_FAILED") {
			ret = append(ret, "[Kerberos] Valid User But Invalid Password")
			goto End
		} else if strings.Contains(err.Error(), "KDC_ERR_C_PRINCIPAL_UNKNOWN") {
			ret = append(ret, "[Kerberos] User doesn't Exist")
			goto End
		} else {
			ret = append(ret, "[Kerberos] Valid Login!")
			goto End
		}
	}

End:
	return ret, kerr
}
