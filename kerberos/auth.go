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

func KerbAuth(username string, domain string, password string, dc string) ([]string, string, bool) {

	resp := ""
	autherr := false
	data := []string{domain, username, password, dc}

	kcfg_str := fmt.Sprintf(KERB_FMT_STRING, domain, dc)
	cfg, err := kconfig.NewConfigFromString(kcfg_str)

	cl := kclient.NewClientWithPassword(username, domain, password, cfg, kclient.DisablePAFXFAST(true))
	err = cl.Login()

	if err != nil {
		if strings.Contains(err.Error(), "Networking_Error: AS Exchange Error") {
			resp = "[FATAL: Networking Error - Cannot contact KDC]"
			autherr = true
		} else if strings.Contains(err.Error(), "KRB_AP_ERR_SKEW") {
			resp = "[FATAL: Time delta between server and client too large]"
			autherr = true
		} else if strings.Contains(err.Error(), "KRB5_REALM_UNKNOWN") {
			resp = "[FATAL: find KDC for requested realm]"
			autherr = true
		} else if strings.Contains(err.Error(), "KRB5_KDC_UNREACH") {
			resp = "[FATAL: Cannot contact any KDC for requested realm]"
			autherr = true
		} else if strings.Contains(err.Error(), "client does not have a username") {
			resp = "[Error: Blank Username]"
			autherr = true
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

	return data, resp, autherr
}
