package smb

import (
	"net"
	"strings"

	smb2 "github.com/hirochachacha/go-smb2"
)

func SmbAuth(domain string, username string, password string, host string) ([]string, string, bool) {

	data := []string{domain, username, password, host} // used for response handling
	resp := ""                                         // used for response tracking
	serr := false                                      // used for error tracking

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   domain,
		},
	}
	conn, err := net.Dial("tcp", string(host+":445"))
	if err != nil {
		resp = "[SMB] FATAL: Error Dialing SMB Server"
		serr = true
		goto End
	} else {
		c, err := d.Dial(conn)
		if err != nil {
			resp = err.Error()

			if strings.Contains(resp, " bad username or authentication information") {
				resp = "[SMB] Invalid Username Or Password"
			} else {
				serr = true
			}
			goto End
		}
		resp = "[SMB] Valid Login!"
		c.Logoff()
	}

End:
	return data, resp, serr

}
