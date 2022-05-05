package smb

import (
	"fmt"
	"net"
	"strings"

	smb2 "github.com/hirochachacha/go-smb2"
)

func SmbAuth(domain string, username string, password string, host string) ([]string, error) {

	data := []string{domain, username, password, host} // used for response handling
	var serr error

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   domain,
		},
	}
	conn, err := net.Dial("tcp", string(host+":445"))
	if err != nil {
		serr = fmt.Errorf("[SMB] FATAL: Error Dialing SMB Server")
		goto End
	} else {
		c, err := d.Dial(conn)
		if err != nil {

			if strings.Contains(err.Error(), " bad username or authentication information") {
				data = append(data, "[SMB] Invalid Username Or Password")
			} else {
				serr = fmt.Errorf("[SMB] Error Dialing Host: " + serr.Error())
			}
			goto End
		}
		data = append(data, "[SMB] Valid Login!")
		c.Logoff()
		goto End
	}

End:
	return data, serr

}
