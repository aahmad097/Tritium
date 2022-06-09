package spray

type cred struct {
	username string
	domain   string
	password string
	target   string
}

func SprayMgr(users []cred, auth int) {

	switch auth {
	case 0:
		sprayKerb(users)
	case 1:
		sprayLdap(users)
	case 2:
		spraySMB(users)
	}

}

func spraySMB(users []cred) {
	for i := 0; i < len(users); i++ {

	}
}

func sprayLdap(users []cred) {
	for i := 0; i < len(users); i++ {

	}

}

func sprayKerb(users []cred) {
	for i := 0; i < len(users); i++ {

	}
}
