# Tritium

A tool to enumerate and spray valid Active Directory accounts through Kerberos Pre-Authentication.

## Background

Although many Kerberos password spraying tools currently exist on the market, I found it difficult to find tools with the following built-in functionality: 

* The ability to prevent users from locking out the domain
* The ability to integrate username enumeration with the password spraying process (User enumeration is a seperate functionality from the spray)
* The ability to recursively spray passwords rather than running one spray at a time 
* The ability to resume password sprays and ignore previously compromised accounts 

Tritium solves all of the issues mentioned above and more. User enumeration will no longer waste a login attempt because it uses the output of the first spray to generate a file of valid users. Tritium also gives the user the ability to pass it a password file to recursively spray passwords. And Finally, Tritium has built in functionality to detect if a domain is being locked out due to password spraying by saving the state and quitting the password spray if 3 consecutive accounts are locked out. 

## Usage

```
 ./Tritium -h

        ___________      .__  __  .__               
        \__    ___/______|__|/  |_|__|__ __  _____  
          |    |  \_  __ \  \   __\  |  |  \/     \ 
          |    |   |  | \/  ||  | |  |  |  /  Y Y  \
          |____|   |__|  |__||__| |__|____/|__|_|__/ v 0.4
                                                                                          

          Author: S4R1N, alfarom256
 


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
```

## Under Development 

Below are some of the features being developed: 

* Ability to capture ^C and save state if process was killed manually


