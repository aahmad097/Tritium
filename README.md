你好！
很冒昧用这样的方式来和你沟通，如有打扰请忽略我的提交哈。我是光年实验室（gnlab.com）的HR，在招Golang开发工程师，我们是一个技术型团队，技术氛围非常好。全职和兼职都可以，不过最好是全职，工作地点杭州。
我们公司是做流量增长的，Golang负责开发SAAS平台的应用，我们做的很多应用是全新的，工作非常有挑战也很有意思，是国内很多大厂的顾问。
如果有兴趣的话加我微信：13515810775  ，也可以访问 https://gnlab.com/，联系客服转发给HR。
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
* Other stuff ;)


