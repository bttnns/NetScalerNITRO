nsAuto
======
This script is used to take a brand new NetScaler and apply a base configuration.  All that needs to be done on the NetScaler is configure the NSIP/Netmask/Gateway.  Once that is done, you can run the script to configure the NetScaler.

You use the nsAutoCfg.json file to specify the configuration.  Check out the file for what all you can do to configure the NetScaler.  A high level overview of this configuration file is below.

Requirements
-----
NetScaler(s) 10.1 or up

The NetScaler Python SDK, can download from a NetScaler 10.5 or up

Python module requirments: paramiko, requests (Install both via "pip install MODULENAME")

Running
-----
Run from the Nitro SDK root or install the Nitro SDK (installation instructions in the SDK)

In the same directory you need your license file and the config.json referenced below.



Run Script via:

python nsAuto.py




nsAutoCfg.json
-----
```
ns # This node is an array of netscalers to config, you specify multiple here.  In my example file I have two. 192.168.1.50 and 192.168.1.60

  config # the config node is an item that is used to specify the configuration, most of these are required

    nsip

    username

    password

    hostname

    ips # This node is a way to add SNIPs/MIPs/ect... Any type of NetScaler IP types can go here (I only have one, but you 
    can specify multiple)
    
      ip
    
      netmask
    
      type # SNIP/MIP/ECT...
    
      mgmt # True or False, enables all of the managment nodes or not
    
    dns # This node specifies DNS for the NetScaler, can specify multiple nameservers
    
      nameserver # IP address for your nameserver

    tz # Timezone (Same timezone you see in the dropdown, I use New York (Eastern Time))

    localLicFileLoc # Specify where your license file is on your machine running the script

    features # Enable or disable multiple features here

      feature # Use the same CLI names (lb, cs, ssl, ect...)

      enable # true to enable, false to disable

    modes # Enable or disable multiple modes here

      mode # Use the same CLI names (l2, l3, usnip, ect...)

      enable # true or false

    services # Specify services to add here, takes multiple.

      port

      name

      ip

      type # Use CLI name: (http, ssl, dns, ect...)

    lbvs # Specify lbvservers to add here, takes multiple

      name

      servicetype # CLI Name: (http, ssl, ect)

      ipv46 # VIP IP, v4 or v6

      port

      presistance type

      lbmethod

      services # Add services to bind here

        servicename # Matches the service name above

        weight

hanode # Specify all your HA Nodes here.  Note this is a new node from ns at the top

  nsip

  username

  password

  id # HA ID

  mode # primary or secondary * If you specify primary, when configuring we will set the others a STAYSECONDARY for the initial configuration to ensure configuration stays with the primary
  
  hastatus # Specify the final hastatus: ENABLED, STAYPRIMARY, STAYSECONDARY, ect...
  
  primary # Specify the primary HA Node for this netscaler here, if you are the primary then specify your own IP
```
