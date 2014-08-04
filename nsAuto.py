#!/usr/bin/env python

import base64
import paramiko
import os
import requests
import json
import time
import threading
from nssrc.com.citrix.netscaler.nitro.service.nitro_service import nitro_service
from nssrc.com.citrix.netscaler.nitro.exception.nitro_exception import nitro_exception
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nsip import nsip
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nshostname import nshostname
from nssrc.com.citrix.netscaler.nitro.resource.config.dns.dnsnameserver import dnsnameserver
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nsconfig import nsconfig
from nssrc.com.citrix.netscaler.nitro.resource.config.system.systemfile import systemfile
from nssrc.com.citrix.netscaler.nitro.resource.config.basic.service import service
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbvserver import lbvserver
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbvserver_service_binding import lbvserver_service_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.cs.csvserver import csvserver
from nssrc.com.citrix.netscaler.nitro.resource.config.ha.hanode import hanode


class netScaler:
    """This class reperesents a connection to a NetScaler using NITRO. Class
    Methods below provide functionality to interact with the NetScaler."""

    def __init__(self, conf):
        #initlization
        self.cfg = conf
        self.ns_session = ""

    def initConnection(self):
        """Create the NetScaler session using HTTP, passing in the credentials
        to the NSIP"""
        try:
            self.ns_session = nitro_service(self.cfg['config']['nsip'],
                                            "HTTP")

            self.ns_session.set_credential(self.cfg['config']['username'],
                                           self.cfg['config']['password'])
            self.ns_session.timeout = 300

            self.ns_session.login()

        except nitro_exception as e:
            print("Exception::errorcode=" +
                  str(e.errorcode) + ",message=" + e.message)
        except Exception as e:
            print("Exception::message=" + str(e.args))

        return

    def savec(self):
        """Simple class used to save the config of the NS"""
        try:
            self.ns_session.save_config()

        except nitro_exception as e:
            print("Exception::errorcode=" +
                  str(e.errorcode) + ",message=" + e.message)
        except Exception as e:
            print("Exception::message=" + str(e.args))

        return

    def closeConnection(self, savec=False):
        """Close the session.  Can pass in if you wish to save the config or
        not.  Defaults to not saving the config"""
        try:
            if savec:
                self.savec()

            self.ns_session.logout()

        except nitro_exception as e:
            print("Exception::errorcode=" +
                  str(e.errorcode) + ",message=" + e.message)
        except Exception as e:
            print("Exception::message=" + str(e.args))

        return

    def reboot(self, wait=False, savec=False):
        """Reboot the NetScaler.  Can pass in if you wish to save the config or
        not.  Defaults to not saving the config.  You can also choose to wait
        in this function until the netscaler is back up using wait, doing so
        will re-init the connection through nitro"""
        try:
            if savec:
                self.savec()

            self.ns_session.reboot(False)

        except nitro_exception as e:
            print("Exception::errorcode=" +
                  str(e.errorcode) + ",message=" + e.message)
        except Exception as e:
            print("Exception::message=" + str(e.args))

        if wait:
            # if we want to wait lets keep checking the nitro status page for a
            # 200 OK.  If we get the 200, lets reinit the connection and cont.
            while True:
                time.sleep(15)
                try:
                    r = requests.get("http://" + self.cfg['config']['nsip'] +
                                     "/nitro/v1/stat", timeout=15,
                                     auth=(self.cfg['config']['username'],
                                           self.cfg['config']['password']))
                    if r.status_code == 200:
                        # if were good to go, lets re-init that connection
                        self.initConnection()
                        break

                except requests.exceptions.Timeout as e:
                    print "TO::Waiting on", self.cfg['config']['hostname'], "to reboot..."
                except requests.exceptions.ConnectionError as e:
                    print "CE::Waiting on", self.cfg['config']['hostname'], "to reboot..."
        return

    def defineIPs(self):
        """Configure a SNIP on the given NetScaler.  Can pass in if you wish to
         enable management or not, will default to yet. Management enabling
         will turn on Telnet, SSH, GUI, FTP, and SNMP access."""
        for ip in self.cfg['config']['ips']:
            try:
                #Define the snip
                newSNIP = nsip()
                newSNIP.ipaddress = ip['ip']
                newSNIP.netmask = ip['netmask']
                newSNIP.type = ip['type']

                #enable management if necessary
                if ip['mgmt']:
                    newSNIP.mgmtaccess = "ENABLED"
                    newSNIP.telnet = "ENABLED"
                    newSNIP.ssh = "ENABLED"
                    newSNIP.gui = "ENABLED"
                    newSNIP.ftp = "ENABLED"
                    newSNIP.snmp = "ENABLED"

                nsip.add(self.ns_session, newSNIP)

            except nitro_exception as e:
                print("Exception::errorcode=" +
                      str(e.errorcode) + ",message=" + e.message)
            except Exception as e:
                print("Exception::message=" + str(e.args))

        return

    def hostNameDnsTz(self):
        """Configure the HostName, DNS, and Time Zone for the NetScaler."""
        # Begin by setting the hostname
        try:
            newNsHostname = nshostname()
            newNsHostname.hostname = self.cfg['config']['hostname']
            nshostname.update(self.ns_session, newNsHostname)

        except nitro_exception as e:
            print("Exception::errorcode=" +
                  str(e.errorcode) + ",message=" + e.message)
        except Exception as e:
            print("Exception::message=" + str(e.args))

        # Add DNS Entries, traverse the dns class variable and add the
        # nameservers
        for dns in self.cfg['config']['dns']:
            try:
                newDNS = dnsnameserver()
                newDNS.ip = dns['nameserver']
                dnsnameserver.add(self.ns_session, newDNS)

            except nitro_exception as e:
                print("Exception::errorcode=" +
                      str(e.errorcode) + ",message=" + e.message)
            except Exception as e:
                print("Exception::message=" + str(e.args))

        # Configure the NetScaler TimeZone
        try:
            nsconf = nsconfig()
            nsconf.timezone = self.cfg['config']['tz']
            nsconfig.update(self.ns_session, nsconf)

        except nitro_exception as e:
            print("Exception::errorcode=" +
                  str(e.errorcode) + ",message=" + e.message)
        except Exception as e:
            print("Exception::message=" + str(e.args))

        return

    def uploadLicense(self):
        """Upload the NetScaler License File"""
        try:
            """Frist lets upload the license file to /nsconfig/license
            We will use NITRO's system file to upload the lic as a txt
            This is due to nitro limitations, if those limitations are dropped
            We can just use a lic file instead. Due to the limitations
            We will upload using NITRO and rename using SFTP through the NSIP
            (We could just upload using SFTP, and it would be faster, but I
            want to show off how it would be accomplished using NITRO)"""

            # Setting up the upload
            sf = systemfile()
            # NITRO checks the incoming file extension,
            sf.filename = "platform.txt"
            #							 we use TXT as NITRO supports this
            sf.filelocation = "/nsconfig/license"
            sf.fileencoding = "BASE64"

            # Reading in the license file and encoding using base64 for NITRO
            fin = open(self.cfg['config']['localLicFileLoc'], "r")
            file_data = fin.read()
            fin.close()
            b64_data = base64.b64encode(file_data)

            # Setting the file content to the base64 data
            sf.filecontent = b64_data

            # Uploading the file
            systemfile.add(self.ns_session, sf)

        except nitro_exception as e:
            print("Exception::errorcode=" +
                  str(e.errorcode) + ",message=" + e.message)
        except Exception as e:
            print("Exception::message=" + str(e.args))

        try:
            # Now we have to rename the txt to lic. Going to use SFTP for this
            # setting up paramiko client
            transport = paramiko.Transport((self.cfg['config']['nsip'], 22))
            transport.connect(username=self.cfg['config']['username'],
                              password=self.cfg['config']['password'])
            sftp = paramiko.SFTPClient.from_transport(transport)

            oldLoc = sf.filelocation + "/" + sf.filename
            newLoc = sf.filelocation + "/" + \
                os.path.splitext(sf.filename)[0] + ".lic"
            sftp.rename(oldLoc, newLoc)

            """note: if we wanted to just use FTP we could remove the
            systemfile code above and use sftp.put(localpath,
            remotepath, callback=None, confirm=True) paramiko handles file
            reading and uploading, just call that line..."""

            # Closing SFTP connection
            sftp.close()
            transport.close()

        except Exception as e:
            print("Exception on lic rename::message=" + str(e.args))

        return

    def confFeatures(self):
        """Configure the features for the NetScaler"""
        en = []
        dis = []

        for feature in self.cfg['config']['features']:
            if feature['enable']:
                #If we hit a feature to enable, add it to the en list
                en.append(feature['feature'])
            else:
                #Add it to the dis list if we need to disable the feature
                dis.append(feature['feature'])
        try:
            if en:
                #Send all enable features at once
                self.ns_session.enable_features(en)
            if dis:
                #Send all disable features at once
                self.ns_session.disable_features(dis)

        except nitro_exception as e:
            print("Exception::errorcode=" +
                  str(e.errorcode) + ",message=" + e.message)
        except Exception as e:
            print("Exception::message=" + str(e.args))

        return

    def confModes(self):
        """Configure the modes for the NetScaler"""
        en = []
        dis = []

        for mode in self.cfg['config']['modes']:
            if mode['enable']:
                #If we need to enable modes, add it to the en list
                en.append(mode['mode'])
            else:
                #add it to the dis list...
                dis.append(mode['mode'])
        try:
            if en:
                #Send all at once
                self.ns_session.enable_modes(en)
            if dis:
                self.ns_session.disable_modes(dis)

        except nitro_exception as e:
            print("Exception::errorcode=" +
                  str(e.errorcode) + ",message=" + e.message)
        except Exception as e:
            print("Exception::message=" + str(e.args))

        return

    def addServices(self):
        """Configure the services for the NetScaler"""
        if "services" in self.cfg.keys():
            #Lets loop through all the services
            for svc in self.cfg['services']:
                try:
                    #Setup the new service
                    newSVC = service()
                    newSVC.name = svc['name']
                    newSVC.ip = svc['ip']
                    newSVC.port = svc['port']
                    newSVC.servicetype = svc['type']

                    #Add the new service
                    service.add(self.ns_session, newSVC)

                except nitro_exception as e:
                    print("Exception::errorcode=" +
                          str(e.errorcode) + ",message=" + e.message)
                except Exception as e:
                    print("Exception::message=" + str(e.args))

        return

    def addLBVServers(self):
        """Configure the lbvservers for the NetScaler"""
        if "lbvs" in self.cfg.keys():
            #Lets loop through all lbvservers
            for lbvs in self.cfg['lbvs']:
                try:
                    #Setup a new lbvserver
                    newLBVS = lbvserver()
                    newLBVS.name = lbvs['name']
                    newLBVS.servicetype = lbvs['servicetype']
                    newLBVS.ipv46 = lbvs['ipv46']

                    #check these optional values
                    if "port" in lbvs.keys():
                        newLBVS.port = lbvs['port']
                    if "persistencetype" in lbvs.keys():
                        newLBVS.persistencetype = lbvs['persistencetype']
                    if "lbmethod" in lbvs.keys():
                        newLBVS.lbmethod = lbvs['lbmethod']

                    #Add the lbvs
                    response = lbvserver.add(self.ns_session, newLBVS)
                    if response.severity and response.severity == "WARNING":
                        print("\tWarning : " + response.message)

                except nitro_exception as e:
                    print("Exception::errorcode=" +
                          str(e.errorcode) + ",message=" + e.message)
                except Exception as e:
                    print("Exception::message=" + str(e.args))

                #If we have services to bind, lets do it.
                if "services" in lbvs.keys():
                    for svc in lbvs['services']:
                        #Create a new binding
                        newSVCBinding = lbvserver_service_binding()
                        newSVCBinding.name = lbvs['name']
                        newSVCBinding.servicename = svc['servicename']
                        newSVCBinding.weight = svc['weight']

                        #Add the binding!
                        try:
                            lbvserver_service_binding.add(self.ns_session,
                                                          newSVCBinding)
                        except nitro_exception as e:
                            print("Exception::errorcode=" +
                                  str(e.errorcode) + ",message=" + e.message)
                        except Exception as e:
                            print("Exception::message=" + str(e.args))
        return


def confNS(ns):
    """ This is used to preform the basic configuration of the NetScaler being
    passed in to the function"""
    # Lets get the initial config done and license the box
    ns.initConnection()
    ns.defineIPs()
    ns.hostNameDnsTz()
    ns.uploadLicense()
    ns.reboot(True, True)

    # After a reboot lets configure modes and features
    ns.confFeatures()
    ns.confModes()

    # Next lets add services and configure VServers
    ns.addServices()
    ns.addLBVServers()

    # Were done here, lets save and close the connection
    ns.savec()
    ns.closeConnection()


def confHA(hanod, jsn):
    # Configure a NetScaler connection and initiate
    ns = netScaler({"config": hanod})
    ns.initConnection()

    if hanod['mode'] == "primary":
        # If we are primary, update primary, add ALL secondaries
        newHA = hanode()
        newHA.hastatus = "STAYPRIMARY"

        try:
            hanode.update(ns.ns_session, newHA)
        except nitro_exception as e:
            print("Exception::errorcode=" + str(e.errorcode) + ",message=" +
                  e.message)
        except Exception as e:
            print("Exception::message=" + str(e.args))

        # Now we need to add all secondaries
        for secHANode in jsn['hanode']:
            # Check that the secondary is not the primary and the secondary's
            # Primary field matches our primary nsip
            if hanod['nsip'] != secHANode['nsip'] and hanod['nsip'] == secHANode['primary']:
                newHA = hanode()
                newHA.id = secHANode['id']
                newHA.ipaddress = secHANode['nsip']

                try:
                    hanode.add(ns.ns_session, newHA)
                except nitro_exception as e:
                    print("Exception::errorcode=" + str(e.errorcode) +
                          ",message=" + e.message)
                except Exception as e:
                    print("Exception::message=" + str(e.args))
    else:
        # Were secondary, update secondary, add primary
        newHA = hanode()
        newHA.hastatus = "STAYSECONDARY"

        try:
            hanode.update(ns.ns_session, newHA)
        except nitro_exception as e:
            print("Exception::errorcode=" + str(e.errorcode) +
                  ",message=" + e.message)
        except Exception as e:
            print("Exception::message=" + str(e.args))

        newHA = hanode()
        newHA.ipaddress = hanod['primary']
        newHA.id = hanod['id']

        try:
            newHA.add(ns.ns_session, newHA)
        except nitro_exception as e:
            print("Exception::errorcode=" + str(e.errorcode) +
                  ",message=" + e.message)
        except Exception as e:
            print("Exception::message=" + str(e.args))

    ns.savec()
    ns.closeConnection()


if __name__ == '__main__':
    """ This is our main thread of execution, it starts all the work!"""
    # read in cnfig http://www.objgen.com/json/models/mdui
    fin = open("nsAutoCfg.json", "r")
    json_raw = fin.read()
    fin.close()
    jsn = json.loads(json_raw)

    # Create some threads and netscalers
    threads = []

    for nscfg in jsn['ns']:
        print("Configuring NS " + nscfg['config']['hostname'])
        ns = netScaler(nscfg)

        # Create a thread object and add it to our list of threads
        t = threading.Thread(target=confNS, args=(ns,))
        t.daemon = True
        threads.append(t)

    print "Starting to configure..."

    # Lets start the threads -- If there are many NetScalers, we might want to
    # Slow this part down, rather than run them all at once...
    [x.start() for x in threads]

    # Lets wait for them to finish
    [x.join() for x in threads]

    print "All done preforming configuration"

    # Check if we need to configure HA and go for it...
    if "hanode" in jsn:
        print "Configuring HA"

        # Lets clear out our previous threads that already ran...
        del threads[:]

        # Find the primary node
        for hanod in jsn['hanode']:
            t = threading.Thread(target=confHA, args=(hanod, jsn))
            t.daemon = True
            threads.append(t)

        # Lets start the threads -- If there are many NetScalers, we might
        # want to slow this part down, rather than run them all at once...
        [x.start() for x in threads]

        # Lets wait for them to finish
        [x.join() for x in threads]

        # Now lets go through and set the actual HAStatus...
        # Since Nitro has no sync state, lets wait a quarter minute to allow
        # Sync across to initiate
        time.sleep(15)

        for hanod in jsn['hanode']:
            ns = netScaler({"config": hanod})
            ns.initConnection()

            newHA = hanode()
            newHA.hastatus = hanod['hastatus']

            try:
                hanode.update(ns.ns_session, newHA)
            except nitro_exception as e:
                print("Exception::errorcode=" + str(e.errorcode) +
                      ",message=" + e.message)
            except Exception as e:
                print("Exception::message=" + str(e.args))

            ns.closeConnection()


"""
- create connection into NS
- creating first snip
- hostname
- dns
- TZ
- licensing
- reboot
- HA pair
- LB Vserver
* Content switching example
* SSL
* enabling basic AppFW?
"""
