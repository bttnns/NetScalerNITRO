#!/usr/bin/env python
# -*- coding: latin-1 -*-

# CTX139319 Wizard Script
# Requires NetScaler build 10.1 or newer with Gateway license
# Requires existing Gateway VServer and SSL certificate chain configured and bound
# Requires NetScaler to be able to resolve DNS queries for AC and SF resources
# Requires SF and AC FQDNs to be added to clientless domains under global settings
# Requries LDAP authentication on Gateway Virtual Server

# TODO - Session Profiles for Clientless Web access from Windows



import sys

from nssrc.com.citrix.netscaler.nitro.exception.nitro_exception import nitro_exception
from nssrc.com.citrix.netscaler.nitro.service.nitro_service import nitro_service

from nssrc.com.citrix.netscaler.nitro.resource.config.policy.policypatset import policypatset
from nssrc.com.citrix.netscaler.nitro.resource.config.policy.policypatset_pattern_binding import policypatset_pattern_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.policy.policypatset_binding import policypatset_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.vpn.vpnclientlessaccesspolicy import vpnclientlessaccesspolicy
from nssrc.com.citrix.netscaler.nitro.resource.config.vpn.vpnclientlessaccesspolicy_binding import vpnclientlessaccesspolicy_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.vpn.vpnclientlessaccessprofile import vpnclientlessaccessprofile
from nssrc.com.citrix.netscaler.nitro.resource.config.vpn.vpnsessionaction import vpnsessionaction
from nssrc.com.citrix.netscaler.nitro.resource.config.vpn.vpnsessionpolicy import vpnsessionpolicy
from nssrc.com.citrix.netscaler.nitro.resource.config.vpn.vpnvserver import vpnvserver
from nssrc.com.citrix.netscaler.nitro.resource.config.vpn.vpnvserver_appcontroller_binding import vpnvserver_appcontroller_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.vpn.vpnvserver_authenticationldappolicy_binding import vpnvserver_authenticationldappolicy_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.vpn.vpnvserver_binding import vpnvserver_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.vpn.vpnvserver_staserver_binding import vpnvserver_staserver_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.vpn.vpnvserver_vpnclientlessaccesspolicy_binding import vpnvserver_vpnclientlessaccesspolicy_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.vpn.vpnvserver_vpnclientlessaccesspolicy_binding import vpnvserver_vpnclientlessaccesspolicy_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.vpn.vpnvserver_vpnsessionpolicy_binding import vpnvserver_vpnsessionpolicy_binding



class set_config :
    def __init__(self):
        _ip=""
        _username=""
        _password=""

    @staticmethod
    def main(cls, args_):
        
        
        debug = False

        print '\n'
        print "*************************************"
        print "*** CTX139319 Implementation Script *"
        print "*************************************"
        print '\n'

        config = set_config()
        config.ip = raw_input('What is the NSIP? (e.g. 192.168.100.1):  ')
        
        # Assume a default value when pressing Enter
        if config.ip == '':
            config.ip = '172.16.231.10'
        config.username = raw_input('NetScaler Username:  ')
        if config.username == '':
            config.username = 'nsroot'
        config.password = raw_input('NetScaler Password:  ')
        if config.password == '':
            config.password = 'nsroot'
        
        try:
            client = nitro_service(config.ip,"http")
            client.set_credential(config.username,config.password)
            client.timeout = 900

            mySSODomain = raw_input('What is the NT/AD Domain for Single Sign On to Citrix components?   ')
            if mySSODomain == '':
                mySSODomain = 'demo.lab'
            myAppCURL = raw_input('What is the URL for the AppController? (e.g. https://ac.domain.com)  ')
            if myAppCURL == '':
                myAppCURL = 'https://ac.demo.lab'
            myStoreFrontURL = raw_input('What is the base URL for StoreFront? (e.g. https://storefront.domain.com)   ')
            if myStoreFrontURL == '':
                myStoreFrontURL = 'https://sf.demo.lab'
            myReceiverWebPath = raw_input('What is the path to Receiver Web on ' + myStoreFrontURL + '? (e.g. /Citrix/StoreWeb)   ')
            if myReceiverWebPath == '':
                myReceiverWebPath = '/Citrix/StoreWeb'

            if debug:
                print 'SSO Domain %s', mySSODomain
                print 'APP Cntrol %s', myAppCURL
                print 'Storefront %s', myStoreFrontURL
                print 'Rcvr Web   %s', myReceiverWebPath

            #worker(client,myGateway, myAppCURL)
            
            
            if debug:
                print '\n*** Gateway Selection ***\n'

            myGateway = gatewaySelection(client,debug)
            if debug:
                print '\n*** Gateway Selection ***\n'
            else:     
                print 'Gateway: %s\n' % myGateway

            clientlessAccessPoliciesReceiver(client, myGateway, debug)
            if debug:
                print '\n*** Receiver Web Clientless Configuration ***\n'
            else:
                print '         \--- Receiver Clientless'

            clientlessAccessPoliciesReceiverWeb(client,myGateway, debug)
            if debug:
                print '\n*** Session Configuration for WorxHome ***\n'
            else:
                print '         \--- Receiver Web Clientless'

            sessionWorxHome(client,myGateway,mySSODomain,myAppCURL, debug)
            if debug:
                print '\n*** Session Configuration for Receiver ***\n'
            else:
                print '         \--- WorxHome Session'
            
            sessionReceiverWindows(client, myGateway, mySSODomain, myStoreFrontURL, myAppCURL, debug)
            if debug:
                print '\n*** Session Configuration for Web ***\n'
            else:
                print '         \--- Receiver Windows Session'

            sessionWeb(client,myGateway,mySSODomain,myStoreFrontURL+myReceiverWebPath, myAppCURL, debug)
            if debug:
                print '\n*** Session Web Configuration for Web ***\n'
            else:
                print '         \--- Mobile Web Session'

            sessionInternalWeb(client,myGateway,mySSODomain,myStoreFrontURL+myReceiverWebPath, debug)
            if debug:
                print '\n*** Session PC Configuration for Web ***\n'
            else:
                print '         \--- PC Web Session'

            staBinding(client,myGateway,myAppCURL,debug)
            if debug:
                print '\n*** AppController added to STA binding ***\n'
            else:
                print '         \--- AC STA'
            
            client.logout()
            if debug:
                print '\n*** Logging off ***\n'                        
        
        except nitro_exception as e:  # Error Handling
            print("Exception::errorcode=" +
                  str(e.errorcode) + ",message=" + e.message)
        except Exception as e:
            print("Exception::message=" + str(e.args))
        return

def worker(client, myGateway, myAppCURL):
    try:
        print ''
        
    except nitro_exception as e:  # Error Handling
        print("Exception::errorcode=" +
              str(e.errorcode) + ",message=" + e.message)
    except Exception as e:
        print("Exception::message=" + str(e.args))
    return

def staBinding(client,myGateway,myAppCURL,debug):
    try:
        
        mySTAServer = vpnvserver_staserver_binding()
        mySTAServer.name = myGateway
        mySTAServer.staserver = myAppCURL
        vpnvserver_staserver_binding.add(client,mySTAServer)

    except nitro_exception as e:  # Error Handling
        print("Exception::errorcode=" +
              str(e.errorcode) + ",message=" + e.message)
    except Exception as e:
        print("Exception::message=" + str(e.args))
    return

def sessionInternalWeb(client, myGateway, mySSODomain, sfURL, debug):
    try:

        mySessionAction = vpnsessionaction()
        mySessionAction.name = 'internalSites_act'
        mySessionAction.homepage = sfURL
        mySessionAction.splittunnel = 'ON'
        mySessionAction.clientlessvpnmode = 'ON'
        mySessionAction.clientlessmodeurlencoding = 'TRANSPARENT'
        mySessionAction.sso = 'ON'
        mySessionAction.defaultauthorizationaction = 'ALLOW'
        mySessionAction.icaproxy = 'OFF'
        mySessionAction.ntdomain = mySSODomain
        mySessionAction.securebrowse = 'ENABLED'
        mySessionAction.wihome = mySessionAction.homepage
        vpnsessionaction.add(client,mySessionAction)
        if debug:
            print 'VPN Session Action for PC Web created\n'
         
        mySessionPolicy = vpnsessionpolicy
        mySessionPolicy.name = 'internalSites_pol'
        mySessionPolicy.action = mySessionAction.name
        mySessionPolicy.rule = '''REQ.HTTP.HEADER User-Agent NOTCONTAINS CitrixReceiver && REQ.HTTP.HEADER Referer NOTEXISTS'''
        vpnsessionpolicy.add(client,mySessionPolicy)
        if debug:
            print 'VPN Session Policy for PC Web created\n'

        myPolicyBinding = vpnvserver_vpnsessionpolicy_binding()
        myPolicyBinding.name = myGateway
        myPolicyBinding.priority = 140
        myPolicyBinding.policy = mySessionPolicy.name
        vpnvserver_vpnsessionpolicy_binding.add(client,myPolicyBinding)
        if debug:
            print 'VPN Session Policy is bound to Gateway Virtual Server\n'
        
    except nitro_exception as e:  # Error Handling
        print("Exception::errorcode=" +
              str(e.errorcode) + ",message=" + e.message)
    except Exception as e:
        print("Exception::message=" + str(e.args))
    return

def sessionWeb(client, myGateway, mySSODomain, sfURL, myAppCURL, debug):
    try:

        mySessionAction = vpnsessionaction()
        mySessionAction.name = 'webBrowser_act'
        mySessionAction.homepage = sfURL
        mySessionAction.clientlessvpnmode = 'ON'
        mySessionAction.clientlessmodeurlencoding = 'TRANSPARENT'
        mySessionAction.sso = 'ON'
        mySessionAction.defaultauthorizationaction = 'ALLOW'
        mySessionAction.icaproxy = 'OFF'
        mySessionAction.ntdomain = mySSODomain
        mySessionAction.securebrowse = 'ENABLED'
        mySessionAction.wihome = mySessionAction.homepage
        vpnsessionaction.add(client,mySessionAction)
        if debug:
            print 'VPN Session Action for Web created\n'
         
        mySessionPolicy = vpnsessionpolicy
        mySessionPolicy.name = 'webBrowser_pol'
        mySessionPolicy.action = mySessionAction.name
        mySessionPolicy.rule = '''REQ.HTTP.HEADER User-Agent NOTCONTAINS CitrixReceiver || REQ.HTTP.HEADER Referer EXISTS'''
        vpnsessionpolicy.add(client,mySessionPolicy)
        if debug:
            print 'VPN Session Policy for Web created\n'

        myPolicyBinding = vpnvserver_vpnsessionpolicy_binding()
        myPolicyBinding.name = myGateway
        myPolicyBinding.priority = 130
        myPolicyBinding.policy = mySessionPolicy.name
        vpnvserver_vpnsessionpolicy_binding.add(client,myPolicyBinding)
        if debug:
            print 'VPN Session Policy is bound to Gateway Virtual Server\n'
        
    except nitro_exception as e:  # Error Handling
        print("Exception::errorcode=" +
              str(e.errorcode) + ",message=" + e.message)
    except Exception as e:
        print("Exception::message=" + str(e.args))
    return

def sessionReceiverWindows(client, myGateway, mySSODomain, sfURL,myAppCURL, debug):
    try:

        mySessionAction = vpnsessionaction()
        mySessionAction.name = 'receiverWindows_act'
        mySessionAction.clientlessvpnmode = 'ON'
        mySessionAction.clientlessmodeurlencoding = 'TRANSPARENT'
        mySessionAction.sso = 'ON'
        mySessionAction.defaultauthorizationaction = 'ALLOW'
        mySessionAction.icaproxy = 'OFF'
        mySessionAction.ntdomain = mySSODomain
        mySessionAction.securebrowse = 'ENABLED'
        mySessionAction.wihome = sfURL
        mySessionAction.storefronturl = myAppCURL
        vpnsessionaction.add(client,mySessionAction)
        if debug:
            print 'VPN Session Action for Receiver created\n'
         
        mySessionPolicy = vpnsessionpolicy
        mySessionPolicy.name = 'receiverWindows_pol'
        mySessionPolicy.action = mySessionAction.name
        mySessionPolicy.rule = '''REQ.HTTP.HEADER User-Agent CONTAINS CitrixReceiver || REQ.HTTP.HEADER X-Citrix-Gateway EXISTS'''
        vpnsessionpolicy.add(client,mySessionPolicy)
        if debug:
            print 'VPN Session Policy for Receiver created\n'

        myPolicyBinding = vpnvserver_vpnsessionpolicy_binding()
        myPolicyBinding.name = myGateway
        myPolicyBinding.priority = 120
        myPolicyBinding.policy = mySessionPolicy.name
        vpnvserver_vpnsessionpolicy_binding.add(client,myPolicyBinding)
        if debug:
            print 'VPN Session Policy is bound to Gateway Virtual Server\n'
        
    except nitro_exception as e:  # Error Handling
        print("Exception::errorcode=" +
              str(e.errorcode) + ",message=" + e.message)
    except Exception as e:
        print("Exception::message=" + str(e.args))
    return
    
def sessionWorxHome(client, myGateway, mySSODomain, myAppCURL, debug):
    try:
     
        mySessionAction = vpnsessionaction()
        mySessionAction.name = 'WorxHome_act'
        mySessionAction.clientlessvpnmode = 'ON'
        mySessionAction.clientlessmodeurlencoding = 'TRANSPARENT'
        mySessionAction.sso = 'ON'
        mySessionAction.defaultauthorizationaction = 'ALLOW'
        mySessionAction.icaproxy = 'OFF'
        mySessionAction.ntdomain = mySSODomain
        mySessionAction.securebrowse = 'ENABLED'
        mySessionAction.storefronturl = myAppCURL
        vpnsessionaction.add(client,mySessionAction)
        if debug:
            print 'VPN Session Action for WorxHome created\n'
         
        mySessionPolicy = vpnsessionpolicy
        mySessionPolicy.name = 'WorxHome_pol'
        mySessionPolicy.action = mySessionAction.name
        mySessionPolicy.rule = '''REQ.HTTP.HEADER User-Agent CONTAINS zenprise || REQ.HTTP.HEADER User-Agent CONTAINS Android'''
        vpnsessionpolicy.add(client,mySessionPolicy)
        if debug:
            print 'VPN Session Policy for WorxHome created\n'

        myPolicyBinding = vpnvserver_vpnsessionpolicy_binding()
        myPolicyBinding.name = myGateway
        myPolicyBinding.priority = 110
        myPolicyBinding.policy = mySessionPolicy.name
        vpnvserver_vpnsessionpolicy_binding.add(client,myPolicyBinding)
        if debug:
            print 'VPN Session Policy is bound to Gateway Virtual Server\n'
        
    except nitro_exception as e:  # Error Handling
        print("Exception::errorcode=" +
              str(e.errorcode) + ",message=" + e.message)
    except Exception as e:
        print("Exception::message=" + str(e.args))
    return

def clientlessAccessPoliciesReceiverWeb(client,gateway, debug):
    try:

        # Create the clientless Access profile for ReceiverWeb
        myClientlessProfile = vpnclientlessaccessprofile()
        myClientlessProfile.profilename = 'receiverWeb_act'
        vpnclientlessaccessprofile.add(client,myClientlessProfile)
        if debug:
            print 'Clientless Access Profile for Receiver has been created.'
        
        # Define the cookie patset for rewrite
        myCookiePatset = policypatset()
        myCookiePatset.name = 'receiverWebCookies'
        myCookiePatset.indextype = 'User-defined'
        policypatset.add (client,myCookiePatset)
        if debug:
            print 'Cookie pattern set was created'
        
        # Define the cookies to rewrite and bind to patset
        myCookiePatsetEntry = policypatset_pattern_binding()
        myCookiePatsetEntry.name = 'receiverWebCookies'
        myCookiePatsetEntry.index = 1
        myCookiePatsetEntry.String = 'CsrfToken'
        policypatset_pattern_binding.add(client,myCookiePatsetEntry)
        myCookiePatsetEntry.index = 2
        myCookiePatsetEntry.String = 'ASP.NET_SessionId'
        policypatset_pattern_binding.add(client,myCookiePatsetEntry)
        myCookiePatsetEntry.index = 3
        myCookiePatsetEntry.String = 'CtxsPluginAssistantState'
        policypatset_pattern_binding.add(client,myCookiePatsetEntry)
        myCookiePatsetEntry.index = 4
        myCookiePatsetEntry.String = 'CtxsAuthId'
        policypatset_pattern_binding.add(client,myCookiePatsetEntry)
        if debug:
            print 'Cookie patterns were defined and bound to pattern set'
        
        # Bind the patset and URL rewrite patset to the clientless profile
        myClientlessProfile.clientconsumedcookies = 'receiverWebCookies'
        myClientlessProfile.urlrewritepolicylabel = 'ns_cvpn_default_inet_url_label'
        vpnclientlessaccessprofile.update(client, myClientlessProfile)
        if debug:
            print 'Clientless Access Profile for Receiver for Web has been created.'
    
        # Create the clientless access policy for Receiver for Web
        myClientlessPolicy = vpnclientlessaccesspolicy()
        myClientlessPolicy.name = 'receiverWeb_Pol'
        myClientlessPolicy.rule = 'true'
        myClientlessPolicy.profilename = myClientlessProfile.profilename
        vpnclientlessaccesspolicy.add(client,myClientlessPolicy)
        if debug:
            print 'Clientless Access Policy for Receiver for Web has been created and Clientless Access profile was bound.'
        
        myPolicyBinding = vpnvserver_vpnclientlessaccesspolicy_binding()
        myPolicyBinding.policy = myClientlessPolicy.name
        myPolicyBinding.priority = 120
        myPolicyBinding.name = gateway
        vpnvserver_vpnclientlessaccesspolicy_binding.add(client,myPolicyBinding)
        if debug:
            print 'Clientless policy was bound to VServer'
    
    except nitro_exception as e:  # Error Handling
        print("Exception::errorcode=" +
              str(e.errorcode) + ",message=" + e.message)
    except Exception as e:
        print("Exception::message=" + str(e.args))
    return

def clientlessAccessPoliciesReceiver(client,gateway,debug):
    try:
        
        # Create the clientless Access profile for Receiver
        myClientlessProfile = vpnclientlessaccessprofile()
        myClientlessProfile.profilename = 'receiver_act'
        vpnclientlessaccessprofile.add(client,myClientlessProfile)
        if debug:
            print 'Clientless Access Profile for Receiver has been created.'
    
        # Create the clientless access policy        
        myClientlessPolicy = vpnclientlessaccesspolicy()
        myClientlessPolicy.name = 'receiver_pol'
        myClientlessPolicy.rule = '''HTTP.REQ.HEADER("User-Agent").CONTAINS("CitrixReceiver") && HTTP.REQ.HEADER("X-Citrix-Gateway").EXISTS'''
        myClientlessPolicy.profilename = myClientlessProfile.profilename
        vpnclientlessaccesspolicy.add(client,myClientlessPolicy)
        if debug:
            print 'Clientless Access Policy for Receiver has been created and Clientless Access profile was bound.'
 
        myPolicyBinding = vpnvserver_vpnclientlessaccesspolicy_binding()
        myPolicyBinding.policy = myClientlessPolicy.name
        myPolicyBinding.priority = 110
        myPolicyBinding.name = gateway
        vpnvserver_vpnclientlessaccesspolicy_binding.add(client,myPolicyBinding)
        if debug:
            print 'Clientless policy was bound to VServer'
           
    except nitro_exception as e:  # Error Handling
        print("Exception::errorcode=" +
              str(e.errorcode) + ",message=" + e.message)
    except Exception as e:
        print("Exception::message=" + str(e.args))
    return
    
def gatewaySelection(client, debug):
    try:
        
        gwList = vpnvserver().get(client)
        for i in range(len(gwList)):
            print "%i. %s" % (i,gwList[i].name)
    
        gwNum = int(raw_input('Select the gateway for Worx and Receiver access: '))
        worxGatewayName = gwList[gwNum].name
        return worxGatewayName

    except nitro_exception as e:  # Error Handling
        print("Exception::errorcode=" +
              str(e.errorcode) + ",message=" + e.message)
    except Exception as e:
        print("Exception::message=" + str(e.args))

if __name__ == '__main__':
#    try:
#        if len(sys.argv) < 3:
#            sys.exit()
#        else:
#            ipaddress=sys.argv[1]
#            username=sys.argv[2]
#            password=sys.argv[3]
    set_config().main(set_config(),sys.argv)
#    except SystemExit:
#        print("Exception::Usage: Sample.py <nsip> <username> <password>")


