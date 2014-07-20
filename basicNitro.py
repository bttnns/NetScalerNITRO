#!/usr/bin/env python
# Nitro Imports
from nssrc.com.citrix.netscaler.nitro.service.nitro_service import nitro_service
from nssrc.com.citrix.netscaler.nitro.exception.nitro_exception import nitro_exception
from nssrc.com.citrix.netscaler.nitro.resource.config.basic.service import service

if __name__ == '__main__':
    """Create the NetScaler session using HTTP, passing in the credentials to
    the NSIP"""
    try:  # Error Handling
        ns_session = nitro_service("192.168.1.50", "HTTP")  # Create session

        ns_session.set_credential("nsroot", "nsroot")  # Set the session creds
        ns_session.timeout = 300  # Set Timeout in seconds

        ns_session.login()  # Preform login

        newSVC = service()  # Create new Service instance
        newSVC.name = "service1"  # Define a name
        newSVC.ip = "8.8.8.8"  # Define the service IP
        newSVC.port = "80"  # Define the service port
        newSVC.servicetype = "HTTP"  # Define the service type

        #Add the new service
        service.add(ns_session, newSVC)  # Add the service to the NetScaler

    except nitro_exception as e:  # Error Handling
        print("Exception::errorcode=" +
              str(e.errorcode) + ",message=" + e.message)
    except Exception as e:
        print("Exception::message=" + str(e.args))
