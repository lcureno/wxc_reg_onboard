This script helps to configure Local Gateway on Cisco IOS XE for Webex Calling as the Webex Calling guide suggest: https://help.webex.com/en-us/article/jr1i3r/Configure-Local-Gateway-on-Cisco-IOS-XE-for-Webex-Calling#id_100838

The script will prompt the required information for the deployment type that you selected and will build the configuration for registering and route calls to your Webex Calling organization.

How to run? 
The script can be uploaded to the Cisco IOS XE device and it can be run from there or you can run it from a HTTP, FTP, SFTP server. 

Like this example: 
tclsh http://[YOUR_SERVER]/wxc_reg_onboard.tcl
