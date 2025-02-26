#!/usr/local/bin/expect -f
# Begining of main script
#version 1_0_0_111224

proc bin2dec {bininput} {
    binary scan [binary format B* [format %032s $bininput]] I value
    return $value
}

proc dec2bin {num width} {
    binary scan [binary format "I" $num] "B*" binval
    return [string range $binval end-$width end]
}

proc cidr2dec cidr {

    append acu_one "" 
    set i 0
    set octet_count 1
    set octet_l {}

    while { $i < 32 } {
        
	    incr i

	    if { $i <= $cidr } {
	    	append acu_one 1
	    } else {
	        append acu_one 0
	    }

	    if { $i == 8*$octet_count} {
	    	lappend octet_l $acu_one
	    	set acu_one ""
	    	incr octet_count
	    }
    }

    #puts $octet_l
    set dec_list {}

    foreach oct $octet_l {
        set decmask [bin2dec $oct]
        lappend dec_list $decmask
    }

    set maskret [join $dec_list "."]
    #puts $maskret

    return $maskret
}

proc findconfig {shrun pattern searchType} {

    global conf_created

    log_add [format {fnc: findconfig - Pattern: %s - SearchType: %s} $pattern $searchType] 0

    switch $searchType {
        
        fonly {

            set find 0

            #puts $shrun

            foreach lineSHRUN $shrun {

                set match_sh_conf [regexp -line "$pattern.*" $lineSHRUN match_conf]

                if {$match_sh_conf} {
 
                    #puts [format {%s --------- %d --------- %s} $pattern $match_sh_conf $lineSHRUN]

                    # For not matching in dial-peer 1000 when the match is dial-peer 10, this fixes that issue. 
                    #puts $match_conf
                    #set replaced_string [regsub -all $pattern $match_conf L] ---> Replaced as in TCL 8.3 this version is not supported. 
                    regsub -all $pattern $match_conf L replaced_string
                    set replaced_string [string trim [string map {" " ""} $replaced_string]]
                    #set replaced_string [string map {"\n\n\n\n" ""} $replaced_string]


                    #puts [format {*** Replaced var: %s ***} $replaced_string]

                    # Replacing break with continue
                    if {$find} {break}

                    set find [string is alpha $replaced_string]
	                #set find 1

	            } 

            }

            #set find 0
            # The lsearch match in dial peer 100 when 10 is provided. - FIX -  
            if {$find == 0} {

                #set array_n [lsearch -regexp $conf_created $pattern]
                set array_n [lsearch -exact $conf_created $pattern]

                if {$array_n == -1} {
                    # No conflict with the config. 
                    set find 0
                    #puts [format {Matching in conf_created list %s ---- Incoming pattern %s} [lsearch -regexp $conf_created $pattern] $pattern]

                } else {
                    set find 1
                }

            }

	        return $find

        }

        retval {
        
            set pat_for_config [format {(%s)(.*?)(?=\n)} $pattern]
            #regexp {(ip domain name)(.*?)(?=\n)} $shrun find

            if { [regexp $pat_for_config $shrun find] } {
                return $find
            } else {
                set find "_NA_"
                return $find
            }

        }

        retlistval {        
            set pat_for_config [format {(%s.*?)(?=\n)} $pattern]
            set findings_list [regexp -all -inline $pat_for_config $shrun]
            return [lsort -unique $findings_list]
        }

        findPatternConf {

            #The pattern_start must be exact
            set pat_star_end_l [split $pattern "@"]
            set pattern_star [format {(%s)} [lindex $pat_star_end_l 0]]
            set pattern_end [format {(%s.*)} [lindex $pat_star_end_l 1]]
            set start_saving 0 
            set count 0 
            
            foreach lineSHRUN $shrun {

                if {[regexp $pattern_star $lineSHRUN]} {set start_saving 1}
            
                if {$start_saving} {
                    if {[regexp $pattern_end $lineSHRUN]} {
                        return $lineSHRUN
                        break
                    }
                    if {$count == 10} {return "_NA_"}
                }

                incr count
            }
        }

    }
}

proc conf_val {config_cmd type shrun} {

    global conf_created 
    #puts $conf_created

    log_add [format {fnc: conf_val - %s - %s} $config_cmd $type] 0

    #dial-peer voice 200 voip
	set i 1
    while { $i < 65000 } {
        
        set initial 100
		
        if { $type == "WxC" || $type == "CM"} {
            # Even
            set confNumber [expr $initial*(2*$i - 1)]
        } elseif { $type == "PSTN"} {
            # Odd
            set confNumber [expr $initial*2*$i]
        } elseif {$type == "PSTN_IN"} {
            # Odd + 1
            set confNumber [expr $initial*2*$i + 1]
        } elseif {$type == "TDM_Translation"} {
            set confNumber [expr 10 + $i]
        } elseif {$type == "TDM"} {
            set confNumber [expr 9 + $i]
        } 

        set pattern [format {%s %d} $config_cmd $confNumber]
        #puts $pattern
		
		#set shrun [exec show running-config]
        set findRet [findconfig $shrun $pattern "fonly"]
        #puts [format {findRet: %s --- Pattern: %s} $findRet $pattern]

        if {$findRet} {

        } else {
            # Finish LOOP
            lappend conf_created $pattern
            return $pattern
            set i 65001
        }

        incr i

    }

}

proc print_in {inputText} {

    #log_add "fnc: print_in" 0

    set input_ret ""
    set i 0
    
    puts -nonewline $inputText
    catch { flush stdout } errFlush
    catch { gets stdin usrinput } errIn

    log_add [format {fnc:print_in  - %s} $inputText] 0
    log_add [format {fnc:print_in  - %s} $errFlush] 0
    log_add [format {fnc:print_in  - %s} $errIn] 0

    # Analyzing inputs
    while {$i < [string length $usrinput]} {

        set input_ch [string index $usrinput $i]
        # Scaning input:
        set ascii_number [scan $input_ch %c]

        # Delete
        if {$ascii_number == 127} { 
            if {[string length $input_ret] > 0} {set input_ret [string range $input_ret 0 [expr "[string length $input_ret] - 2"]]}
        } else {
            append input_ret $input_ch
        }
    
        incr i
    }

    return $input_ret
  }


proc inManual {dptype mode shrun} {

    log_add "fnc: inManual" 0

    set inputL {
        "Registrar Domain"
        "Trunk Group OTG/DTG"
        "Line/Port"
        "Outbound Proxy Address"
        "Username"
        "Password"
    }

    set tenant_number 1
    set mul_tenant_list {}

    if { $dptype == 3 || $dptype == 4} {
        # Force to a number, limited to 15 for now ...
        set tenant_number [force_input "\nHow many tenants do you want to add?: " "number" 15 "The input is not an number or it's greather than the allowed number of tenants (15)"]
        set e164_in [force_input "\nDo you want to route the WxC tenant numbers with e164-pattern-maps (y/N)?: " "yN" "" "Invalid option"]

        if {[yN $e164_in]} {
            lappend inputL "\nPlease add the number list, each entry separate with a space (example: 1315369500.\$ 1\[2-3\]26636120*\$ 12..$ )"     
            lappend inputL "Add a description on the e164-pattern-map"
        }
    } 


    set inValist {}
	
    set j 0

    # Multi tenant
    while { $j < $tenant_number } {    
        set tempListTenant {}

        puts "\n"
        puts [format {*** *** *** Tenant %s *** *** ***} [expr $j + 1]]

        foreach inp $inputL {

            set inPutF [format {%s: } $inp]
            set inVal [print_in $inPutF]

            #lappend inValist $inVal

            if { $dptype == 3 || $dptype == 4 } {
                lappend tempListTenant $inVal
            } else {
                lappend inValist $inVal  
            }
        }

        lappend mul_tenant_list $tempListTenant
        incr j
        
    }

    set shrun_st [join $shrun "\n"]

    if { $dptype == 3 } {

        set pstndp [force_input "\nIs the PSTN already configured (y/N)?: " "yN" "" "Invalid option"]

        puts "\n\n"

        if {[yN $pstndp]} {
            # Show all dial peers. 
            #set dp_all_list [findconfig $shrun_st "dial-peer voice" "retlistval"]
            set dpg_all_list [findconfig $shrun_st "voice class dpg" "retlistval"]
            #set list_to_show [concat $dpg_all_list $dp_all_list]
            set pstn_to_use [shw_conf_options $dpg_all_list "dial-peer group" "PSTN routing"]

        } else {
            puts "\nYou must create later the outbound routing for WxC to make calls to PSTN"
            lappend pstn_to_use "_NA_"
        }
    }

    set wxc_int [sh_int_fnc "WxC" $mode]

    if { $dptype == 1 } {

        set pstn_int [sh_int_fnc "PSTN" $mode]

        #puts "\n"
        #Removing encryption key, there's a bug. 
        #set enkey [force_input "\nTo protect registration and STUN credentials on the router using symmetric encryption, please provide the encryption key (password): " "charac_num" 8 "Password must contain 8 or more characters"]
        set enkey "_NA_"

        lappend inValist $enkey
        lappend inValist $wxc_int
        lappend inValist $pstn_int

        set ipToUse [force_input "\nWhat is the PSTN IP: " "ip" "N/A" "Incorrect input"]
        lappend inValist $ipToUse

    } elseif {$dptype == 2} {

        # Questions:
        # What is the CM source port for calling:  
        # Provide the pattern to identify calls from UCM towards the PSTN trunk (example: 192\\.168\\.80\\.6[0-5]:5060):
        # Provide the interface to reach CUCM:
        # The configuration guide suggest to create SRV domain and A record, do you want to do this part? 
        # Please provide the call manager IPs ?
        # Please provide the domain name? 

        # INTEGRATION WITH CALL MANAGER. 
        set pstn_int [sh_int_fnc "PSTN" $mode]
        set cucm_int [sh_int_fnc "CM" $mode]

        puts "\n"

        #set enkey [force_input "\nTo protect registration and STUN credentials on the router using symmetric encryption, please provide the encryption key (password): " "charac_num" 8 "Password must contain 8 or more characters"]
        set enkey "_NA_"

        set classURIPat [print_in "Provide the pattern that is going to be used for identifying calls from UCM towards the PSTN trunk (example: 192\\.168\\.80\\.6\[0-5\]:5060): "]
        set cumIPs [print_in "\nPlease provide the call manager IPs (if there are more than one, separate with a comma example: 192.168.0.1,192.168.0.2): "]

        set cm_dom [force_input "\nThe configuration guide suggests to create SRV domain and A record for the UCM address, do you want to do this part (y/N)?: " "yN" "" "Invalid option"]

        if {[yN $cm_dom]} {
            # GET DOMAIN NAME FROM CONFIG. 
            set create_cm_dom_out [cr_cm_dom $shrun $cumIPs]
            # $ipHostList $wxSRVdom $pstnSRVdom]
            set ipHostConf [lindex $create_cm_dom_out 0]
            set TargetSRVdomWx [lindex $create_cm_dom_out 1]
            set TargetSRVdomPSTN [lindex $create_cm_dom_out 2]

        } else {

            set TargetSRVdomWx [print_in "\nPlease type the SRV domain for the CM trunk where the calls from WxC are going to be sent: "]
            set TargetSRVdomPSTN [print_in "Please type the SRV domain for the CM trunk where the calls from PSTN are going to be sent: "]

            # NO NEED IT.
            set ipHostConf {}
            
        }

        set ipToUse [force_input "\nWhat is the PSTN IP: " "ip" "N/A" "Incorrect input"]

        lappend inValist $enkey
        lappend inValist $wxc_int
        lappend inValist $pstn_int
        #9
        lappend inValist $ipToUse
        lappend inValist $cucm_int

        lappend inValist $classURIPat
        lappend inValist $cumIPs

        # IP HOST CONF
        lappend inValist $ipHostConf
        lappend inValist $TargetSRVdomWx
        lappend inValist $TargetSRVdomPSTN


    } elseif {$dptype == 3} { 
        # Add tenant only
        lappend inValist $mul_tenant_list
        lappend inValist $wxc_int
        lappend inValist $pstn_to_use

    } elseif {$dptype == 4} { 
        # Configure Local Gateway with a SIP PSTN trunk + E164-Pattern-Maps routing for tenant numbers

        lappend inValist $mul_tenant_list

        set pstn_int [sh_int_fnc "PSTN" $mode]

        #puts "\n"
        #Removing encryption key, there's a bug. 
        #set enkey [force_input "\nTo protect registration and STUN credentials on the router using symmetric encryption, please provide the encryption key (password): " "charac_num" 8 "Password must contain 8 or more characters"]
        set enkey "_NA_"

        lappend inValist $enkey
        lappend inValist $wxc_int
        lappend inValist $pstn_int

        set ipToUse [force_input "\nWhat is the PSTN IP: " "ip" "N/A" "Incorrect input"]
        lappend inValist $ipToUse


    } elseif {$dptype == 5} {
        # Configure Local Gateway with a TDM PSTN trunk.

        # WxC Interface

        puts "\n"

        #set enkey [force_input "\nTo protect registration and STUN credentials on the router using symmetric encryption, please provide the encryption key (password): " "charac_num" 8 "Password must contain 8 or more characters"]
        set enkey "_NA_"
        lappend inValist $enkey
        lappend inValist $wxc_int

    }

    return $inValist

}

proc cr_cm_dom {shrun cm_ip_input} {

    set ipHostList {}

    set shrun_st [join $shrun "\n"]

    # SEARCH IP NAME
    set findRet [findconfig $shrun_st "ip domain name " "retval"]
    set domToUse [string map {"ip domain name " ""} $findRet]
        
    if {$findRet == "_NA_"} {
        # TRYING SECOND
        set retHost [exec show hosts]
        set findRet [findconfig $retHost "Default domain is " "retval"]
        set domToUse [string map {"Default domain is " ""} $findRet]
    } 

    if {$findRet == "_NA_"} {
        set domToUse [print_in "Can you provide the domain?: "]
    }

    set cmIPs_list [split $cm_ip_input ","]
    set k 0

    set wxSRVdom "wxtocucm.io"
    set pstnSRVdom "pstntocucm.io"

    foreach cm_ip $cmIPs_list {

        if {$k == 0} {
            set domain [format {ip host ucmpub.%s %s} $domToUse $cm_ip]
            set srvdomain [format {ip host _sip._udp.%s srv 0 1 5065 ucmpub.%s} $wxSRVdom $domToUse]
            set srvdomainPSTN [format {ip host _sip._udp.%s srv 0 1 5060 ucmpub.%s} $pstnSRVdom $domToUse]
        } else {
            set domain [format {ip host ucmsub%d.%s %s} $k $domToUse $cm_ip]
            set srvdomain [format {ip host _sip._udp.%s srv 2 1 5065 ucmsub%d.%s} $wxSRVdom $k $domToUse ]
            set srvdomainPSTN [format {ip host _sip._udp.%s srv 2 1 5060 ucmsub%d.%s} $pstnSRVdom $k $domToUse ]
        }

        lappend ipHostList [encap_list $domain]
        lappend ipHostList [encap_list $srvdomain]
        lappend ipHostList [encap_list $srvdomainPSTN]

        incr k

    }

    set shrun_st ""

    set out_cm_fun [encap_list $ipHostList $wxSRVdom $pstnSRVdom]
    return $out_cm_fun

}

proc sh_int_fnc {Intype mode} {

    if {$mode == "Testing"} {
        set showip "Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0/0   192.168.0.1 YES NVRAM  up                    up
GigabitEthernet0/0/1   unassigned      YES NVRAM  down                  down
GigabitEthernet0/0/2       unassigned      YES NVRAM  down                  down"

    } else {
        set showip [exec show ip interface brief]
        #puts $showip
    }

    set j 0
    set cap_int_l {}
    set int_list [split $showip "\n"]
    set acu_int "  Index    LGW Interfaces\n -------   ---------------\n"

    puts "\n"

    foreach intRow $int_list {

        if {$j != 0} {
            regexp {^([^ ]*)} $intRow int_output
            if {$int_output == "Interface"} {continue}
            set intCol [format {   %d        %s} $j $int_output]
            lappend cap_int_l $int_output
            append acu_int $intCol "\n"
        }

        incr j

    }

    puts $acu_int

    puts "\n"
    set inttouse [force_input [format {Please select the interface for %s: } $Intype] "number" [llength $cap_int_l] "Incorrect selection"]

    if { $inttouse <= [llength $cap_int_l]} {
        #puts [format {Selected interface: %s} [lindex $cap_int_l [expr $inttouse - 1]]]
        set ret_interface [lindex $cap_int_l [expr $inttouse - 1]]
    } else {
        puts "*** *** *** Wrong interface input, exiting ... *** *** ***"
    }
    return $ret_interface
}

proc shw_conf_options {inputList print print_2} {
    
    # Add tenant only
    if {[llength $inputList] == 0} {
        puts [format {*** *** *** You must configure the %s on the tenant, otherwise the registration could fail *** *** ***} $print]
        #puts "\n"
        return "_NA_"
    } elseif {[llength $inputList] == 1} {
        set return_values [lindex $inputList 0]
        #puts "\n"
        return $return_values
    } else {

        set acu_int "  Index    Configuration\n -------   ---------------\n"
        set j 1
        #puts "\n"

        foreach intRow $inputList {
            set intCol [format {   %d        %s} $j $intRow]
            append acu_int $intCol "\n"
            incr j

        }

        puts $acu_int

        set confTOuse [print_in [format {Please select the %s config for the %s: } $print $print_2]]

        set return_values [lindex $inputList [expr $confTOuse - 1]]

        return $return_values
    }

}

proc supported_deployments_l {ret_type dptype} {

    set list_dp_typ {"Configure Local Gateway with a SIP PSTN trunk" 
    "Configure Local Gateway with an existing Unified CM environment" 
    "Add WxC Calling tenant" 
    "Configure Local Gateway with a SIP PSTN trunk + E164-Pattern-Maps routing for tenant numbers"
    "Help"
    }

    # Removing after having a better idea of what to do... 
    #puts [format $formatStr "5" "    Configure Local Gatway with a TDM PSTN trunk"]

    switch $ret_type {
        all_list {return $list_dp_typ}
        required_dp {return [lindex $list_dp_typ [expr $dptype - 1]]}
    }

}

proc deployment_type {} {
    
    set loop_bool 1
    set deploy_list_length [llength [supported_deployments_l "all_list" 0]]

    while {$loop_bool} {
        
        # WxC LGW Deployment type
        puts "\n"
        set formatStr {%25s%-s}
        puts [format $formatStr "Selection" "    Deployment type"]
        puts [format $formatStr "----------" "    ----------------"]

        set j 1

        foreach deploy_elem [supported_deployments_l "all_list" 0] {
            set toPrint [format {%21d        %-s} $j $deploy_elem]
            puts $toPrint
            incr j 
        }

        set dt [force_input "\nSelect Deployment type: " "depType" $deploy_list_length "Incorrect deployment type"]

        if {$dt == $deploy_list_length} {

            set continue_from_help [help_print]
            if {$continue_from_help == "N"} {
                set dt 1000
                set loop_bool 0
            }
            } else {
                set loop_bool 0
            }
    
    }

    return $dt
}

proc con_sec_conf {wxcint yp} {

    set con_sec_list {}

    # -> Removing as bug was found <- 
    # key config-key password-encrypt YourPassword
    # password encryption aes
    
    if {$yp != "_NA_"} {
        set encp [format {key config-key password-encrypt %s} $yp]
        lappend con_sec_list [encap_list $encp]
        lappend con_sec_list [encap_list "password encryption aes"]
    }

    lappend con_sec_list [encap_list "crypto pki trustpoint EmptyTP" "revocation-check none"]

    set sip_ua_conf {
        "timers connection establish tls 5"
        "transport tcp tls v1.2"
        "crypto signaling default trustpoint EmptyTP cn-san-validate server"
        "tcp-retry 1000"
    }

    foreach sipualine $sip_ua_conf {
        lappend con_sec_list [encap_list "sip-ua" $sipualine]
    }

    set download_certificates [format {ip http client source-interface %s} $wxcint]
    lappend con_sec_list [encap_list $download_certificates]

    # Download certificates.
    lappend con_sec_list [encap_list "crypto pki trustpool import clean url https://www.cisco.com/security/pki/trs/ios_core.p7b"]

    return $con_sec_list

}

proc general_config {show_running pstn_ip} {

    puts "*** *** *** Creating trusted list *** *** ***"
    log_add [format {fnc: general_config - %s} "*** *** *** Creating trusted list *** *** ***" ] 0

    # Taken from https://help.webex.com/en-us/article/b2exve/Port-Reference-Information-for-Webex-Calling on 02/10/24
    set wxc_serv_ips {"23.89.0.0/16" "128.177.36.0/24" "139.177.72.0/23" "163.129.0.0/17" "185.115.196.0/22" "199.59.64.0/21" "85.119.56.0/23" "135.84.168.0/21" "144.196.0.0/16" "170.72.0.0/16" "199.19.196.0/23" "128.177.14.0/24" "139.177.64.0/21" "150.253.128.0/17" "170.133.128.0/18" "199.19.199.0/24"}
    set cmAddressOutput {}

    # Adding PSTN IP
    lappend wxc_serv_ips [format {%s/32} $pstn_ip]

    set gencnf_l {}

    foreach ipcidr $wxc_serv_ips {

        set ipaddressTrusCMD {"voice service voip" "ip address trusted list"}

        set tVar [split $ipcidr "/"]
        set ipallow [lindex $tVar 0]
        set cidr_val [lindex $tVar 1]
	
	    #puts $ipallow
	    #puts $cidr_val

	    set mask [cidr2dec $cidr_val]
	
        set ipmask [format {ipv4 %s %s} $ipallow $mask]
        lappend ipaddressTrusCMD $ipmask
        lappend gencnf_l $ipaddressTrusCMD

    }

    #set voiservcom [ios_config "voice service voip" "mode border-element"]
    
    # More general config
    lappend gencnf_l {"voice service voip" "mode border-element"}
    lappend gencnf_l {"voice service voip" "media statistics"}
    lappend gencnf_l {"voice service voip" "media bulk-stats"}
    lappend gencnf_l {"voice service voip" "allow-connections sip to sip"}
    lappend gencnf_l {"voice service voip" "no supplementary-service sip refer"}
    lappend gencnf_l {"voice service voip" "stun" "stun flowdata agent-id 1 boot-count 4"}
    lappend gencnf_l {"voice service voip" "stun" "stun flowdata shared-secret 0 Password123$"}
    # The config "asymmetric payload full" --> Cause DTMF issues. 
    lappend gencnf_l {"voice service voip" "sip" "early-offer forced"}

    # Voice class codec
    set vclasscodec [conf_val "voice class codec" "WxC" $show_running]

    # *** *** *** Can be modified to add more codec? *** *** ***
    lappend gencnf_l [encap_list $vclasscodec "codec preference 1 g711ulaw"]
    lappend gencnf_l [encap_list $vclasscodec "codec preference 2 g711alaw"]

    # Voice class stun-usage
    set vstunusage [conf_val "voice class stun-usage" "WxC" $show_running]

    #Stun Commands
    lappend gencnf_l [encap_list $vstunusage "stun usage firewall-traversal flowdata" ]
    lappend gencnf_l [encap_list $vstunusage "stun usage ice lite"]

    # SRTP-CRYPTO
    set vsrtpcrypto [conf_val "voice class srtp-crypto" "WxC" $show_running]
    set srtpcryptoNumber [string map {"voice class srtp\n" ""} $vsrtpcrypto]

    lappend gencnf_l [encap_list $vsrtpcrypto "crypto 1 AES_CM_128_HMAC_SHA1_80"]

    set reList {}
    lappend reList $gencnf_l $srtpcryptoNumber $vclasscodec $vstunusage

    return $reList

}

proc encap_list {args} {
    set acu_l {}
    foreach larg $args {
        lappend acu_l $larg
    }
    return $acu_l
}

proc wxc_tenant_cnf {tenantIN wxcInt show_running srtpcrypto codecNumber stunN} {

    global display_routing_dgm_l

    log_add [format {fnc: wxc_tenant_cnf - %s} $tenantIN] 0
    log_add [format {fnc: wxc_tenant_cnf - %s - %s - %s -%s} $wxcInt $srtpcrypto $codecNumber $stunN] 0

    set tenant_cnf_l {}
    set vtenant_list {}

    ### VOICE CLASS URI ###
    set dtg [string map {_ .} [lindex $tenantIN 1]]
    set vclassuri [format {%s sip} [conf_val "voice class uri" "WxC" $show_running]]
    set wxcdtg [format {pattern dtg=%s} $dtg]

    lappend tenant_cnf_l [encap_list $vclassuri $wxcdtg]

    ### CREATING VOICE CLASS TENANT ###
    set regDom [lindex $tenantIN 0]
    set linePort [lindex [split [lindex $tenantIN 2] "@"] 0]
    set outprox [lindex $tenantIN 3]
    set username [lindex $tenantIN 4]
    set password [lindex $tenantIN 5]
    set otg [lindex $tenantIN 1]

    ### CREATING SIP PROFILE ###
    set otg_sip_prof [format {rule 80 request ANY sip-header From modify ">" ";otg=%s>"} $otg]
	
    set sip_prof_list  {
        "rule 10 request ANY sip-header SIP-Req-URI modify \"sips:\" \"sip:\"" 
        "rule 20 request ANY sip-header To modify \"<sips:\" \"<sip:\""
        "rule 30 request ANY sip-header From modify \"<sips:\" \"<sip:\""
		"rule 40 request ANY sip-header Contact modify \"<sips:(.*)>\" \"<sip:\\1;transport=tls>\""
        "rule 50 response ANY sip-header To modify \"<sips:\" \"<sip:\""
        "rule 60 response ANY sip-header From modify \"<sips:\" \"<sip:\""
        "rule 70 response ANY sip-header Contact modify \"<sips:\" \"<sip:\""
        "rule 90 request ANY sip-header P-Asserted-Identity modify \"sips:\" \"sip:\""
    }

    # Moving to the correct position.
    set sip_prof_list [linsert $sip_prof_list 7 $otg_sip_prof]
    #lappend sip_prof_list $otg_sip_prof

    set sipProfcmd [conf_val "voice class sip-profiles" "WxC" $show_running]
    #puts $sipProfcmd

    foreach rule $sip_prof_list {
        lappend tenant_cnf_l [encap_list $sipProfcmd $rule]
    }

    ### VOICE CLASS TENANT ###
    set vclasstenant [conf_val "voice class tenant" "WxC" $show_running]

    set regLine [format {registrar dns:%s scheme sips expires 240 refresh-ratio 50 tcp tls} $regDom]
    set credLine [format {credentials number %s username %s password 0 %s realm BroadWorks} $linePort $username $password]
    set authLine1 [format {authentication username %s password 0 %s realm BroadWorks} $username $password]
    set authLine2 [format {authentication username %s password 0 %s realm %s} $username $password $regDom]
    set outproxLine [format {outbound-proxy dns:%s} $outprox]
    set sipserverLine [format {sip-server dns:%s} $regDom]


    lappend tenant_cnf_l [encap_list $vclasstenant $regLine]
    lappend tenant_cnf_l [encap_list $vclasstenant $credLine]
    lappend tenant_cnf_l [encap_list $vclasstenant $authLine1]
    lappend tenant_cnf_l [encap_list $vclasstenant $authLine2]

    # Sorting list as doc:
    lappend tenant_cnf_l [encap_list $vclasstenant "no remote-party-id"]
    lappend tenant_cnf_l [encap_list $vclasstenant $sipserverLine]
    lappend tenant_cnf_l [encap_list $vclasstenant "connection-reuse"]
    
    # SRTP CRYPTO
    if {$srtpcrypto != "_NA_"} {
        lappend tenant_cnf_l [encap_list $vclasstenant [string map {"voice class " ""} $srtpcrypto]]
    }

    set tenantConf {
        "session transport tcp tls"
        "no session refresh"
        "url sips"
        "error-passthru"
        "rel1xx disable"
        "asserted-id pai"
    }

    foreach tconf $tenantConf {
        lappend tenant_cnf_l [encap_list $vclasstenant $tconf]
    }

    # INTERFACE
    set intControlT [format {bind control source-interface %s} $wxcInt]
    set intMediaT [format {bind media source-interface %s} $wxcInt]
    lappend tenant_cnf_l [encap_list $vclasstenant $intControlT]
    lappend tenant_cnf_l [encap_list $vclasstenant $intMediaT]

    lappend tenant_cnf_l [encap_list $vclasstenant "no pass-thru content custom-sdp"]


    # ASSIGNING SIP PROFILE
    set sipProfTenant [string map {"voice class " ""} $sipProfcmd]
    lappend tenant_cnf_l [encap_list $vclasstenant $sipProfTenant]

    # OUTBOUND PROXY
    lappend tenant_cnf_l [encap_list $vclasstenant $outproxLine]

    lappend tenant_cnf_l [encap_list $vclasstenant "privacy-policy passthru"]

    # WXC DIAL-PEER - CREATE
    set WxCDialPeer [conf_val "dial-peer voice" "WxC" $show_running]
    set Dial_Peer_Wxc [format {%s voip} $WxCDialPeer]

    set DialPeerConf {
        "description Inbound/Outbound Webex Calling"
        "max-conn 250"
        "destination-pattern BAD.BAD"
        "session protocol sipv2"
        "session target sip-server"
        "dtmf-relay rtp-nte"
        "no voice-class sip localhost"
        "srtp"
        "no vad"
    }


    set tenantConfig [string map {"voice class tenant" "voice-class sip tenant"} $vclasstenant]
    #lappend DialPeerConf $tenantConfig
    set DialPeerConf [linsert $DialPeerConf 7 $tenantConfig]

    # Condition was added to integrate the multi-tenant config
    if {$codecNumber != "_NA_"} {
        set codecDP [string map {"voice class" "voice-class"} $codecNumber]
        #lappend DialPeerConf $codecDP
        set DialPeerConf [linsert $DialPeerConf 5 $codecDP]
    }

    if {$stunN != "_NA_"} {
        set dialStunCnf [string map {"voice class" "voice-class"} $stunN]
        #lappend DialPeerConf $dialStunCnf
        set DialPeerConf [linsert $DialPeerConf 7 $dialStunCnf]
    }

    #set vclassuri [format {%s sip} [conf_val "voice class uri" "WxC" $show_running]]
    set dialUri [string map {" sip" ""} [string map {"voice class uri" "incoming uri request"} $vclassuri]]
    #lappend DialPeerConf $dialUri
    set DialPeerConf [linsert $DialPeerConf 5 $dialUri]

    foreach confDP $DialPeerConf {
        lappend tenant_cnf_l [encap_list $Dial_Peer_Wxc $confDP]
    }

    # Restarting tenant
    lappend vtenant_list [encap_list $vclasstenant "no registrar"]
    lappend vtenant_list [encap_list $vclasstenant $regLine]

    # Added $vclasstenant to get the tenant -> Multi tenant config
    set retList [encap_list $tenant_cnf_l $Dial_Peer_Wxc $vclasstenant $vtenant_list]

    # Adding info to routing diagram list - 1 # 0 , 1 , 2 , 3 , 4 , 5
    global display_routing_dgm_l
    lappend display_routing_dgm_l $vclassuri
    lappend display_routing_dgm_l $wxcdtg
    lappend display_routing_dgm_l $Dial_Peer_Wxc
    lappend display_routing_dgm_l $dialUri
    lappend display_routing_dgm_l $outprox
    lappend display_routing_dgm_l $tenantConfig

    return $retList

}


proc routecnf {type show_running routeip pstnInt codecNumber WxCDP ucm_int cm_pattern wxtocucm_dom pstntocucm_dom} {

    set route_conf_l {}
    set return_route_list {}

    global display_routing_dgm_l

    log_add [format {fnc: routecnf - %s - %s - %s - %s - %s - %s - %s - %s} $routeip $pstnInt $codecNumber $WxCDP $ucm_int $cm_pattern $wxtocucm_dom $pstntocucm_dom] 0

    set codecDP [string map {"voice class" "voice-class"} $codecNumber]

    # Before if { $type == 1 || $type == 2}
    if { $type == 1} {
        ### CREATING VOICE CLASS URI WxC ###
        set vclassuri [format {%s sip} [conf_val "voice class uri" "PSTN" $show_running]]
        set pstnIP [format {host ipv4:%s} $routeip]
        lappend route_conf_l [encap_list $vclassuri $pstnIP]
        #puts $vclassuri

        set incomingURIDP [string map {" sip" ""} [string map {"voice class uri" "incoming uri via"} $vclassuri]]
    }

    ### CREATING PSTN DIALPEER ###
    set pstnDP [format {%s voip} [conf_val "dial-peer voice" "PSTN" $show_running]]

    set pstnIntDPcontrol [format {voice-class sip bind control source-interface %s} $pstnInt]
    set pstnIntDPmedia [format {voice-class sip bind media source-interface %s} $pstnInt]
	set SessionTarget [format {session target ipv4:%s} $routeip]

    if {$type == 4 || $type == 2} {set dp_pstn_des "Outbound to IP PSTN trunk"} else {set dp_pstn_des "Inbound/Outbound IP PSTN trunk"}
    
    lappend route_conf_l [encap_list $pstnDP [format {description %s} $dp_pstn_des]]
    lappend route_conf_l [encap_list $pstnDP "destination-pattern BAD.BAD"]
    lappend route_conf_l [encap_list $pstnDP "session protocol sipv2"]
    lappend route_conf_l [encap_list $pstnDP $SessionTarget]
    # URI
    # Moving after BAD.BAD

    # BEFORE if { $type == 1 || $type == 2}
    if { $type == 1} {
        lappend route_conf_l [encap_list $pstnDP $incomingURIDP]
    }

    lappend route_conf_l [encap_list $pstnDP "voice-class sip asserted-id pai"]
    lappend route_conf_l [encap_list $pstnDP $pstnIntDPcontrol]
    lappend route_conf_l [encap_list $pstnDP $pstnIntDPmedia]
    lappend route_conf_l [encap_list $pstnDP $codecDP]
    lappend route_conf_l [encap_list $pstnDP "dtmf-relay rtp-nte"]
    lappend route_conf_l [encap_list $pstnDP "no vad"]

    set PSTNvoicedpg [conf_val "voice class dpg" "PSTN" $show_running]
    set PSTNdpgconfDP [string map {" voip" ""} [string map {" voice" ""} $pstnDP]]

    
    if { $type == 1 } {

        ### CREATE DPG ###
        set WxCvoicedpg [conf_val "voice class dpg" "WxC" $show_running]
        set WxCdpgconfDP [string map {" voip" ""} [string map {" voice" ""} $WxCDP]]

        lappend route_conf_l [encap_list $WxCvoicedpg "description Route calls to Webex Calling"]
        lappend route_conf_l [encap_list $WxCvoicedpg $WxCdpgconfDP]

        lappend route_conf_l [encap_list $PSTNvoicedpg "description Route calls to PSTN"]
        lappend route_conf_l [encap_list $PSTNvoicedpg $PSTNdpgconfDP]

        ### ASSIGNING DPGS to DIAL-PEERs ###
        set WxCdpgToDP [string map {"voice class" "destination"} $PSTNvoicedpg]
        set PSTNdpgToDP [string map {"voice class" "destination"} $WxCvoicedpg]

        lappend route_conf_l [encap_list $WxCDP $WxCdpgToDP]
        lappend route_conf_l [encap_list $pstnDP $PSTNdpgToDP]
        
        # Display Routing diagram - 1
        lappend display_routing_dgm_l $PSTNvoicedpg
        lappend display_routing_dgm_l $PSTNdpgconfDP
        lappend display_routing_dgm_l $vclassuri
        lappend display_routing_dgm_l $pstnIP
        lappend display_routing_dgm_l $pstnDP
        lappend display_routing_dgm_l $incomingURIDP
        lappend display_routing_dgm_l $PSTNdpgToDP
        lappend display_routing_dgm_l $SessionTarget
        lappend display_routing_dgm_l $routeip
        lappend display_routing_dgm_l $WxCvoicedpg
        lappend display_routing_dgm_l $WxCdpgconfDP
        lappend display_routing_dgm_l $WxCdpgToDP
       
    } elseif {$type == 2} {

        global conf_created
        lappend conf_created "voice class uri 200"

        # Classifies Unified CM to Webex calls using SIP VIA port:
        set vclassuri [format {%s sip} [conf_val "voice class uri" "CM" $show_running]]
        lappend route_conf_l [encap_list $vclassuri "pattern :5065"]

        # Classifies Unified CM to PSTN calls using SIP via port:
        set vclassuri_pstn [format {%s sip} [conf_val "voice class uri" "PSTN" $show_running]]
        set pattern_pstn [format {pattern %s} $cm_pattern]
        lappend route_conf_l [encap_list $vclassuri_pstn $pattern_pstn]

        # Dial-peer for calls between Unified CM and Webex Calling:
        set dp_cm_to_wxc [format {%s voip} [conf_val "dial-peer voice" "CM" $show_running]]
        set in_uri_dp [string map {" sip" ""} [string map {"voice class uri" "incoming uri via"} $vclassuri]]

        set session_target [format {session target dns:%s} $wxtocucm_dom]

        set int_ucm_con [format {voice-class sip bind control source-interface %s} $ucm_int]
        set int_ucm_med [format {voice-class sip bind media source-interface %s} $ucm_int]

        set cm_to_wx_dp_conf {
            "description UCM-Webex Calling trunk"
            "destination-pattern BAD.BAD"
            "session protocol sipv2"
        }

        lappend cm_to_wx_dp_conf $session_target
        lappend cm_to_wx_dp_conf $in_uri_dp
        lappend cm_to_wx_dp_conf $codecDP
        lappend cm_to_wx_dp_conf $int_ucm_con
        lappend cm_to_wx_dp_conf $int_ucm_med
        lappend cm_to_wx_dp_conf "dtmf-relay rtp-nte"
        lappend cm_to_wx_dp_conf "no vad"

        foreach confLineDP $cm_to_wx_dp_conf {
            lappend route_conf_l [encap_list $dp_cm_to_wxc $confLineDP]
        }

        # Dial-peer for calls between Unified CM and the PSTN:
        set dp_cm_to_pstn [format {%s voip} [conf_val "dial-peer voice" "PSTN" $show_running]]

        set st_pstn_to_cucm [format {session target dns:%s} $pstntocucm_dom]
        set inuri_cm_to_pstn_dp [string map {" sip" ""} [string map {"voice class uri" "incoming uri via"} $vclassuri_pstn]]

        set cm_to_pstn_dp_conf {
            "description UCM-PSTN trunk"
            "destination-pattern BAD.BAD"
            "session protocol sipv2"
        }

        lappend cm_to_pstn_dp_conf $st_pstn_to_cucm
        lappend cm_to_pstn_dp_conf $inuri_cm_to_pstn_dp
        lappend cm_to_pstn_dp_conf $codecDP
        lappend cm_to_pstn_dp_conf $int_ucm_con
        lappend cm_to_pstn_dp_conf $int_ucm_med
        lappend cm_to_pstn_dp_conf "dtmf-relay rtp-nte"
        lappend cm_to_pstn_dp_conf "no vad"

        foreach confLineDP $cm_to_pstn_dp_conf {
            lappend route_conf_l [encap_list $dp_cm_to_pstn $confLineDP]
        }


        # DPG to Route calls to Webex Calling
        set WxCvoicedpg [conf_val "voice class dpg" "WxC" $show_running]
        set WxCdpgconfDP [string map {" voip" ""} [string map {" voice" ""} $WxCDP]]
        lappend route_conf_l [encap_list $WxCvoicedpg "description Route calls to Webex Calling"]
        lappend route_conf_l [encap_list $WxCvoicedpg $WxCdpgconfDP]

        #description Route calls to Unified CM Webex Calling trunk
        set dpg_cm_to_wxc [conf_val "voice class dpg" "WxC" $show_running]
        set dpg_cm_to_wxc_dp [string map {" voip" ""} [string map {" voice" ""} $dp_cm_to_wxc]]

        lappend route_conf_l [encap_list $dpg_cm_to_wxc "description Route calls to Unified CM Webex Calling trunk"]
        lappend route_conf_l [encap_list $dpg_cm_to_wxc $dpg_cm_to_wxc_dp]

        # dpg 200 - description Route calls to PSTN
        lappend route_conf_l [encap_list $PSTNvoicedpg "description Route calls to PSTN"]
        lappend route_conf_l [encap_list $PSTNvoicedpg $PSTNdpgconfDP]

        #dpg 400 - description Route calls to Unified CM PSTN trunk
        set dpg_wxc_to_cm [conf_val "voice class dpg" "PSTN" $show_running]
        set dpg_wxc_to_cm_dp [string map {" voip" ""} [string map {" voice" ""} $dp_cm_to_pstn]]

        lappend route_conf_l [encap_list $dpg_wxc_to_cm "description Route calls to Unified CM PSTN trunk"]
        lappend route_conf_l [encap_list $dpg_wxc_to_cm $dpg_wxc_to_cm_dp]


        # DIAL PEERS ARE DIFFERENT.
        ### ASSIGNING DPGS to DIAL-PEERs ###
        
        set WxCtoCM_dpg [string map {"voice class" "destination"} $dpg_cm_to_wxc]
        lappend route_conf_l [encap_list $WxCDP $WxCtoCM_dpg]

        set cmtoWxC_dpg_det [string map {"voice class" "destination"} $WxCvoicedpg]
        lappend route_conf_l [encap_list $dp_cm_to_wxc $cmtoWxC_dpg_det]

        set wxctocm_dpg_det [string map {"voice class" "destination"} $dpg_wxc_to_cm]
        lappend route_conf_l [encap_list $pstnDP $wxctocm_dpg_det]

        # FOR LATER
        set ucm_pstn_dpg_det [string map {"voice class" "destination"} $PSTNvoicedpg]
        lappend route_conf_l [encap_list $dp_cm_to_pstn $ucm_pstn_dpg_det]

        # CUCM, print deployment
        lappend display_routing_dgm_l $pstnDP
        lappend display_routing_dgm_l $SessionTarget
        lappend display_routing_dgm_l $vclassuri
        lappend display_routing_dgm_l "pattern :5065"
        lappend display_routing_dgm_l $vclassuri_pstn
        lappend display_routing_dgm_l $pattern_pstn
        lappend display_routing_dgm_l $dp_cm_to_wxc
        lappend display_routing_dgm_l $in_uri_dp
        lappend display_routing_dgm_l $session_target
        lappend display_routing_dgm_l $dp_cm_to_pstn
        lappend display_routing_dgm_l $st_pstn_to_cucm
        lappend display_routing_dgm_l $inuri_cm_to_pstn_dp
        lappend display_routing_dgm_l $WxCvoicedpg
        lappend display_routing_dgm_l $WxCdpgconfDP
        lappend display_routing_dgm_l $dpg_cm_to_wxc
        lappend display_routing_dgm_l $dpg_cm_to_wxc_dp
        lappend display_routing_dgm_l $dpg_wxc_to_cm
        lappend display_routing_dgm_l $dpg_wxc_to_cm_dp
        lappend display_routing_dgm_l $WxCDP
        lappend display_routing_dgm_l $WxCtoCM_dpg
        lappend display_routing_dgm_l $dp_cm_to_wxc
        lappend display_routing_dgm_l $cmtoWxC_dpg_det
        lappend display_routing_dgm_l $pstnDP
        lappend display_routing_dgm_l $wxctocm_dpg_det
        lappend display_routing_dgm_l $dp_cm_to_pstn
        lappend display_routing_dgm_l $ucm_pstn_dpg_det
        lappend display_routing_dgm_l $PSTNvoicedpg
        lappend display_routing_dgm_l $PSTNdpgconfDP
        lappend display_routing_dgm_l $routeip


    } elseif {$type == 4} {
        lappend route_conf_l [encap_list $PSTNvoicedpg "description Route calls to PSTN"]
        lappend route_conf_l [encap_list $PSTNvoicedpg $PSTNdpgconfDP]

        global pstn_info
        set pstn_info {}

        lappend pstn_info $PSTNvoicedpg
        lappend pstn_info $PSTNdpgconfDP
        lappend pstn_info $pstnDP
        lappend pstn_info $SessionTarget
        lappend pstn_info $routeip

    }

    lappend return_route_list $route_conf_l $PSTNvoicedpg

    return $return_route_list
}

proc display_conf {inputList} {

    set space " "
    set acu_dis ""
    set savL {}
    set empty ""
    set exclude_list {"ip address trusted list" "stun" }
    set char91_bracket [format %c 91]
    set jump "\n"

    foreach insideL $inputList {

        set acusp ""

        foreach element_l $insideL {

            set stElement $element_l

            if {[lsearch $savL $stElement] == -1} {
                
                if {[lsearch $insideL $stElement] == 0 } {

                    if {[regexp "ip host.*" $element_l] || [regexp "ip name-server.*" $element_l] || [regexp "crypto pki trustpool import.*" $element_l] || [regexp "ip http client.*" $element_l]} {
                        append acu_dis "\n" $acusp $element_l
                    } else {
                        append acu_dis "\n" $acusp $element_l "\n"
                    }
                    
                } else {
                    append acu_dis $acusp $element_l "\n"
                }
            
            } elseif {[lsearch $savL $stElement] == 1} {
                # Fix the issue when the dp configuration repeates.

                if {[lsearch $exclude_list $stElement] == -1} {
                    # Fix the issue with duplicate "ip address trusted list"
                    append acu_dis $acusp $element_l "\n"  
                }

            }

            append acusp $space

        }

        set savL $insideL
    }

    puts $acu_dis

    return $acu_dis

}

proc get_lgw_ip {mode int} {

    if {$mode == "Testing"} {
        set interfaces_ips "Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0/0   192.168.1.1 YES NVRAM  up                    up      
GigabitEthernet0/0/1   unassigned      YES NVRAM  down                  down    
GigabitEthernet0       unassigned      YES NVRAM  down                  down  "
    } else {
        set interfaces_ips [exec show ip interface brief]
    }

    set reg_line [regexp -line "$int.*up" $interfaces_ips match_line]
    if {$reg_line} {
        set reg_ip [regexp -line "\[0-9\]{1,3}\.\[0-9\]{1,3}\.\[0-9\]{1,3}\.\[0-9\]{1,3}" $match_line match_ip]
        if {$reg_ip} {
            return $match_ip
        } else {return "Your LGW"}
    } else {return "Your LGW"}
}

proc main {mode show_running} {

    puts "*** *** *** Starting WxC Trunk Registration *** *** ***"
    puts "*** *** *** Getting Running Config *** *** ***"

    global conf_created
    global display_list

    global display_routing_dgm_l
    set display_routing_dgm_l {}
    set route_diagram_l {}


    set vtenant_rl {}
    set conf_created {}
    set conf_to_apply {}
    set script_run_flag 0

    if {$mode != "Testing"} {set wait_time 2000} else {set wait_time 50}

    ### Deployment type ###
    set dptype [deployment_type]
    log_add [format {Deployment Type - %s} [supported_deployments_l "required_dp" $dptype]] 0

    if {$dptype != 1000} {
    
        ### WARNING ###
        warning_print $dptype
        set conTDep [force_input [format {Do you want to continue with deployment %s (y/N): } [supported_deployments_l "required_dp" $dptype]] "yN" "" "Invalid option"]

        if {[yN $conTDep]} {
            # check_dns - Moving to main function.
            check_dns $mode
            set regInfoList [inManual $dptype $mode $show_running]
        } else {set dptype 1000}

    }

    switch $dptype {

        1 {
            # Configure Local Gateway with a SIP PSTN trunk

            set enKey [lindex $regInfoList 6]
            set wxcInt [lindex $regInfoList 7]
            set pstnInt [lindex $regInfoList 8]
            set pstnIP_l [lindex $regInfoList 9]

            puts "\n\n\n*** *** *** Configure connectivity and security *** *** ***"
            set consec_conf_l [con_sec_conf $wxcInt $enKey]

            puts "*** *** *** Creating General Config *** *** ***"
            # Adding PSTN IP in general_config function.
            set varsGenCnf [general_config $show_running $pstnIP_l]

            set genList [lindex $varsGenCnf 0]
            set srtpNumber [lindex $varsGenCnf 1]
            set voiceCodec [lindex $varsGenCnf 2]
            set stunNumber [lindex $varsGenCnf 3]
        
            puts "*** *** *** Creating Tenant Config *** *** ***"
            set retListTenant [wxc_tenant_cnf $regInfoList $wxcInt $show_running $srtpNumber $voiceCodec $stunNumber]

            set tenantList [lindex $retListTenant 0]
            set WxC_Dial_Peer [lindex $retListTenant 1]
            lappend vtenant_rl [lindex $retListTenant 3]

            # ADDING ROUTING
            puts "*** *** *** Creating PSTN config *** *** ***"

            set route_config_list [lindex [routecnf $dptype $show_running $pstnIP_l $pstnInt $voiceCodec $WxC_Dial_Peer "" "" "" ""] 0]

            lappend route_diagram_l $display_routing_dgm_l
            
            lappend display_list $consec_conf_l
            lappend display_list $genList
            lappend display_list $tenantList
            lappend display_list $route_config_list
 
            set script_run_flag 1
        }

        2 {
            # Configure Local Gateway with an existing Unified CM environment
            set enKey [lindex $regInfoList 6]
            set wxcInt [lindex $regInfoList 7]
            set pstnInt [lindex $regInfoList 8]
            set pstnIP_l [lindex $regInfoList 9]
            set cucm_int [lindex $regInfoList 10]
            set classURIPat [lindex $regInfoList 11]
            set cumIPs [lindex $regInfoList 12]
            set ipHostConf [lindex $regInfoList 13]
            set TargetSRVdomWx [lindex $regInfoList 14]
            set TargetSRVdomPSTN [lindex $regInfoList 15]

            puts "\n\n\n*** *** *** Configure connectivity and security *** *** ***"
            set consec_conf_l [con_sec_conf $wxcInt $enKey]

            puts "*** *** *** Creating General Config *** *** ***"
            set varsGenCnf [general_config $show_running $pstnIP_l]
        
            set genList [lindex $varsGenCnf 0]
            set srtpNumber [lindex $varsGenCnf 1]
            set voiceCodec [lindex $varsGenCnf 2]
            set stunNumber [lindex $varsGenCnf 3]

            puts "*** *** *** Creating Tenant Config *** *** ***"
            set retListTenant [wxc_tenant_cnf $regInfoList $wxcInt $show_running $srtpNumber $voiceCodec $stunNumber]

            set tenantList [lindex $retListTenant 0]
            set WxC_Dial_Peer [lindex $retListTenant 1]
            lappend vtenant_rl [lindex $retListTenant 3]


            set route_config_list [lindex [routecnf $dptype $show_running $pstnIP_l $pstnInt $voiceCodec $WxC_Dial_Peer $cucm_int $classURIPat $TargetSRVdomWx $TargetSRVdomPSTN] 0] 
            #routecnf {type show_running routeip pstnInt codecNumber WxCDP ucm_int cm_pattern wxtocucm_dom pstntocucm_dom} 

            lappend display_list $consec_conf_l
            lappend display_list $genList
            lappend display_list $tenantList
            lappend display_list $route_config_list
            lappend display_list $ipHostConf

            # Print deployment:
            lappend display_routing_dgm_l $cumIPs
            lappend route_diagram_l $display_routing_dgm_l

            set script_run_flag 1

        }

        3 {
            # Add tenant (only)"
            #puts $regInfoList

            set multi_tenant_list [lindex $regInfoList 0]
            set wxcInt [lindex $regInfoList 1]
            set pstn_dp_dpg [lindex $regInfoList 2]

            puts "\n"
            #puts $multi_tenant_list

            set shrun_st [join $show_running "\n"]

            set srtpNumber [shw_conf_options [findconfig $shrun_st "voice class srtp-crypto" "retlistval"] "voice class srtp-cryto" "voice class tenant"]
            set voiceCodec [shw_conf_options [findconfig $shrun_st "voice class codec" "retlistval"] "voice class codec" "voice class tenant"]
            set stunNumber [shw_conf_options [findconfig $shrun_st "voice class stun-usage" "retlistval"] "voice class stun" "voice class tenant"]

            puts "\n"
            puts [format {The tenant will be created with this config: %s} $srtpNumber]            
            puts [format {The tenant will be created with this config: %s} $voiceCodec]
            puts [format {The tenant will be created with this config: %s} $stunNumber]

            foreach tenant_entry $multi_tenant_list {

                set display_routing_dgm_l {}

                set retListTenant [wxc_tenant_cnf $tenant_entry $wxcInt $show_running $srtpNumber $voiceCodec $stunNumber]           
                
                set WxC_Tenant_Config [lindex $retListTenant 0]

                set WxC_Dial_Peer [lindex $retListTenant 1]
                set WxC_Tenant [lindex $retListTenant 2]
                lappend vtenant_rl [lindex $retListTenant 3]
                
                lappend display_list $WxC_Tenant_Config

                # class_e164_pattern entries_list description
                if {[llength $tenant_entry] >= 7} {
                    set route_list_e164 [class_e164_pattern [lindex $tenant_entry 6] [lindex $tenant_entry 7] $show_running $WxC_Dial_Peer $WxC_Tenant $voiceCodec $pstn_dp_dpg]
                    lappend display_list $route_list_e164 
                } else {
                    if {$pstn_dp_dpg != "_NA_"} {
                        set dp_dest [string map {"voice class" "destination"} $pstn_dp_dpg]
                        lappend display_list [encap_list [encap_list $WxC_Dial_Peer $dp_dest]]
                        lappend display_routing_dgm_l $dp_dest
                    }
                }

                lappend route_diagram_l $display_routing_dgm_l

            }
            
            if {$pstn_dp_dpg !="_NA_"} {
                # Retrieve PSTN information. 
                set dp_pstn [findconfig $show_running [format {%s@%s} $pstn_dp_dpg "dial-peer"] "findPatternConf"]
                set replaced_dp "dial-peer voice"
                set empty ""

                regsub -all " dial-peer" $dp_pstn $replaced_dp rdpDialPeer
                regsub -all " preference \[0-9\]+" $rdpDialPeer $empty pstn_f_dp
                set pstn_dial_peer [format {%s voip} $pstn_f_dp]
                set dp_session_target [findconfig $show_running [format {%s@%s} $pstn_dial_peer "session target"] "findPatternConf"]
                regsub -all " session target ipv4:" $dp_session_target $empty pstn_ip
                #puts $pstn_ip

                global pstn_info
                set pstn_info {}
                lappend pstn_info $pstn_dp_dpg $dp_pstn $pstn_dial_peer $dp_session_target $pstn_ip

            } else {
                global pstn_info
                set pstn_info {}
                lappend pstn_info $pstn_dp_dpg "_NA_" "_NA_" "_NA_" "PSTN"
            }

            set script_run_flag 1

        }  

        4 {

            set multi_tenant_list [lindex $regInfoList 0]
            set enKey [lindex $regInfoList 1]
            set wxcInt [lindex $regInfoList 2]
            set pstnInt [lindex $regInfoList 3]
            set pstnIP_l [lindex $regInfoList 4]

            puts "\n\n\n*** *** *** Configure connectivity and security *** *** ***"
            set consec_conf_l [con_sec_conf $wxcInt $enKey]

            puts "*** *** *** Creating General Config *** *** ***"
            set varsGenCnf [general_config $show_running $pstnIP_l]
        
            set genList [lindex $varsGenCnf 0]
            set srtpNumber [lindex $varsGenCnf 1]
            set voiceCodec [lindex $varsGenCnf 2]
            set stunNumber [lindex $varsGenCnf 3]

            # Security + General config 
            lappend display_list $consec_conf_l
            lappend display_list $genList

            # ADDING ROUTING
            puts "*** *** *** Creating PSTN config *** *** ***"
            set ret_conf [routecnf $dptype $show_running $pstnIP_l $pstnInt $voiceCodec "" "" "" "" ""]          
            set route_config_list [lindex $ret_conf 0]
            set pstn_dp_dpg [lindex $ret_conf 1]

            # Routing config
            lappend display_list $route_config_list
        
            puts "*** *** *** Creating Tenant Config *** *** ***"

            foreach tenant_entry $multi_tenant_list {

                set display_routing_dgm_l {}

                set retListTenant [wxc_tenant_cnf $tenant_entry $wxcInt $show_running $srtpNumber $voiceCodec $stunNumber]           
                
                set WxC_Tenant_Config [lindex $retListTenant 0]

                set WxC_Dial_Peer [lindex $retListTenant 1]
                set WxC_Tenant [lindex $retListTenant 2]
                lappend vtenant_rl [lindex $retListTenant 3]
                
                lappend display_list $WxC_Tenant_Config

                # class_e164_pattern entries_list description
                if {[llength $tenant_entry] >= 7} {
                    set route_list_e164 [class_e164_pattern [lindex $tenant_entry 6] [lindex $tenant_entry 7] $show_running $WxC_Dial_Peer $WxC_Tenant $voiceCodec $pstn_dp_dpg]
                    lappend display_list $route_list_e164 
                } else {
                    lappend display_routing_dgm_l $pstn_dp_dpg
    
                    if {$pstn_dp_dpg != "_NA_"} {
                        set dp_dest [string map {"voice class" "destination"} $pstn_dp_dpg]
                        lappend display_list [encap_list [encap_list $WxC_Dial_Peer $dp_dest]]
                        lappend display_routing_dgm_l $dp_dest
                    }
                    
                }

                lappend route_diagram_l $display_routing_dgm_l

            }

            set script_run_flag 1
            
        }
	    
        5 {
            # Configure Local Gateway with a TDM PSTN trunk
            set enKey [lindex $regInfoList 6]
            set wxcInt [lindex $regInfoList 7]

            puts "\n\n\n*** *** *** Configure connectivity and security *** *** ***"
            set consec_conf_l [con_sec_conf $wxcInt $enKey]

            puts "*** *** *** Creating General Config *** *** ***"
            set varsGenCnf [general_config $show_running $pstnIP_l]

            set genList [lindex $varsGenCnf 0]
            set srtpNumber [lindex $varsGenCnf 1]
            set voiceCodec [lindex $varsGenCnf 2]
            set stunNumber [lindex $varsGenCnf 3]

            puts "*** *** *** Creating Tenant Config *** *** ***"
            set retListTenant [wxc_tenant_cnf $regInfoList $wxcInt $show_running $srtpNumber $voiceCodec $stunNumber]
            lappend vtenant_rl [lindex $retListTenant 3]
            
            set tenantList [lindex $retListTenant 0]
            set WxC_Dial_Peer [lindex $retListTenant 1]

            set lgw_tdm_conf_l [lgw_tdm_run $show_running $wxcInt $WxC_Dial_Peer]

            lappend display_list $consec_conf_l
            lappend display_list $genList
            lappend display_list $tenantList
            lappend display_list $lgw_tdm_conf_l

            set script_run_flag 1
             
        }

        1000 {puts "\n*** *** *** Thanks for using it... Exit! *** *** ***\n"}
	    default {puts "\n*** *** *** Not valid option for input deployment... Exit! *** *** ***"}
    }	

    if {$script_run_flag} {
    
        # Clearing show running config:
        set show_running {}

        puts "\n*** *** *** Displaying config *** *** ***"
        set conf_saved_data ""

        foreach confList $display_list {
            append conf_saved_data [display_conf $confList]
        }
    
        puts "\n*** *** *** *** *** *** *** *** ***"
        set apply_bool 0
        
        if { $mode == "Running"} {
            set apply_bool [force_input "Do you want to apply the config (y/N): " "yN" "" "Invalid option"]
            set apply_bool [yN $apply_bool]
        }

        if {$apply_bool} {
            apply_config $display_list

            after $wait_time
            puts "\n*** *** *** Force WxC tenant registration *** *** ***"   
            apply_config $vtenant_rl

            puts "\n Do not forget to check the config after running the script, if you want to check registration type: show sip-ua register status\n"
            after $wait_time

        }

        after $wait_time
        set svf_bool [force_input "\nDo you want to save the config in a file (y/N): " "yN" "" "Invalid option"]
        set svf_bool [yN $svf_bool]
    
        if {$svf_bool} {
            set fileConfig [time_file "saved_config" "txt"]
            save_file $fileConfig $conf_saved_data
            puts [format {*** *** *** Saving file %s... ... *** *** ***} $fileConfig]
        } else {
            puts "\n*** *** *** No file saved *** *** ***"
        }


        set routedg_b [force_input "\nDo you want to print the routing information (y/N): " "yN" "" "Invalid option"]
        set routedg_b [yN $routedg_b]

        if {$routedg_b} {

            # Gettin cube IP: wxcInt
            set lgw_ip [get_lgw_ip $mode $wxcInt]
            puts "\n\n"
            puts "*** *** *** Displaying Routing information *** *** ***"

            foreach tnt $route_diagram_l {
                print_deployment_routing $dptype $tnt $lgw_ip
            }

        }

        puts "\n\n*** *** *** Finishing script, thanks for using it! *** *** ***\n\n"
    
    }

    global dbg
    if {$dbg} {
        global logFile
        close $logFile
    }

}

proc class_e164_pattern {e164_in description sh_run_l wxc_dp tenant Vcodec pstn_dp_dpg} {

    # List to retrieve configuration
    set e164_routing {}

    log_add [format {fnc: class_e164_pattern - %s - %s - %s - %s - %s - %s} $e164_in $description $wxc_dp $tenant $Vcodec $pstn_dp_dpg] 0

    set voice_e164 [format {%s} [conf_val "voice class e164-pattern-map" "PSTN_IN" $sh_run_l]]  
    
    if {[string length $description] <= 39} {
        set voice_e164_des [format {description %s - %s} $description [string map {"voice class " "WxC "} $tenant]]
    } else {
        set voice_e164_des [format {description %s} $description]
    }

    lappend e164_routing [encap_list $voice_e164 $voice_e164_des]

    set e164_entry [split $e164_in " "]
    
    foreach entry $e164_entry {
        set entList [format {e164 %s} $entry]
        lappend e164_routing [encap_list $voice_e164 $entList] 
    }

    ### DPG CRREATION ###

    set WxCvoicedpg [conf_val "voice class dpg" "WxC" $sh_run_l]
    set WxCdpgconfDP [string map {" voip" ""} [string map {" voice" ""} $wxc_dp]]

    lappend e164_routing [encap_list $WxCvoicedpg [format {description Routing calls to %s} [string map {"voice class " "WxC "} $tenant]]]
    lappend e164_routing [encap_list $WxCvoicedpg $WxCdpgconfDP]
    
    ### CREATING INBOUND PSTN DIALPEER ###
    set dp_incoming_pstn [format {%s voip} [conf_val "dial-peer voice" "PSTN_IN" $sh_run_l]]

    set DialPeerConf {
        "session protocol sipv2"
        "voice-class sip asserted-id pai"
        "dtmf-relay rtp-nte"
        "no vad"
    }

    # ASSIGNING DPGS to DIAL-PEERs ###
    set dp_des_inp [format {description Inbound DP from PSTN for %s} [string map {"voice class " "WxC "} $tenant]]
    set DialPeerConf [linsert $DialPeerConf 0 $dp_des_inp]

    set In_PSTN_DPG [string map {"voice class" "destination"} $WxCvoicedpg]
    set DialPeerConf [linsert $DialPeerConf 3 $In_PSTN_DPG]

    set in_called_e164 [format {incoming called %s} [string map {"voice class " ""} $voice_e164]]
    set DialPeerConf [linsert $DialPeerConf 4 $in_called_e164]

    # ADDING CODEC ON INBOUND DP
    if {$Vcodec != "_NA_"} {
        set DialPeerConf [linsert $DialPeerConf 5 [string map {"voice class" "voice-class"} $Vcodec]]
    }

    foreach item $DialPeerConf {
        lappend e164_routing [encap_list $dp_incoming_pstn $item]
    }

    ### Assinging Destination DPG or DP to WxC Dial-Peer###
    if {$pstn_dp_dpg != "_NA_"} {
        set dp_dest [string map {"voice class" "destination"} $pstn_dp_dpg]
        lappend e164_routing [encap_list $wxc_dp $dp_dest]
    }

    global display_routing_dgm_l
    lappend display_routing_dgm_l $WxCvoicedpg
    lappend display_routing_dgm_l $WxCdpgconfDP
    lappend display_routing_dgm_l $dp_incoming_pstn
    lappend display_routing_dgm_l $in_called_e164
    lappend display_routing_dgm_l $In_PSTN_DPG
    lappend display_routing_dgm_l $voice_e164
    lappend display_routing_dgm_l $voice_e164_des

    if {$pstn_dp_dpg != "_NA_"} {lappend display_routing_dgm_l $dp_dest}
    
    return $e164_routing

}

proc lgw_tdm_run {sh_run wxc_int dp_cm_to_wxc} {

    set lgw_tdm_conf_list {}

    log_add [format {fnc: lgw_tdm_run - %s - %s} $wxc_int $dp_cm_to_wxc] 0

    # voice translation-rule 100 / rule 1 /^\+/ /A2A/ 
    set translation_rule_plus [conf_val "voice translation-rule" "WxC" $sh_run]
    lappend lgw_tdm_conf_list [encap_list $translation_rule_plus "rule 1 /^\\+/ /A2A/"]

    # voice translation-profile 100 / translate called 100
    set translation_rule_profile [conf_val "voice translation-profile" "WxC" $sh_run]
    set translate_called [string map {"voice translation-rule" "translate called"} $translation_rule_plus]
    lappend lgw_tdm_conf_list [encap_list $translation_rule_profile $translate_called]

    # "voice translation-rule 200" / "rule 1 /^/ /A1A/"
    set translation_rule_rule_pstn [conf_val "voice translation-rule" "PSTN" $sh_run]
    lappend lgw_tdm_conf_list [encap_list $translation_rule_rule_pstn "rule 1 /^/ /A1A/"]

    # voice translation-profile 200 / translate called 200
    set translation_rule_profile_pstn [conf_val "voice translation-profile" "PSTN" $sh_run]
    set translate_called_pstn [string map {"voice translation-rule" "translate called"} $translation_rule_rule_pstn]
    lappend lgw_tdm_conf_list [encap_list $translation_rule_profile_pstn $translate_called_pstn]


    # voice translation-rule 11 / rule 1 /^A1A/ //
    set translation_rule_3 [conf_val "voice translation-rule" "TDM_Translation" $sh_run]
    lappend lgw_tdm_conf_list [encap_list $translation_rule_3 "rule 1 /^A1A/ //"]

    # voice translation-profile 11 / translate called 11
    set translation_rule_profile_3 [conf_val "voice translation-profile" "TDM_Translation" $sh_run]
    set translate_called_3 [string map {"voice translation-rule" "translate called"} $translation_rule_3]
    lappend lgw_tdm_conf_list [encap_list $translation_rule_profile_3 $translate_called_3]

    # voice translation-rule 12 
    # rule 1 /^A2A44/ /0/
    # rule 2 /^A2A/ /00/

    set translation_rule_4 [conf_val "voice translation-rule" "TDM_Translation" $sh_run]
    lappend lgw_tdm_conf_list [encap_list $translation_rule_4 "rule 1 /^A2A44/ /0/"]
    lappend lgw_tdm_conf_list [encap_list $translation_rule_4 "rule 2 /^A2A/ /00/"]

    #voice translation-profile 12 / translate called 12 
    set translation_rule_profile_4 [conf_val "voice translation-profile" "TDM_Translation" $sh_run]
    set translate_called_4 [string map {"voice translation-rule" "translate called"} $translation_rule_4]
    lappend lgw_tdm_conf_list [encap_list $translation_rule_profile_4 $translate_called_4]

    # card type e1 0 2 
    # isdn switch-type primary-net5 
    # controller E1 0/2/0 
    # pri-group timeslots 1-31

    lappend lgw_tdm_conf_list [encap_list "card type e1 0 2"]
    lappend lgw_tdm_conf_list [encap_list "isdn switch-type primary-net5"]
    lappend lgw_tdm_conf_list [encap_list "controller E1 0/2/0" "pri-group timeslots 1-31"]


    # dial-peer voice 200 pots 

    set dp_pstn [conf_val "dial-peer voice" "PSTN" $sh_run]
    set dp_pstn_pots [format {%s pots} $dp_pstn]

    # port needs to be provided as an input. 
    set inout_pri_pstn_dp {
        "description Inbound/Outbound PRI PSTN trunk" 
        "destination-pattern BAD.BAD"
        "direct-inward-dial" 
        "port 0/2/0:15"
    }
    # translation-profile incoming 200 
    lappend inout_pri_pstn_dp [string map {"voice translation-profile" "translation-profile incoming"} $translation_rule_profile_pstn]

    foreach dpLine $inout_pri_pstn_dp {
        lappend lgw_tdm_conf_list [encap_list $dp_pstn_pots $dpLine]
    }

    # dial-peer voice 10 voip
    set dp_loop_around [conf_val "dial-peer voice" "TDM" $sh_run]
    set dp_loop_around_vp [format {%s voip} $dp_loop_around]

    set wxc_int_dp_control [format {voice-class sip bind control source-interface %s} $wxc_int]
    set wxc_int_dp_media [format {voice-class sip bind media source-interface %s} $wxc_int]

    set dp_outbound_loop_around {
        "description Outbound loop-around leg"
        "destination-pattern BAD.BAD"
        "session protocol sipv2"
        "session target ipv4:192.168.80.14"
        "dtmf-relay rtp-nte"
        "codec g711alaw"
        "no vad" 
    }
    lappend dp_outbound_loop_around $wxc_int_dp_control
    lappend dp_outbound_loop_around $wxc_int_dp_media

    # Need to get this IP from the GW:
    # set session_target_dp_loop_around [format {session target ipv4:%s} $iploop]

    foreach dpLine $dp_outbound_loop_around {
        lappend lgw_tdm_conf_list [encap_list $dp_loop_around_vp $dpLine]
    }


    # dial-peer voice 11 voip
    set dp_inbound_loop_around [conf_val "dial-peer voice" "TDM" $sh_run]
    set dp_inbound_loop_around_vp [format {%s voip} $dp_inbound_loop_around]

    set dp_inbound_loop_around_to_wxc {
        "description Inbound loop-around leg towards Webex"
        "session protocol sipv2"
        "incoming called-number A1AT"
        "dtmf-relay rtp-nte"
        "codec g711alaw"
        "no vad" 
    }

    # translation-profile incoming 11 / voice translation-profile 11
    lappend dp_inbound_loop_around_to_wxc [string map {"voice translation-profile" "translation-profile incoming"} $translation_rule_profile_3] 
    lappend dp_inbound_loop_around_to_wxc $wxc_int_dp_control
    lappend dp_inbound_loop_around_to_wxc $wxc_int_dp_media

    foreach dpLine $dp_inbound_loop_around_to_wxc {
        lappend lgw_tdm_conf_list [encap_list $dp_inbound_loop_around_vp $dpLine]
    }


    # dial-peer voice 12 voip
    set dp_looparound_pstn [conf_val "dial-peer voice" "TDM" $sh_run]
    set dp_looparound_pstn_vp [format {%s voip} $dp_looparound_pstn]

    set dp_inbound_loop_around_to_pstn {
        "description Inbound loop-around leg towards PSTN"
        "session protocol sipv2"
        "incoming called-number A2AT"
        "dtmf-relay rtp-nte"
        "codec g711alaw" 
        "no vad"
    }

    # translation-profile incoming 12
    lappend dp_inbound_loop_around_to_pstn [string map {"voice translation-profile" "translation-profile incoming"} $translation_rule_profile_4] 
    lappend dp_inbound_loop_around_to_pstn $wxc_int_dp_control
    lappend dp_inbound_loop_around_to_pstn $wxc_int_dp_media

    foreach dpLine $dp_inbound_loop_around_to_pstn {
        lappend lgw_tdm_conf_list [encap_list $dp_looparound_pstn_vp $dpLine]
    }

    # DPG
    #voice class dpg 100
    #description Route calls to Webex Calling
    #dial-peer 100
    
    set dpg_cm_to_wxc [conf_val "voice class dpg" "WxC" $sh_run]
    set dpg_cm_to_wxc_dp [string map {" voip" ""} [string map {" voice" ""} $dp_cm_to_wxc]]

    lappend lgw_tdm_conf_list [encap_list $dpg_cm_to_wxc "description Route calls to Webex Calling"]
    lappend lgw_tdm_conf_list [encap_list $dpg_cm_to_wxc $dpg_cm_to_wxc_dp]

    #voice class dpg 200
    #description Route calls to PSTN
    #dial-peer 200

    set dpg_pstn [conf_val "voice class dpg" "PSTN" $sh_run]
    set dpg_pstn_dp_conf [string map {" pots" ""} [string map {" voice" ""} $dp_pstn_pots]]

    lappend lgw_tdm_conf_list [encap_list $dpg_pstn "description Route calls to PSTN"]
    lappend lgw_tdm_conf_list [encap_list $dpg_pstn $dpg_pstn_dp_conf]


    #voice class dpg 10
    #description Route calls to Loopback
    #dial-peer 10

    #set dpg_route_loopback [conf_val "voice class dpg" "TDM_Translation" $sh_run]
    set dpg_route_loopback [conf_val "voice class dpg" "TDM" $sh_run]
    set dpg_dp_loopback [string map {" voip" ""} [string map {" voice" ""} $dp_loop_around_vp]]

    lappend lgw_tdm_conf_list [encap_list $dpg_route_loopback "description Route calls to Loopback"]
    lappend lgw_tdm_conf_list [encap_list $dpg_route_loopback $dpg_dp_loopback]


    # DIALPEER DESTIONATION TO DPG
    #dial-peer voice 100
    #destination dpg 10
    # $dpg_route_loopback
    lappend lgw_tdm_conf_list [encap_list $dp_cm_to_wxc [string map {"voice class" "destination"} $dpg_route_loopback]]

    #dial-peer voice 200
    #destination dpg 10
    # $dp_pstn - $dp_pstn_pots
    lappend lgw_tdm_conf_list [encap_list $dp_pstn_pots [string map {"voice class" "destination"} $dpg_route_loopback]]
    puts [encap_list $dp_pstn_pots [string map {"voice class" "destination"} $dpg_route_loopback]]
    #dial-peer voice 11
    #destination dpg 100
    lappend lgw_tdm_conf_list [encap_list $dp_inbound_loop_around_vp [string map {"voice class" "destination"} $dpg_cm_to_wxc]]

    #dial-peer voice 12
    #destination dpg 200
    lappend lgw_tdm_conf_list [encap_list $dp_looparound_pstn_vp [string map {"voice class" "destination"} $dpg_pstn]]

    return $lgw_tdm_conf_list

}

proc apply_config {inputConfLists} {
    #EMPTY
    puts "\n\n*** *** *** APPLYING CONFIG *** *** ***\n"

    log_add "*** *** *** APPLYING CONFIG *** *** ***" 0

    foreach confList $inputConfLists {
        foreach config $confList {
            #puts $config
            if {[llength $config] == 1} {
                set command_run [format {+++ Executing ---> %s +++} [lindex $config 0]]
                puts $command_run
                set display_output [ios_config [lindex $config 0]]

                log_add [format {fnc: apply_config - %s} $command_run] 0
                log_add [format {Output - %s%s} $display_output "\n"] 0

            } elseif {[llength $config] == 2} {
                set  command_run [format {+++ Executing ---> %s / %s +++} [lindex $config 0] [lindex $config 1]]
                puts $command_run
                set display_output [ios_config [lindex $config 0] [lindex $config 1]]
                
                log_add [format {fnc: apply_config - %s} $command_run] 0
                log_add [format {Output - %s%s} $display_output "\n"] 0

            } elseif {[llength $config] == 3} {
                set command_run [format {+++ Executing ---> %s / %s / %s +++} [lindex $config 0] [lindex $config 1] [lindex $config 2]]
                puts $command_run
                set display_output [ios_config [lindex $config 0] [lindex $config 1] [lindex $config 2]]

                log_add [format {fnc: apply_config - %s} $command_run] 0
                log_add [format {Output - %s%s} $display_output "\n"] 0

            }
            #after 1500
            puts $display_output

        }      
    }

}


proc fix_sh_L {input} {
    # Converst the sh run to a list. 
    # Carriage Return character
    set outputList {}

    log_add "fnc: fix_sh_L" 0
    
    #puts "\n"
    #puts "*** *** *** fix_sh_L func running *** *** ***"
    
    set cr_ascci [format %c 13]
    set stn ""
    regsub -all $cr_ascci $input $stn shString

    set char10 [format %c 10]
    set splittedList [split $shString $char10]

    set i 0

    return $splittedList

}

proc warning_print {dpType} {

    log_add "fnc: warning_print" 0

    set deployment [supported_deployments_l "required_dp" $dpType]

    puts "\n\n\n*** *** *** IMPORTANT INFORMATION ABOUT THIS DEPLOYMENT *** *** ***\n"
    puts [format {Please consider that the deployment type %d - %s:} $dpType $deployment]

    switch $dpType {
        1 {
            puts "\nIt will create a voice class uri with the PSTN IP for routing the calls from PSTN to WxC"
            puts "If this is an existing CUBE/LGW deployment and you are already using it for another services,"
            puts "setting a voice class uri will take priority and your services can be impacted,"
            puts "If you are receiving calls from the PSTN IP that you provided for the script."
            puts "\nThis is the setting that is added for routing the calls from PSTN to the WxC Tenant (the number 200 could be different)"
            puts "\n voice class uri 200 sip \n  host ipv4:\[Your PSTN IP\]"
            puts "\nIt's added to the dial peer (the number 200 could be different):"
            puts "\n dial-peer voice 200 voip\n  description Inbound/Outbound IP PSTN trunk\n  incoming uri via 200"
            puts "\n\nFor further information about this deployment, please check: "
            puts "https://help.webex.com/en-us/article/jr1i3r/Configure-Local-Gateway-on-Cisco-IOS-XE-for-Webex-Calling#id_100838"
            puts "\nFor further information about Cisco IOS and IOS XE Call Routing, please check: "
            puts "https://www.cisco.com/c/en/us/support/docs/voice/ip-telephony-voice-over-ip-voip/211306-In-Depth-Explanation-of-Cisco-IOS-and-IO.html"
        }

        2 {
            puts "\nIt will create a voice class uri for classifying the calls from CM to Webex (using sip VIA port)"
            puts "Also it will create a voice class uri to classify the calls from the UCM towards the PSTN trunk"
            puts "If this is an existing CUBE/LGW deployment and you are already using it for another services,"
            puts "setting a voice class uri will take priority and your services can be impacted."
            puts "\n\nThis is the voice class uri that is used for identifying the calls from CM to Webex (the number can be different):"
            puts "\nvoice class uri 300 sip\n pattern :5065"
            puts "\nThe voice class uri is assigned to this dial-peer:"
            puts "\n dial-peer voice 300 voip\n  description UCM-Webex Calling trunk\n  incoming uri via 300"
            puts "\n\nThis is the voice class uri that is used for identifying the calls from CM to PSTN (the number can be different)"
            puts "\nvoice class uri 400 sip\n pattern 192\\.168\\.80\\.6\[0-5\]:5060"
            puts "\nThe voice class uri is assigned to this dial-peer:"
            puts "\n dial-peer voice 400 voip\n  description UCM-PSTN trunk\n  incoming uri via 400"
            puts "\n\nFor further information about this deployment, please check: "
            puts "https://help.webex.com/en-us/article/jr1i3r/Configure-Local-Gateway-on-Cisco-IOS-XE-for-Webex-Calling#id_101131"
            puts "\nFor further information about routing on LGW and priorities, please check: "
            puts "https://www.cisco.com/c/en/us/support/docs/voice/ip-telephony-voice-over-ip-voip/211306-In-Depth-Explanation-of-Cisco-IOS-and-IO.html"
        }

        3 {
            puts "\nIt will create a WxC tenant or multiple WxC tenants."
            puts "Use this script if you have already a WxC tenant configuration"
            puts "You have an option to add e164 pattern map routing for each WxC tenant that will be configured to match in an inbound dial-peer"
            puts "\n\nThis is what the script will create to route any number or pattern that you provided for the e164 pattern map:\n"
            puts "\nvoice class e164-pattern-map 201\n description Numbers for voice class tenant 100\n e164 12..$\n e164 1\[2-5\]15369500.$"
            puts "\nThat voice class e164-pattern-map will be associated to a dial-peer as incoming called:"
            puts "\ndial-peer voice 201 voip\n description Inbound DP PSTN for voice class tenant 100\n incoming called e164-pattern-map 201"
            puts "\n\nFor further information about e164 pattern map, please check: "
            puts "https://www.cisco.com/c/en/us/support/docs/voice/ip-telephony-voice-over-ip-voip/211306-In-Depth-Explanation-of-Cisco-IOS-and-IO.html#toc-hId--497013386"
        }

        4 {
            puts "\nIt will create a WxC tenant or multiple WxC tenants, also the complete configuration required for registering the tenants in WxC"
            puts "\nYou have an option to add e164 pattern map routing for each WxC tenant that will be configured to match an inbound dial-peer"
            puts "\n\nThis is what the script will create to route any number or pattern that you provided for the e164 pattern map:\n"
            puts "\nvoice class e164-pattern-map 201\n description Numbers for voice class tenant 100\n e164 12..$\n e164 1\[2-5\]15369500.$"
            puts "\nThat voice class e164-pattern-map will be associated to a dial-peer as incoming called:"
            puts "\ndial-peer voice 201 voip\n description Inbound DP PSTN for voice class tenant 100\n incoming called e164-pattern-map 201"
            puts "\n\nFor further information about e164 pattern map, please check: "
            puts "https://www.cisco.com/c/en/us/support/docs/voice/ip-telephony-voice-over-ip-voip/211306-In-Depth-Explanation-of-Cisco-IOS-and-IO.html#toc-hId--497013386"
        }
    }
    puts "\nBefore the script executes any command, it will display the config and ask whether you want to apply the config or not"
    puts "You have the option to save the config whether you apply the config or not"
    puts "\n*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n"
}

proc cisco_logo {} {

    puts "\n"
    puts " *** *** *** WxC Calling Registration TCL script *** *** ***"
    puts "\n\n"

    set chr "###"
    set con_ini "     "
    set space "     "
    set dspace "  "

    set decimal_list {68 68 68 238 511 511 511 511 68 68}
    
    foreach col $decimal_list {

        set bin_number [dec2bin $col 8]
        set log_append $con_ini

        foreach row [split $bin_number {}] {      
            if {$row == 1} {
                append log_append $chr$dspace
            } else {
                append log_append $space
            }
        }

        puts $log_append
    }

    puts "\n\n"


}

proc check_dns {mode} {

    set loop_var 1
    #puts "*** *** *** DNS CHECKING *** *** ***"

    log_add "fnc: check_dns" 0

    if {$mode == "Testing"} {

        set hosts_output "Default domain is lc.net
Name servers are 255.255.255.255
NAME  TTL  CLASS   TYPE      DATA/ADDRESS
-----------------------------------------"
    } elseif {$mode == "Running"} {
        set hosts_output [exec show hosts]
    }
    
    if { [regexp "Name server.*255.255.255.255" $hosts_output fdns] } {
        set dns_server [force_input "\nThere is no a DNS server configure yet. Please provide the DNS server IP: " "ip" "N/A" "Incorrect IP"]
        set tempList {}
        global display_list
        set dns_command [format {ip name-server %s} $dns_server]
        lappend tempList [encap_list $dns_command]
        lappend display_list $tempList
    } 
}

proc force_input {inputText type criteria errToPrint} {
    
    # This function is created to force the user an input.
    set loop_var 1
    set condition 0

    while {$loop_var} {

        set inToUse [print_in $inputText]

        switch $type {
            ip {set condition [regexp -line "^((25\[0-5\]|2\[0-4\[0-9\]|\[01\]?\[0-9\]\[0-9\]?)\.){3}(25\[0-5\]|2\[0-4\]\[0-9\]|\[01\]?\[0-9\]\[0-9\]?)$" $inToUse]}    
            charac_num {if {[llength [split $inToUse {}]] >= $criteria} {set condition 1}}
            number {if {[regexp -line "\[0-9\]+" $inToUse]} {if {$inToUse <= $criteria && $inToUse > 0} {set condition 1}}}
            yN {if {$inToUse == "y" || $inToUse == "N"} {set condition 1}}
            yNF {if {$inToUse == "y" || $inToUse == "N" || $inToUse == "--debug"} {set condition 1}}
            depType {if {[regexp -line "\[0-9\]+" $inToUse]} {if {$inToUse <= $criteria && $inToUse > 0} {set condition 1}}}
        }

        if {$condition} {
            set loop_var 0
        } else {
            puts "\n"
            puts [format {%s, please try again...} $errToPrint]
            puts "\n\n"
        }

    }

    return $inToUse  

}

proc save_file {fileName data} {

    log_add "fnc: save_file" 0

    set outFile [open $fileName {WRONLY CREAT APPEND}] 		
	puts $outFile $data
	close $outFile

}

proc space {number} {
    set space " "
    set acu_return ""
    set n 0
    while {$n < $number} {
        append acu_return $space
        incr n
    }
    return $acu_return
}

proc print_deployment_routing {dpType list_routing_info lgw_ip}  {
    
    log_add "fnc: print_deployment_routing" 0
    
    set depType4 0

    if {$dpType == 4} {
        set dpType 3
        set depType4 1
    }

    set number_show_diagram 1
    set cnt_diagram 0
    
    set wxc_uri [lindex $list_routing_info 0]
    set wxc_otg  [lindex $list_routing_info 1]
    set wxc_dp [lindex $list_routing_info 2]
    set wxc_dp_incoming_uri [lindex $list_routing_info 3]
    set wxc_srv [lindex $list_routing_info 4]
    set dp_tenant [lindex $list_routing_info 5]

    switch $dpType {
        1 {

            set pstn_dpg [lindex $list_routing_info 6] 
            set pstn_dpg_des [lindex $list_routing_info 7]

            set pstn_voice_class_uri [lindex $list_routing_info 8]
            set pstn_voice_class_uri_conf [lindex $list_routing_info 9]

            set pstn_dial_peer [lindex $list_routing_info 10]
            set pstn_incoming_uri [lindex $list_routing_info 11]
            set pstn_dpg_destination [lindex $list_routing_info 12]
            set pstn_session_target [lindex $list_routing_info 13]
            set pstn_ip [lindex $list_routing_info 14]

            set wxc_dpg [lindex $list_routing_info 15]
            set wxc_dpg_route [lindex $list_routing_info 16]
            set wxc_dp_destination [lindex $list_routing_info 17]

            puts [format {%s*** *** *** Routing diagram for %s *** *** ***} "\n\n" $dp_tenant ]

        }

        2 {
            set number_show_diagram 2
            set cnt_diagram 0

            set pstn_dial_peer [lindex $list_routing_info 6] 
            set pstn_session_target [lindex $list_routing_info 7]
            set ucm_to_wxc_class_uri [lindex $list_routing_info 8] 
            set ucm_to_wxc_class_uri_pattern [lindex $list_routing_info 9]
            set ucm_to_pstn_uri [lindex $list_routing_info 10]
            set ucm_to_pstn_uri_pattern [lindex $list_routing_info 11]

            set dp_ucm_to_wxc [lindex $list_routing_info 12]
            set dp_ucm_to_wxc_in_uri [lindex $list_routing_info 13]
            set dp_ucm_to_wxc_st [lindex $list_routing_info 14]
            set dp_pstn_fr_ucm [lindex $list_routing_info 15]
            set dp_pstn_fr_ucm_st [lindex $list_routing_info 16]
            set dp_pstn_fr_ucm_in_uri [lindex $list_routing_info 17]

            set wxc_dpg [lindex $list_routing_info 18]
            set wxc_dpg_route [lindex $list_routing_info 19]
            
            set ucm_dpg [lindex $list_routing_info 20]
            set ucm_dpg_conf [lindex $list_routing_info 21]

            set pstn_fr_ucm_dpg [lindex $list_routing_info 22]
            set pstn_fr_ucm_dpg_conf [lindex $list_routing_info 23]

            set dp_wxc_dest [lindex $list_routing_info 24]
            set dp_ucm_dest [lindex $list_routing_info 25]
            set dp_pstn_dest [lindex $list_routing_info 26]
            set dp_pstn_fr_ucm_dest [lindex $list_routing_info 27]

            set dp_ucm_to_pstn_des [lindex $list_routing_info 31]

            set pstn_dpg [lindex $list_routing_info 32]
            set pstn_dpg_conf [lindex $list_routing_info 33]

            set pstn_ip [lindex $list_routing_info 34]
            set cucmIPsList [lindex $list_routing_info 35]

            puts [format {%s*** *** *** Routing diagram for %s *** *** ***} "\n\n" $dp_tenant]

            puts "UCM cluster IPs:\n"
            foreach ucmip [split $cucmIPsList ","] {
                puts [format { - %s} $ucmip]
            }

        }

        3 {
            global pstn_info

            #set pstn_ip "PSTN"
            
            set pstn_dpg [lindex $pstn_info 0]
            set pstn_dpg_conf [lindex $pstn_info 1]
            set pstn_dial_peer [lindex $pstn_info 2]
            set pstn_session_target [lindex $pstn_info 3]
            set pstn_ip [lindex $pstn_info 4]

            set dp_destination [string map {"voice class" "destination"} $pstn_dpg]

            # Starting point
            if {[llength $list_routing_info] > [expr 7 + $depType4]} {
                set wxc_dpg [lindex $list_routing_info 6]
                set wxc_dpg_route [lindex $list_routing_info 7]

                set dp_incoming_pstn [lindex $list_routing_info 8] 
                set dp_incoming_conf [lindex $list_routing_info 9]
                set dp_in_called_e164 [lindex $list_routing_info 10]

                set voice_class_e164 [lindex $list_routing_info 11]
                set voice_class_e164_des [lindex $list_routing_info 12]

                #set pstn_dpg_conf [lindex $list_routing_info 13]
                set dp_destination [lindex $list_routing_info 13] 

            }

            puts [format {%s*** *** *** Routing diagram for %s *** *** ***} "\n\n" $dp_tenant ]

        }
        

    }

    set acu ""
    set perimeter_charac "+"
    set initial_space "    "
    set space_between " "

    set row_n 102
    set column 7
    set space_bet_box 17

    puts "\n\n"

    # DIAGRAM
    while {$cnt_diagram < $number_show_diagram} {
        set i 0
        set j 0
        set acu ""

        while {$j < $column} {
            if {$j == 0 || $j == 6} {
                set i 0
                append acu $initial_space
                while {$i <= $row_n} {
                    if {0 <= $i && $i < 11 || 28 < $i && $i <= 39 || 62 < $i && $i <= 73} {
                    append acu $perimeter_charac $space_between
                    } elseif {10 < $i && $i < 27 || 45 < $i && $i < 62} {
                        append acu $space_between 
                    }
                    incr i
                }

            } elseif {$j >= 1 && $j < 2 || $j > 4} {
                set i 0
                while {$i <= $row_n} {
                    if {$i == 4 || $i == 23 || $i == 40 || $i == 59 || $i == 76 || $i == 95} {
                        append acu $perimeter_charac $space_between
                    } else {
                        append acu $space_between
                    }
                    incr i
                }
            } elseif {$j == 3} {
                set i 0
                while {$i <= $row_n} {
                    if {$i == 4 || $i == 21 || $i == 38 || $i == 55 || $i == 72 || $i == 88} {
                        append acu $perimeter_charac $space_between
                    } elseif {$i == 12} {
                        if {$cnt_diagram != 1} {append acu "WxC"} else {append acu "UCM"}
                    } elseif {$i == 46} {
                        append acu "LGW"
                    } elseif {$i == 79} {
                        if {$dpType == 2} {
                        if {$cnt_diagram != 1} {append acu "UCM "} else {append acu "PSTN"}
                        } else {append acu "PSTN"}
                    } else {
                        append acu $space_between
                    }
                    incr i
                }
            } elseif {$j == 2 || $j == 4} {
                set i 0
                if {$j == 4} {set a 1}
                while {$i <= $row_n} {
                    if {$i == 4 || $i == 23 || $i == 40 || $i == 59 || $i == 76 || $i == 95} {
                        append acu $perimeter_charac $space_between
                    } elseif {$i > 23 && $i < 38 || $i > 59 && $i < 74} {
                        if {$j == 4} {
                            if { $i == 24 || $i == 60} {append acu "<"} else {append acu "="}
                        } else {
                            append acu "-"
                        }
                    } elseif {$i == 38 || $i == 74} {
                        if {$j == 4} { 
                            append acu "="
                        } else {
                            append acu ">"
                        }
                    } else {
                        append acu $space_between
                    }
                    incr i
                }
            } elseif {$j == 3} {
                set i 0
                while {$i <= $row_n} {
                    if {$i == 4 || $i == 23 || $i == 40 || $i == 59 || $i == 76 || $i == 95} {
                        append acu $perimeter_charac $space_between
                    } else {
                        append acu $space_between
                    }
                    incr i
                }
            }
            if {$j != 6} {
                append acu "\n"
            }
            incr j
        }

        puts $acu

        # DEPLOYMENT TYPE 2
        if {$dpType == 2} {
            # Deployment 2

            if {$cnt_diagram != 1} {
                # DEPLOYMENT 2 - ADDRESSES
                set spA [expr 41 - [string length $wxc_srv]]
                puts [format {    %s%s%s%s%s} $wxc_srv [space $spA] $lgw_ip [space [expr 79 - [string length $wxc_srv] - [string length $lgw_ip] - $spA]] "UCM"]
            } else {
                # DEPLOYMENT 2 - ADDRESSES
                set spA [expr 41 - [string length "UCM"]]
                puts [format {    %s%s%s%s%s} "UCM" [space $spA] $lgw_ip [space [expr 79 - [string length "UCM"] - [string length $lgw_ip] - $spA]] $pstn_ip]
            }

            #ROUTING DESCRIPTION FOR DEPLOYMENT 2
            if {$cnt_diagram == 0} {
                puts [format {%s%s%s} "\n\n" [space 15] "--------------> Call flow: WxC to UCM -------------->\n"]
                puts [format {    %s%s%s%s} "WxC Inbound DP:" [space 50] "WxC Outbound to UCM:" "\n"]
                puts [format {     %s%s%s} $wxc_uri [space [expr 65 - [string length $wxc_uri]]] $ucm_dpg]
                puts [format {      %s%s%s%s} $wxc_otg [space [expr 65 - [string length $wxc_otg]]] $ucm_dpg_conf "\n"]
                puts [format {     %s%s%s} $wxc_dp [space [expr 65 - [string length $wxc_dp]]] $dp_ucm_to_wxc]
                puts [format {      %s%s%s} $wxc_dp_incoming_uri [space [expr 65 - [string length $wxc_dp_incoming_uri]]] $dp_ucm_to_wxc_st]
                puts [format {      %s} $dp_ucm_dest]
                # PSTN info
                puts [format {%s%s%s} "\n\n" [space 15] "<============== Call flow: UCM to WxC <==============\n"]
                puts [format {    %s%s%s%s} "UCM Inbound DP:" [space 50] "UCM Outbound to WxC:" "\n"]
                puts [format {     %s%s%s} $ucm_to_wxc_class_uri [space [expr 65 - [string length $ucm_to_wxc_class_uri]]] $wxc_dpg]
                puts [format {      %s%s%s%s} $ucm_to_wxc_class_uri_pattern [space [expr 65 - [string length $ucm_to_wxc_class_uri_pattern]]] $wxc_dpg_route "\n"]
    
                puts [format {     %s%s%s} $dp_ucm_to_wxc [space [expr 65 - [string length $dp_ucm_to_wxc]]] $wxc_dp]
                puts [format {      %s%s%s} $dp_ucm_to_wxc_in_uri [space [expr 65 - [string length $dp_ucm_to_wxc_in_uri]]] $dp_tenant]
                puts [format {      %s%s} $dp_pstn_fr_ucm_dest "\n\n"]

            } elseif {$cnt_diagram == 1} {
                puts [format {%s%s%s} "\n\n" [space 15] "--------------> Call flow: UCM to PSTN -------------->\n"]
                puts [format {    %s%s%s%s} "UCM Inbound DP:" [space 50] "UCM Outbound to PSTN:" "\n"]
                puts [format {     %s%s%s} $ucm_to_pstn_uri [space [expr 65 - [string length $ucm_to_pstn_uri]]] $pstn_dpg]
                puts [format {      %s%s%s%s} $ucm_to_pstn_uri_pattern [space [expr 65 - [string length $ucm_to_pstn_uri_pattern]]] $pstn_dpg_conf "\n"]
                puts [format {     %s%s%s} $dp_pstn_fr_ucm [space [expr 65 - [string length $dp_pstn_fr_ucm]]] $pstn_dial_peer]
                puts [format {      %s%s%s} $dp_pstn_fr_ucm_in_uri [space [expr 65 - [string length $dp_pstn_fr_ucm_in_uri]]] $pstn_session_target]
                puts [format {      %s} $dp_ucm_to_pstn_des]

                puts [format {%s%s%s} "\n\n" [space 15] "<============== Call flow: PSTN to UCM <==============\n"]
                puts [format {    %s%s} "You can set this dial-peer to route the calls to UCM from PSTN:" "\n"]
                puts [format {     %s}  $dp_pstn_fr_ucm]
                puts [format {      %s}  $dp_pstn_fr_ucm_st]
            }

        } else {
            # DEPLOYMENTS ADDRESSES FOR DEPLOYMENT TYPE --> 1,3,4
            set spA [expr 41 - [string length $wxc_srv]]
            puts [format {    %s%s%s%s%s} $wxc_srv [space $spA] $lgw_ip [space [expr 79 - [string length $wxc_srv] - [string length $lgw_ip] - $spA]] $pstn_ip]
        }

        incr cnt_diagram

    } 
    
    # DEPLOYMENTS ROUTING DESCRIPTION
    if {$dpType == 1} {
        puts [format {%s%s%s} "\n\n" [space 15] "--------------> Call flow: WxC to PSTN -------------->\n"]
        puts [format {    %s%s%s%s} "WxC Inbound DP:" [space 50] "WxC Outbound to PSTN:" "\n"]
        puts [format {     %s%s%s} $wxc_uri [space [expr 65 - [string length $wxc_uri]]] $pstn_dpg]
        puts [format {      %s%s%s%s} $wxc_otg [space [expr 65 - [string length $wxc_otg]]] $pstn_dpg_des "\n"]
        puts [format {     %s%s%s} $wxc_dp [space [expr 65 - [string length $wxc_dp]]] $pstn_dial_peer]
        puts [format {      %s%s%s} $wxc_dp_incoming_uri [space [expr 65 - [string length $wxc_dp_incoming_uri]]] $pstn_session_target]
        puts [format {      %s} $wxc_dp_destination]
        # PSTN info
        puts [format {%s%s%s} "\n\n" [space 15] "<============== Call flow: PSTN to WxC <==============\n"]
        puts [format {    %s%s%s%s} "PSTN Inbound DP:" [space 50] "PSTN Outbound to WxC:" "\n"]
        puts [format {     %s%s%s} $pstn_voice_class_uri [space [expr 65 - [string length $pstn_voice_class_uri]]] $wxc_dpg]
        puts [format {      %s%s%s%s} $pstn_voice_class_uri_conf [space [expr 65 - [string length $pstn_voice_class_uri_conf]]] $wxc_dpg_route "\n"]
    
        puts [format {     %s%s%s} $pstn_dial_peer [space [expr 65 - [string length $pstn_dial_peer]]] $wxc_dp]
        puts [format {      %s%s%s} $pstn_incoming_uri [space [expr 65 - [string length $pstn_incoming_uri]]] $dp_tenant]
        puts [format {      %s} $pstn_dpg_destination]

    } elseif {$dpType == 3} {

        puts [format {%s%s%s} "\n\n" [space 15] "--------------> Call flow: WxC to PSTN -------------->\n"]

        if {$pstn_dpg != "_NA_"} {
            puts [format {    %s%s%s%s} "WxC Inbound DP:" [space 50] "WxC Outbound to PSTN:" "\n"]
            puts [format {     %s%s%s} $wxc_uri [space [expr 65 - [string length $wxc_uri]]]  $pstn_dpg]
            puts [format {      %s%s%s%s} $wxc_otg [space [expr 65 - [string length $wxc_otg]]] $pstn_dpg_conf "\n"]
            puts [format {     %s%s%s} $wxc_dp [space [expr 65 - [string length $wxc_dp]]] $pstn_dial_peer]
            puts [format {      %s%s%s} $wxc_dp_incoming_uri [space [expr 65 - [string length $wxc_dp_incoming_uri]]] $pstn_session_target]
            puts [format {      %s} $dp_destination]
        } else {
            puts [format {    %s%s%s} "WxC Inbound DP:" [space 50] "WxC Outbound to PSTN:"]
            puts [format {     %s%s%s %s} $wxc_uri [space [expr 65 - [string length $wxc_uri]]] "Add a destination to" $wxc_dp]
            puts [format {     %s%s%s%s} $wxc_otg [space [expr 65 - [string length $wxc_otg]]] "to route the calls to PSTN or the next call leg" "\n"]
            puts [format {     %s} $wxc_dp]
            puts [format {      %s} $wxc_dp_incoming_uri]
        }

        if {[llength $list_routing_info]>[expr 7 + $depType4]} {
            puts [format {%s%s%s} "\n\n" [space 15] "<============== Call flow: PSTN to WxC <==============\n"]
            puts [format {    %s%s%s%s} "PSTN Inbound DP:" [space 50] "PSTN Outbound to WxC:" "\n"]
            puts [format {     %s%s%s} $voice_class_e164 [space [expr 65 - [string length $voice_class_e164]]] $wxc_dpg]
            puts [format {      %s%s%s%s} $voice_class_e164_des [space [expr 65 - [string length $voice_class_e164_des]]] $wxc_dpg_route "\n"]
            puts [format {     %s%s%s} $dp_incoming_pstn [space [expr 65 - [string length $dp_incoming_pstn]]] $wxc_dp]
            puts [format {      %s%s%s} $dp_incoming_conf [space [expr 65 - [string length $dp_incoming_conf]]] $dp_tenant]
            puts [format {      %s} $dp_in_called_e164]
        } else {
            puts [format {%s%s%s} "\n\n" [space 15] "<============== Call flow: PSTN to WxC <==============\n"]
            puts [format {    %s%s} "If you want to route the calls to WxC, from an inbound dp route the calls to this dial-peer:" "\n"]
            puts [format {     %s}  $wxc_dp]
            puts [format {      %s}  $dp_tenant]
            puts [format {      %s} $wxc_srv]
        }

    } 
}

proc time_file {filepre ext} {
    set timeSec [clock seconds]
    set suffixTime [clock format $timeSec -format %m_%d_%y__%H%M]
    set fileName [format {%s-%s.%s} $filepre $suffixTime $ext]
    return $fileName
}

proc howtouse {} {
    puts "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***"
    puts "\nConsideration before running the script:\n"
    puts "The script will create and apply the configuration for registering the CUBE/LGW to Webex Calling."
    puts "Please take a look to the Configure Local Gateway documentation before running the script:\n" 
    puts "   https://help.webex.com/en-us/article/jr1i3r/Configure-Local-Gateway-on-Cisco-IOS-XE-for-Webex-Calling"
    puts "\nPLEASE READ CAREFULLY:"
    puts "Before running the script you MUST install the required licenses, otherwise the script will fail"
    puts "The script won't validate whether your LGW device or firmware is supported or not, so, please refer to the WxC documentation" 
    puts "At the end of the script, the config will be showed, you can decide to run the config or not"
    puts "If you're running the script in an existing environment, be careful with the routing configuration because it could impact your existing environment"
    puts "\nThe script will get the current config to validate the dial-peer number, the tenant number, the voice class uri number in order to avoid modifying the existing config\n"
    puts "Therefore the script must be able to run these commads: "
    puts " show running-config dial-peer"
    puts " show running-config | section include tenant"
    puts " show running-config | section voice class dpg"
    puts " show running-config | section voice class codec"
    puts " show running-config | section voice class stun-usage"
    puts " show running-config | section voice class srtp-crypto"
    puts " show running-config | section voice class uri"
    puts " show running-config | section voice class sip-profiles"
    puts " show running-config | section ip domain"
    puts " show running-config | section voice translation-rule"
    puts " show running-config | section voice translation-profile"
    puts " show running-config | section voice class e164-pattern-map"
    puts "\n"
    puts "If the commands above can't be run, the script will FAIL"
    #puts "The script will create an error file if any issue is found, not all the erros are printed, so please double check the config after running the script"
    puts "\n\nACTIONS BEFORE RUNNING THE SCRIPT: \n\n"
    puts "Please add the following commands before running the script: "
    puts "\nkey config-key password-encrypt YourPassword"
    puts "    password encryption aes"
    puts "\n"
    puts "IF THE SCRIPT FAILS AT THE BEGINNING, CHECK YOUR LICENSES\n"
    puts "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n\n"
    set continue_var [force_input "Do you want to continue (y/N): " "yNF" "" "Invalid option"]

    if {$continue_var == "--debug"} {
        return $continue_var
    } else {return [yN $continue_var]}
}

proc yN {input} {
    
    switch $input {      
        y {return 1}
        N {return 0}
        default {return 0}
    }

}

proc help_print {} {
    set j 1
    puts "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***"
    puts "\nThe script supports these deployments: \n"
    foreach deploy_elem [supported_deployments_l "all_list" 0] {
        if {$j == [llength [supported_deployments_l "all_list" 0]]} {break}
        set toPrint [format {%21d        %s} $j $deploy_elem]
        puts $toPrint
        incr j
    }
    set deploy_list_length [llength [supported_deployments_l "all_list" 0]]
    set dt [force_input "\nWhat deployment do you need help with: " "depType" [expr $deploy_list_length - 1] "Incorrect deployment type"]
    puts "\n\n"

    switch $dt {
    1 { 
        puts [format {*** Deployment type: %s ***} [supported_deployments_l "required_dp" 1]]
        puts "\nThese are the required inputs that the script will require:\n"
        puts "There is no a DNS server configure yet. Please provide the DNS server IP: \[You must provide an IP\]"
        puts "Registrar Domain: \[Provided by Control Hub\]"
        puts "Trunk Group OTG/DTG: \[Provided by Control Hub\]"
        puts "Line/Port: \[Provided by Control Hub\]"
        puts "Outbound Proxy Address: \[Provided by Control Hub\]"
        puts "Username: \[Provided by Control Hub\]"
        puts "Password: \[Provided by Control Hub\]"
        puts "The script will display a list of interfaces and will ask you to provide the WxC interface"
        puts "The script will display a list of interfaces and will ask you to provide the PSTN interface"
        puts "What is the PSTN IP: \[Provided the PST IP\]"
        puts "\n\nThe script will identify if there's a DNS server, it uses the command \[show hosts\] to get the DNS information\n"
        puts "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n\n"
    }

    2 {
        puts [format {*** Deployment type: %s ***} [supported_deployments_l "required_dp" 2]]
        puts "\nThese are the required inputs that the script will require:\n"
        puts "There is no a DNS server configure yet. Please provide the DNS server IP: \[You must provide an IP\]"
        puts "Registrar Domain: \[Provided by Control Hub\]"
        puts "Trunk Group OTG/DTG: \[Provided by Control Hub\]"
        puts "Line/Port: \[Provided by Control Hub\]"
        puts "Outbound Proxy Address: \[Provided by Control Hub\]"
        puts "Username: \[Provided by Control Hub\]"
        puts "Password: \[Provided by Control Hub\]"
        puts "The script will display a list of interfaces and will ask you to provide the WxC interface"
        puts "The script will display a list of interfaces and will ask you to provide the PSTN interface"
        puts "The script will display a list of interfaces and will ask you to provide the CM interface"
        puts "Provide the pattern that is going to be used for identifying calls from UCM towards the PSTN trunk (example: 192\.168\.80\.6\[0-5\]:5060): \[You must put a regex pattern to identify the calls from UCM\]"
        puts "Please provide the call manager IPs (if there are more than one, separate with a comma example: 192.168.0.1,192.168.0.2): \[The UCM IPs\]"
        puts "The configuration guide suggests to create SRV domain and A record for the UCM address, do you want to do this part (y/N)?: \[The config suggest to create a SRV domains for routing calls to UCM\]"
        puts " If the above question is \"N\", the script will prompt these questions:"
        puts "  Please type the SRV domain for the CM trunk where the calls from WxC are going to be sent: "
        puts "  Please type the SRV domain for the CM trunk where the calls from PSTN are going to be sent: "
        puts "What is the PSTN IP: \[Your PSTN IP\]"
        puts "\n\nThe script will identify if there's a DNS server, it uses the command \[show hosts\] to get the DNS information\n"
        puts "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n\n"
    }

    3 {
        puts [format {*** Deployment type: %s ***} [supported_deployments_l "required_dp" 3]]
        puts "\nThese are the required inputs that the script will require:\n"
        puts "There is no a DNS server configure yet. Please provide the DNS server IP: \[You must provide an IP\]"
        puts "How many tenants do you want to add?: \[Number of tenants 1-15\]"
        puts "Do you want to route the WxC tenant numbers with e164-pattern-maps (y/N)?: \[If you typed \"y\", creates the e164 for routing number to the tenant\]"
        puts "Registrar Domain: \[Provided by Control Hub\]"
        puts "Trunk Group OTG/DTG: \[Provided by Control Hub\]"
        puts "Line/Port: \[Provided by Control Hub\]"
        puts "Outbound Proxy Address: \[Provided by Control Hub\]"
        puts "Username: \[Provided by Control Hub\]"
        puts "Password: \[Provided by Control Hub\]"
        puts "If you typed \"y\", the following input will be prompted"
        puts " Please add the number list, each entry separate with a space (example: 1315369500.$ 1\[2-3\]26636120*$ 12..$ ): \[Use a pattern to identify the WxC tenants' numbers\]"
        puts " Add a description on the e164-pattern-map: \[Use this input to identify the voice class e164-pattern-map with the WxC tenant\]"
        puts "\n\nThe script will identify if there's a DNS server, it uses the command \[show hosts\] to get the DNS information"
        puts "The script will validate if the voice class codec, voice class stun-usage and the voice class srtp-crypto were created and use them to complete the tenant config" 
        puts "It will prompt a list if there is more than one voice class created for those configs."
        puts "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n\n"
    }

    4 {
        puts [format {*** Deployment type: %s ***} [supported_deployments_l "required_dp" 3]]
        puts "\nThese are the required inputs that the script will require:\n"
        puts "There is no a DNS server configure yet. Please provide the DNS server IP: \[You must provide an IP\]"
        puts "How many tenants do you want to add?: \[Number of tenants 1-15\]"
        puts "Do you want to route the WxC tenant numbers with e164-pattern-maps (y/N)?: \[If you typed \"y\", creates the e164 for routing number to the tenant\]"
        puts "Registrar Domain: \[Provided by Control Hub\]"
        puts "Trunk Group OTG/DTG: \[Provided by Control Hub\]"
        puts "Line/Port: \[Provided by Control Hub\]"
        puts "Outbound Proxy Address: \[Provided by Control Hub\]"
        puts "Username: \[Provided by Control Hub\]"
        puts "Password: \[Provided by Control Hub\]"
        puts "If you typed \"y\", the following input will be prompted"
        puts " Please add the number list, each entry separate with a space (example: 1315369500.$ 1\[2-3\]26636120*$ 12..$ ): \[Use a pattern to identify the WxC tenants' numbers\]"
        puts " Add a description on the e164-pattern-map: \[Use this input to identify the voice class e164-pattern-map with the WxC tenant\]"
        puts "\n\nThe script will identify if there's a DNS server, it uses the command \[show hosts\] to get the DNS information"
        puts "This deployment type will create the complete config to register the WxC tenant\n"
        puts "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n\n"
    }
    
    }

    set continue [force_input "\n\nDo you want to continue for selecting the deployment type (y/N): " "yN" "" "Invalid option"]
    return $continue
}

proc log_add {log_data rmvTime} {

    global dbg
    global mode
    global logFile
    
    if {$dbg} {

        if {$mode == "Testing"} {
            set timestamp [exec date]
        } else {
            set timestamp [exec sh clock]
            set timestamp "[lindex $timestamp 3] [lindex $timestamp 4] [lindex $timestamp 5] [string trim [lindex $timestamp 0] "*"]"
        }
        if {$rmvTime} {puts $logFile $log_data} else {puts $logFile [format {%s - %s} $timestamp $log_data]}
    }

}

# Log var
set dbg 0

cisco_logo
set convar [howtouse]

if {$convar == "--debug"} {
    set convar 1
    set enable_debugging 1
    set mode "Running"
} else {set enable_debugging 0}

if {$convar} {

    # Validate arguments to define where the script is run 
    if {[llength $argv] == 2 || [llength $argv] == 3} {
        if {[lindex $argv 0] == "-t"} {
            set show_running [read [open [lindex $argv 1]]]
            set shRun_L [split $show_running "\n"]
            set mode "Testing"

            if {[lindex $argv 2] == "-d"} {
                puts "*** *** *** Debugging On *** *** ***"
                set dbg 1
                
                set LogFileName [time_file "wxc_onboard_script_log" "log"]
                set logFile [open $LogFileName {WRONLY CREAT APPEND}] 		
                puts $logFile "+++ This is the error file, it is used for troubleshooting +++\n"

                log_add $mode 0                
                log_add "+++ Show running-config +++\n" 1
                log_add $show_running 0
                log_add "+++ Show running-config +++\n" 1

            }

        } 
    } else {

        if {$enable_debugging} {
            puts "*** *** *** Debugging On *** *** ***"
            global dbg
            set dbg 1

            set LogFileName [time_file "wxc_onboard_script_log" "log"]
            set logFile [open $LogFileName {WRONLY CREAT APPEND}] 		

	        puts $logFile "+++ This is the error file, it is used for troubleshooting +++\n"

            log_add "+++ show version +++\n" 1
            puts [format {Running command: %s} "show version"]
            log_add "Running command: show version\n" 0
            set get_version [exec show version]
            log_add $get_version 0
            log_add "\n+++ show version +++\n" 1

        }

        puts "\n\n*** *** *** Getting show running config *** *** ***\n"
        
        set mode "Running"
        log_add $mode 0
        log_add "*** *** *** Getting show running config *** *** ***" 0 

        #set show_running [exec show running-config]
        set show_running ""
 
        # Optimizing the show_running variable. 
        set show_required_l {
            "show running-config dial-peer"
            "show running-config | section include tenant"
            "show running-config | section voice class dpg"
            "show running-config | section voice class codec"
            "show running-config | section voice class stun-usage"
            "show running-config | section voice class srtp-crypto"
            "show running-config | section voice class uri"
            "show running-config | section voice class sip-profiles"
            "show running-config | section ip domain"
            "show running-config | section voice translation-rule"
            "show running-config | section voice translation-profile"
            "show running-config | section voice class e164-pattern-map"
        }

        log_add "+++ Show running-config +++\n" 1

        foreach sh_cmd $show_required_l {
            puts [format {Running command: %s} $sh_cmd]

            log_add $sh_cmd 0

            set get_cmd [exec $sh_cmd]
            append show_running $get_cmd "\n" 
        }

        log_add $show_running 1
        log_add "+++ Show running-config +++\n" 1

        set shRun_L [fix_sh_L $show_running]

    }

    puts "\n\n"

    set display_list {}
    main $mode $shRun_L

} else {
    puts "\n\n*** *** *** Terminating ... *** *** ***\n"
}

# *** *** *** Created by Luis Cureno - lcureno@cisco.com *** *** ***
