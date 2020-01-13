# annparse
 Parser to generate yum update commands from the CentOS announce mailing lists

# What and why?
This tool was created so that requests from security (Nessus scans, generally) could be easily translated into package lists 
without having to manually reference the CentOS mailings lists.  Simply plug in an advisory (and optionally, a year) and 
annparse will provide you a list of packages referenced in the advisory.

# Limitations
* Presently only checks x86_64 but could be easily expanded to support other architectures/SRPMs/whatever else is included 
in release emails.
* Requires manually passing year for older releases.

# How do I use it?
Just passs an advisory, and optionally a year, and annparse will provide you the `yum update` command to run:
> $annparse -a CESA-2019:1619 -y 2019  
> [2020-01-13T15:36:21Z INFO  annparse] yum update vim-filesystem vim-minimal vim-enhanced vim-common vim-X11

You can also run it against the CR repository, in which case commands to enable/disable the repository will be included:
>$ annparse -c -a CEBA-2013:0576 -y 2013  
>[2020-01-13T15:43:11Z INFO  annparse] yum-config-mgr --enablerepo=cr; yum update piranha; yum-config-mgr --disablerepo=cr
