# annparse
Parser to generate yum update commands from the CentOS announce mailing lists

# What and why?
This tool was created so that requests from security (Nessus scans, generally) could be easily translated into package lists 
without having to manually reference the CentOS mailings lists.  Simply plug in an advisory and annparse will provide you a 
list of packages referenced in the advisory.

# Limitations
* Presently only checks x86_64 but could be easily expanded to support other architectures/SRPMs/whatever else is included 
in release emails.
* Requires manually passing year for older releases.

# How do I use it?
Run `annparse --help` for a complete list of syntax options.

Alternatively there are two basic modes of operation: by advisory or by URL.  Most users will use advisory mode:
> $ target/debug/annparse -c -a CESA-2020:4076  
> nss-util nss-util-devel nss-softokn-devel nss-softokn nss-softokn-freebl nss-softokn-freebl-devel nss-tools nss-sysinit nss nss-pkcs11-devel nss-devel nspr nspr-devel

URL mode takes the URL of a specific mailing list entry and provides the affected packages:
> $ target/debug/annparse -u https://lists.centos.org/pipermail/centos-cr-announce/2020-November/012868.html  
> URL: https://lists.centos.org/pipermail/centos-cr-announce/2020-November/012868.html  
> firefox
