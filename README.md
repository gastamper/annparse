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

Pass an advisory using the -a flag, and optionally -c to query the CR advisory list.
> $ ./annparse -c -a CESA-2020:4076  
> nss-util nss-util-devel nss-softokn-devel nss-softokn nss-softokn-freebl nss-softokn-freebl-devel nss-tools nss-sysinit nss nss-pkcs11-devel nss-devel nspr nspr-devel

annparse can also be run in --offline mode if you build a local cache, so as not to spam the CentOS mailing list servers.
