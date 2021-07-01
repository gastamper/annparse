# annparse
Parser to generate affected package lists from CVEs, by checking the CentOS announce mailing lists

# What and why?
This tool was created so that requests from security (Nessus scan results) could be easily translated into package lists 
without having to manually reference the CentOS mailings lists.  Simply plug in an advisory and annparse will provide you a 
list of packages referenced in the advisory.

# How do I use it?
Run `annparse --help` for a complete list of syntax options.

Pass an advisory using the -a flag, and optionally -c to query the CR advisory list.
> $ ./annparse -c -a CESA-2020:4076  
> nss-util nss-util-devel nss-softokn-devel nss-softokn nss-softokn-freebl nss-softokn-freebl-devel nss-tools nss-sysinit nss nss-pkcs11-devel nss-devel nspr nspr-devel

annparse can also be run in --offline mode if using a local cache, so as not to spam the CentOS mailing list servers.  
A local cache is provided in the cache folder, or periodically as part of releases.
