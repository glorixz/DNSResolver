A simplified DNS resolver with caching and cname support.

Run with the following: 
DNSLookupService <rootDNS> {-p1}

<rootDNS> is the IP of the server you want to begin the query at, in dotted form.
{-p1} is an optional flag that disables recursion so that only one query is sent per lookup.
A manual walk-through of a querying process is possible by changing the root server at each iteration. 


Shell commands: 

  - quit|exit
  - server <servername>: Changes the DNS server that future queries will start at
  - trace <on|off>: Turns verbose tracing on or off. If tracing is on, the program prints a 
    trace of all the queries made and responses received before printing any result.
  - lookup|l <hostname> [type]: Looks up a specific host name (with an optional record type, default A) and 
    prints the resulting IP address. The result may be obtained from a local cache, 
	in which case no tracing is printed.
  - dump: Prints all currently cached host names and records.