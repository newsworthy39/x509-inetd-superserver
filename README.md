# x509-inetd-superserver (openssl)

The x509 inetd-like superserver. The inetd-superserver, takes simple init-style sysv-scripts, and executes them, outputting any result via echo, printf back to the client. Since its a TLS-1.2 (tls1.1-compatible) TCP server, listening on a specific-port, you may use whatever protocol as you see fint.

# CA-authority.
Currently, the ssl_ctx_cert_verify_callback  (https://www.openssl.org/docs/ssl/SSL_CTX_set_cert_verify_callback.html) returns true, to allow the passing of

a) SNI Certificate serial to userspace, and b) X509-subject line, to userspace in a free-floating newline, terminated key-value-pair, as demonstrated below:

Subject: CN=/me/Organization=testing.../\n
Serial: <a very long serial>
SHA1-fingerprint: <a long hex-fingerprint>

, because that ssl-handshake mechanism RFC stipulates, that SSL_CTX_set_verify (https://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html), is required to be SSL_VERIFY_PEER, before requesting client-certificate for authentication.

You may alter, the callback, to revert to default functionality, to traverse the SSL-CA-chain, by using the default-behavior and requiring a common CA-authority.

# Arguments:
 -h(ost, default= "0.0.0.0"),
 
 -p(ort, default="5001"),
 
 -d(irectory to look for scripts, to execute when called, multiple directories delimited by ':', optional)
 
 -f(iles to execute when called, multiple files delimited by ':', optional)
 
 -c(ertificate X509 pki-bundle, default="mycrt.pem")  
 
 -m(ax clients to serve at the same time, default 5)
 
 -u(serid, default=65534),
 
 -g(roupid, default=65534)
 
# Scripts and/or programs exit-codes and execution halting.
  A note on execution-control of scripts and/or programs. When using the -f flag, the entire list is seen as one. If the first script return exit(>0) then
 it aborts the execution of the others. This can be used, to signal ownership.
 
 Similarly, when using multiple-directories, almost the same applies. Several directories may be used, however when a file inside a directory, signals ownership
 the server skips forward to next directory and processes this.  
   
 This software, comes with a client-side X509-implementation, using the above arguments, with a hostname. 
 https://github.com/newsworthy39/X509-inetd-client

# Compile:
 git clone https://github.com/newsworthy39/x509-inetd-superserver
 
 cd X509-inetd-superserver
 
 RELEASE="Release"
 
 cd $RELEASE && make
 
# Certificate authority
 .. 
 
# Launch example
 
 x509-inetd-server -c ${project_loc}/certs/mycert.pem -f ${project_loc}/ether.d/authorization -d ${project_loc}/ether.d/facts -m 8
 
 
