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
 -d(irectory to look for scripts, to execute when called, default="/etc/ether.d")
 -c(ertificate X509 pki-bundle, default="mycrt.pem")  
 -n(o CA validation, default off)
 
   
 This software, comes with a client-side X509-implementation, using the above arguments, with a hostname. 
 https://github.com/newsworthy39/X509-inetd-client

# compile:
# compile
 git clone https://github.com/newsworthy39/x509-inetd-superserver
 cd X509-inetd-client
 RELEASE="Release"
 cd $RELEASE && make
