// SSL-Client.c
// As described on http://simplestcodings.blogspot.dk/2010/08/secure-server-client-using-openssl-in-c.html
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <dirent.h>
#include <fcntl.h>
#include <wait.h>

#define FAIL    -1

struct STDINSTDOUT {
	char buffer_in[4096];
	unsigned int offset_in;
	char buffer_out[4096];
	unsigned int offset_out;
};

/**
 * Execute a file, using fork and dup2(pipe)
 * @Param char *name[] = { prog, szbuf, NULL };
 */
int Execute(char **argv) {
	pid_t pid;
	int status;
	int pipefd[2];
	pipe(pipefd);

	/* Set O_NONBLOCK flag for the read end (pfd[0]) of the pipe. */
	if (fcntl(pipefd[0], F_SETFL, O_NONBLOCK) == -1) {
		fprintf(stderr, "Call to fcntl failed.\n");
		exit(1);
	}

	if ((pid = fork()) < 0) { /* fork a child process           */
		fprintf(stderr, "Forking child process failed\n");
		exit(1);
	} else if (pid == 0) { /* for the child process:         */

		close(pipefd[0]);    // close reading end in the child

		dup2(pipefd[1], 1);  // send stdout to the pipe
		dup2(pipefd[1], 2);  // send stderr to the pipe

		close(pipefd[1]);    // this descriptor is no longer needed

		// This replaces my current image, and executes within theese privileges.
		if (execv(*argv, argv) < 0) { /* execute the command  */
			fprintf(stderr, "Executing process %s failed\n", argv[0]);
			exit(-1);
		}

		// Anythere here, will never bee seen.
	} else { /* for the parent:      */
		while (waitpid(-1, &status, 0) != pid) {
#ifdef __DEBUG__
			printf(" I AM  WAITING");
#endif
		}

#ifdef __DEBUG__
		printf("Child exit-status: %d, %d\n", WEXITSTATUS(status), errno);
#endif

		// parent
		char buffer[512];
		bzero(buffer, sizeof(buffer));

		close(pipefd[1]);  // close the write end of the pipe in the parent

		int nread = 0;
		switch (nread = read(pipefd[0], buffer, sizeof(buffer))) {
		case -1: /* Make sure that pipe is empty. */
			if (errno == EAGAIN) {
				printf("Parent: Pipe is empty\n");
				fflush(stdout);
				sleep(1);
			} else { /* Reading from pipe failed. */
				fprintf(stderr, "Parent: Couldn’t read from pipe.\n");
				fflush(stdout);
			}
		case 0: /* Pipe has been closed. */
//          printf("Parent: End of conversation.\n"); break;
		default: /* Received a message from the pipe. */
			strncpy(&(argv[2])[0], buffer, nread); // Remove that annoying trailing newline + fflush.
			break;
		} /* End of switch. */

		return WEXITSTATUS(status);
	}

	return 0; // is ok.
}

/**
 * ExecuteDirectory.
 * Executes the content of a directory (not-recursive). When it encountes an exec, that returns exit(1), then
 * it halts processing, because it signals the claim of responsibility. This can be used, to implement chain-of-responsibilites.
 * @param dir_name The directory, into which, recursively to look for files, to execute (files, containing with +x).
 * @param buffer_in The input buffer, as received from the client.
 * @param buffer_out the result buffer, as the result from the exeuction directory.
 * @param offset the stream-pointer
 * @return none.
 */
static void ExecuteDirectory(const char * dir_name,
		struct STDINSTDOUT * stdinout) {

	DIR * d;

	/* Open the directory specified by "dir_name". */

	d = opendir(dir_name);

	/* Check it was opened. */
	if (!d) {
		fprintf(stderr, "Cannot open directory '%s': %s\n", dir_name,
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	while (1) {
		struct dirent * entry;
		const char * d_name;

		/* "Readdir" gets subsequent entries from "d". */
		entry = readdir(d);
		if (!entry) {
			/* There are no more entries in this directory, so break
			 out of the while loop. */
			break;
		}
		d_name = entry->d_name;

		/* Print the name of the file and directory. */
//#if 0
		/* If you don't want to print the directories, use the
		 following line:, and also - skip the files with a . */

		if (!(entry->d_type & DT_DIR)) {
			if (strncmp(d_name, ".", 1) != 0) {

				char szbuf[512];
				bzero(szbuf, sizeof(szbuf));

				char filename[255];
				bzero(filename, sizeof(filename));
				sprintf(filename, "%s/%s", dir_name, d_name);

#ifdef __DEBUG__
				printf("SERVER EXECUTING FILE: %s/%s\n", dir_name, d_name);
#endif
				char *name[] = { filename, &stdinout->buffer_in[0], szbuf,
				NULL };

				int abort = Execute(name);

				if (strlen(szbuf) > 0) {
					stdinout->offset_out += sprintf(
							&stdinout->buffer_out[stdinout->offset_out],
							"%s\r", szbuf);
				}

				if (abort != 0) {
					break;
				}
			}
		}
	}

//#endif /* 0 */

//		if (entry->d_type & DT_DIR) {
//
//			/* Check that the directory is not "d" or d's parent. */
//
//			if (strcmp(d_name, "..") != 0 && strcmp(d_name, ".") != 0) {
//				int path_length;
//				char path[PATH_MAX];
//
//				path_length = snprintf(path, PATH_MAX, "%s/%s", dir_name,
//						d_name);
//				printf("%s\n", path);
//				if (path_length >= PATH_MAX) {
//					fprintf(stderr, "Path length has got too long.\n");
//					exit(EXIT_FAILURE);
//				}
//
//				/* Recursively call "list_dir" with the new path. */
//				ExecuteDirectory(path, buffer_in, buffer_out, offset);
//			}
//		}

	/* After going through all the entries, close the directory. */
	if (closedir(d)) {
		fprintf(stderr, "Could not close '%s': %s\n", dir_name,
				strerror(errno));
		exit(EXIT_FAILURE);

	}
}

/**
 * OpenListener
 * @param port the port to listen to.
 * @return int 0 , -1 for failure.
 */
int OpenListener(int port) {
	int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);

	int yes = 1;
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		perror("setsockopt");
	}

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(sd, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
		perror("can't bind port");
		return -1;
	}
	if (listen(sd, 10) != 0) {
		perror("Can't configure listening port");
		return -1;
	}
	return sd;
}

/**
 * isRoot
 * Determine if w'ere root or not.
 * @return int 0 / 1
 */
int isRoot() {
	if (getuid() != 0) {
		return 0;
	} else {
		return 1;
	}

}
SSL_CTX* InitServerCTX(void) {
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	OpenSSL_add_all_algorithms(); /* load & register all cryptos, etc. */
	SSL_load_error_strings(); /* load all error messages */
	method = SSLv23_server_method(); /* create new server-method instance */
	ctx = SSL_CTX_new(method); /* create new context from method */
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

int LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {
	/* set the local certificate from CertFile */
	if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	/* verify private key */
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the public certificate\n");
		return -1;
	}

	return 0;
}

/**
 * ShowCerts
 * Show the certificate information, but only if debug.
 * @param SSL*
 * @param copyoutbuffer* the resulting output buffer, to input certificate information into.
 * @return void
 */
void ShowCerts(SSL* ssl, struct STDINSTDOUT * stdinstdout) {
	X509 *cert;
	char *line;

	/* Get certificates (if available) */
	cert = SSL_get_peer_certificate(ssl);

	/* But only if present */
	if (cert != NULL) {
#ifdef __DEBUG__
		printf("Peer certificates:\n");
#endif
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		stdinstdout->offset_in += sprintf(
				&stdinstdout->buffer_in[stdinstdout->offset_in],
				"Subject:%s\r\n", line);

#ifdef __DEBUG__
		printf("Subject: %s\n", line);
#endif
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		stdinstdout->offset_in += sprintf(
				&stdinstdout->buffer_in[stdinstdout->offset_in],
				"Issuer:%s\r\n", line);

#ifdef __DEBUG__
		printf("Issuer: %s\n", line);
#endif
		free(line);

		// calculate & print fingerprint
		const EVP_MD * digest;
		unsigned char md[EVP_MAX_MD_SIZE];
		unsigned int n;
		int pos;

		digest = EVP_get_digestbyname("sha1");
		X509_digest(cert, digest, md, &n);

		stdinstdout->offset_in += sprintf(
				&stdinstdout->buffer_in[stdinstdout->offset_in],
				"Fingerprint:");
		for (pos = 0; pos < 19; pos++)
			stdinstdout->offset_in += sprintf(
					&stdinstdout->buffer_in[stdinstdout->offset_in], "%02x:",
					md[pos]);

		stdinstdout->offset_in += sprintf(
				&stdinstdout->buffer_in[stdinstdout->offset_in], "%02x\r\n",
				md[19]);

		X509_free(cert);
	} else
		printf("No certificates.\n");
}

/**
 * int allways_true_callback.
 * A method, to avoid CA validation of the supplied certificate.
 * This is higly discouraged in production. Use a intermediate CA.
 */
static int always_true_callback(X509_STORE_CTX *ctx, void *arg) {
	return 1;
}

int main(int argc, char *argv[]) {

// Make sure we're root.
//    if (!isRoot()) {
//        printf("This program must be run as root/sudo user\n");
//        exit(0);
//    }

	int server, c, index, skipvalidate = 0;
	char *hostname = "localhost", *portnum = "5001",
			*directory = "/etc/ether.d", *crt = "mycrt.pem", *authority =
					"myca.pem";

	// Our stdinstdout-struct.
	struct STDINSTDOUT tt = { .buffer_in = { 0 }, .buffer_out = { 0 },
			.offset_in = 0, .offset_out = 0 };

	while ((c = getopt(argc, argv, "h:p:d:c:a:n")) != -1)
		switch (c) {
		case 'h':
			hostname = optarg;
			break;
		case 'p':
			portnum = optarg;
			break;
		case 'd':
			directory = optarg;
			break;
		case 'c':
			crt = optarg;
			break;
		case 'a':
			authority = optarg;
			break;
		case 'n':
			skipvalidate = 1;
			break;
		case '?':
			if (optopt == 'c')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else if (isprint(optopt))
				fprintf(stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			return 1;
		default:
			abort();
		}

#ifdef __DEBUG__
	printf(
			"-h(ost) = %s, -p(ort) = %s, -d(irectory) = %s, -c(ertificate-bundle) = %s, -a(uthority) = %s, -n(o CA validation) = %d\n",
			hostname, portnum, directory, crt, authority, skipvalidate);
#endif

	for (index = optind; index < argc; index++) {
		printf("Non-option argument %s\n", argv[index]);
		return 0;
	}

	SSL_CTX *ctx;

	SSL_library_init();
	ctx = InitServerCTX(); /* initialize SSL */

	/* Load certs */
	if (-1 == LoadCertificates(ctx, crt, crt)) {
		printf("error: Could not load certificates, %s, key: %s\n", crt, crt);
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, NULL);
	SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1|SSL_OP_NO_SSLv3|SSL_OP_NO_SSLv2);
	if (1 != SSL_CTX_load_verify_locations(ctx, authority, NULL)) {
		printf("error: Could not load authority from file %s\n", authority);
	}

// Should we skip CA-validation?
	if (skipvalidate == 1)
		SSL_CTX_set_cert_verify_callback(ctx, always_true_callback, NULL);

	; /* create server socket */
	if (-1 == (server = OpenListener(atoi(portnum)))) {
		printf("error: Could not connect, to %s:%d\n", hostname, atoi(portnum));
		exit(EXIT_FAILURE);
	}

	while (1) {
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);
		SSL *ssl;

		int client = accept(server, (struct sockaddr*) &addr, &len); /* accept connection as usual */

#ifdef __DEBUG__
		printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr),
				ntohs(addr.sin_port));
#endif

		pid_t pid;
		int status;

		/*
		 * Here we fork, lets party!
		 */
		pid = fork();
		if (pid < 0) {
			perror("Error forking");
		} else if (pid == 0) {

			// we're child
			close(server);

			// ssl
			ssl = SSL_new(ctx); /* get new SSL state with context */
			SSL_set_fd(ssl, client); /* set connection socket to SSL state */

			unsigned int sd = 0;

			if (SSL_accept(ssl) == FAIL) /* do SSL-protocol accept */

				ERR_print_errors_fp(stderr);

			else {

				ShowCerts(ssl, &tt); /* get any certificates */

				tt.offset_in += SSL_read(ssl, &tt.buffer_in[tt.offset_in],
						sizeof(tt.buffer_in) - tt.offset_in); /* get request */

				if (tt.offset_in > 0) {

#ifdef __DEBUG__
					printf("Received message:\n%s\n", tt.buffer_in);
#endif
					// Arg, blocking!
					ExecuteDirectory(directory, &tt);

					/** The reason, we send a single byte, if
					 * no scripts executed, is to signal an healthy SSL-connection
					 */
					unsigned int bytes = 0;
					if (tt.offset_out > 0) {
						bytes = SSL_write(ssl, &(tt.buffer_out[0]),
								tt.offset_out); /* encrypt & send message */
					} else {
						SSL_write(ssl, "\0", 1); /* encrypt & send message */
					}
#ifdef __DEBUG__
					if (tt.offset_out > 0)
						printf("Output length: %zu, bytes sent: %d, value: %s\n",
								strlen(tt.buffer_out), bytes, tt.buffer_out);
					else
						printf("Output length: %zu, bytes sent: %d\n",
								strlen(tt.buffer_out), bytes);
#endif
				} else
					ERR_print_errors_fp(stderr);
			}
			sd = SSL_get_fd(ssl); /* get socket connection */
			SSL_free(ssl); /* release SSL state */
			close(sd); /* close connection */
			exit(0);
		} else if (pid > 0) {

			close(client);

			// We skip waiting, and let accept do the block. Fork, a SSL-server off,
			// everytime, and/or do some process-accounting here.
			// while (wait(&status) != pid)
			//	;
		}

		/*
		 * to here
		 */
	}
	close(server); /* close server socket */
	SSL_CTX_free(ctx); /* release context */

	// Make sure, we play nice with other programs.
	if (tt.offset_in > 1)
		exit(EXIT_SUCCESS);
	else
		exit(EXIT_FAILURE);
}

