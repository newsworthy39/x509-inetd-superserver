// x509-inetd-server.c
// As described on http://simplestcodings.blogspot.dk/2010/08/secure-server-client-using-openssl-in-c.html
// the server is meant to update a shared resource (ie, db, or other storage mechanism) to reflect the changes
// of its clients, and have support-mechanisms, react to this event.
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

// Used, when controlling output from children to do IPC.
#define FORKOK 0
#define FORKOKSHARE 2
#define FORKEXITABORT 1

struct STDINSTDOUT {
	char buffer_in[4096];
	unsigned int offset_in;
	char buffer_out[4096];
	unsigned int offset_out;
};

char hostname[256] = { "localhost" }, portnum[8] = { "5001" }, directory[256] =
		{ 0 }, files[256] = { 0 }, crt[256] = { "mycrt.pem" }, authority[256] =
		{ 0 };

// default is to use nobody when forking.
unsigned int children = 0, maxchildren = 5, uid = 65534, gid = 65534;

/**
 * Execute a file, using fork and dup2(pipe)
 * @Param char *name[] = { prog, szbuf, NULL };
 */
int execute(const char **argv) {
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
			printf("The child-process is waiting.\n");
#endif
		}

#ifdef __DEBUG__
		printf("Child exit-status: %d, %d\n", WEXITSTATUS(status), errno);
#endif

		// parent
		char buffer[4096];
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
			break;
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
 * Check for the existance of a file.
 */
int fileExists(const char *fname) {
	FILE *file;
	if ((file = fopen(fname, "r"))) {
		fclose(file);
		return 1;
	}
	return 0;
}

/**
 * executeFile.
 * Executes a file
 * it halts processing, because it signals the claim of responsibility. This can be used, to implement chain-of-responsibilites.
 * @param fqdn The file, to run ( files should be marked with +x).
 * @param struct STDINSTDOUT * stdinout The input buffer, as received from the client.
 * @return int if not.
 */
int executeFile(const char * filename, struct STDINSTDOUT * stdinout) {

	char * token, *rest = filename;

	while ((token = strtok_r(rest, ":,", &rest))) {

#ifdef __DEBUG__
		printf("SERVER EXECUTING FILE: %s\n", token);
#endif

		char szbuf[4096];
		bzero(szbuf, sizeof(szbuf));

		const char *name[] = { token, &stdinout->buffer_in[0], szbuf,
		NULL };

		int exit_signal = execute(name);
		switch (exit_signal) {

		// all is well, but output are to be put in inputbuffer.
		case FORKOKSHARE: {

			if (strlen(szbuf) > 0) {
				// lets copy it into the input-buffer, allowing us to 'share' it
				// with the others.
				stdinout->offset_in += sprintf(
						&stdinout->buffer_in[stdinout->offset_in], "%s", szbuf);
			}

		}
			break;

			// All is not well. Abort execution, output into outputbuffer and send to client
		case FORKEXITABORT: {
			if (strlen(szbuf) > 0) {
				stdinout->offset_out += sprintf(
						&stdinout->buffer_out[stdinout->offset_out], "%s",
						szbuf);
			}

			return FORKEXITABORT;

		}
			break;

			// All is well, copy output to outputbuffer.
		default: {
			if (strlen(szbuf) > 0) {
				stdinout->offset_out += sprintf(
						&stdinout->buffer_out[stdinout->offset_out], "%s",
						szbuf);

			}

		}

			break;
		}

		if (token == NULL) {
			return FORKOK;
		}
	}

	return 0;

}

/**
 * ExecuteDirectory.
 * Executes the content of a directory (not-recursive). When it encountes an exec, that returns exit(1), then
 * it halts processing, because it signals the claim of responsibility. This can be used, to implement chain-of-responsibilites.
 * @param dir_name The directory, into which, recursively to look for files, to execute (files, containing with +x).
 * @param struct STDINSTDOUT * stdinout The input/output struct,
 * @return none.
 */
void executeDirectory(const char * dir_name, struct STDINSTDOUT * stdinout) {

	DIR * d;

	/* Open the directory specified by "dir_name". */

	d = opendir(dir_name);

	/* Check it was opened. */
	if (!d) {
		fprintf(stderr, "Cannot open directory '%s': %s\n", dir_name,
				strerror(errno));
		return;
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

				char filename[255];
				bzero(filename, sizeof(filename));
				sprintf(filename, "%s/%s", dir_name, d_name);

				int abort = executeFile(filename, stdinout);

				if (abort == FORKEXITABORT) {
					break;
				}

			}
		}
	}

	/* After going through all the entries, close the directory. */
	if (closedir(d)) {
		fprintf(stderr, "Could not close '%s': %s\n", dir_name,
				strerror(errno));
		exit(EXIT_FAILURE);

	}
}

/**
 * ExecuteDirectory.
 * Executes the content of a directory (not-recursive). When it encountes an exec, that returns exit(1), then
 * it halts processing, because it signals the claim of responsibility. This can be used, to implement chain-of-responsibilites.
 * @param dir_name The directory, into which, recursively to look for files, to execute (files, containing with +x).
 * @param struct STDINSTDOUT * stdinout The input/output struct,
 * @return none.
 */
int executeDirectoryRecursive(const char * dir_name,
		struct STDINSTDOUT * stdinout) {

	DIR * d;

	/* Open the directory specified by "dir_name". */

	d = opendir(dir_name);

	/* Check it was opened. */
	if (!d) {
		fprintf(stderr, "Cannot open directory '%s': %s\n", dir_name,
				strerror(errno));
		return -1;
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

		/* If you don't want to print the directories, use the
		 following line:, and also - skip the files with a . */
		if (!(entry->d_type & DT_DIR)) {
			if (strncmp(d_name, ".", 1) != 0) {

				char filename[255];
				bzero(filename, sizeof(filename));
				sprintf(filename, "%s/%s", dir_name, d_name);

				int abort = executeFile(filename, stdinout);

				if (abort == FORKEXITABORT) {
#ifdef __DEBUG__
					printf("Child exited with abort-code.\n");
#endif
					return abort;
				}

			}
		}

		if (entry->d_type & DT_DIR) {

			/* Check that the directory is not "d" or d's parent. */

			if (strcmp(d_name, "..") != 0 && strcmp(d_name, ".") != 0) {
				int path_length;
				char path[PATH_MAX];

				path_length = snprintf(path, PATH_MAX, "%s/%s", dir_name,
						d_name);
				printf("%s\n", path);
				if (path_length >= PATH_MAX) {
					fprintf(stderr, "Path length has got too long.\n");
					exit(EXIT_FAILURE);
				}

				/* Recursively call "list_dir" with the new path. */
				executeDirectoryRecursive(path, stdinout);
			}
		}

		/* After going through all the entries, close the directory. */
//		if (closedir(d)) {
//			fprintf(stderr, "Could not close '%s': %s\n", dir_name,
//					strerror(errno));
//			exit(EXIT_FAILURE);
//
//		}
	}

	return FORKOK;
}

/**
 * OpenListener
 * @param port the port to listen to.
 * @return int 0 , -1 for failure.
 */
int openListener(int port) {
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
	if (listen(sd, 768) != 0) {
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
SSL_CTX* initServerCTX(void) {
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

int loadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {
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
void showCerts(SSL* ssl, struct STDINSTDOUT * stdinstdout) {
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
				&stdinstdout->buffer_in[stdinstdout->offset_in], "Subject:%s\n",
				line);

#ifdef __DEBUG__
		printf("Subject: %s\n", line);
#endif
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		stdinstdout->offset_in += sprintf(
				&stdinstdout->buffer_in[stdinstdout->offset_in], "Issuer:%s\n",
				line);

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
				&stdinstdout->buffer_in[stdinstdout->offset_in], "%02x",
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
static int alwaysTrueCallback(X509_STORE_CTX *ctx, void *arg) {
	return 1;
}

/**
 * Reap children, and fill up the pool, by decrementing the children.
 * The main while(1) .. sleep .. for, will fill up the missing.
 */
void sigchldHandler(int signum) {

	int status;

	while (waitpid(-1, &status, WNOHANG) > 0)
		;

	children--;
}

/*
 * Setup signals
 */
void setupSignals(void) {
	struct sigaction sa;
	void alarm_handler(int signum), no_client(int signum), sigchld_handler(
			int signum);

	sigfillset(&sa.sa_mask); /****  Take care of signals.  ****/
	sa.sa_flags = 0;

	sa.sa_handler = sigchldHandler;
	sigaction(SIGCHLD, &sa, NULL);
}

/**
 * make_new_child.
 * Creates a new child, with a copy of the SSL-context.
 */
void forkChild(SSL_CTX * ctx, int server) {
	pid_t pid;

	/*
	 * Here we fork, lets party!
	 */
	pid = fork();

	if (pid < 0) {
		perror("Error forking");
	} else if (pid == 0) {

		unsigned int requestsServed = 0;

		int status = setuid(uid);
#ifdef __DEBUG__
		printf("Result of fork/exec setuid is %d, %s\n", status,
				strerror(errno));
#endif

		// we're child. We own the server.
		while (requestsServed++ < 1000) {

			struct sockaddr_in addr;
			socklen_t len = sizeof(addr);

			int client = accept(server, (struct sockaddr*) &addr, &len); /* accept connection as usual */

#ifdef __DEBUG__
			printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr),
					ntohs(addr.sin_port));
#endif
			SSL *ssl;

			// Our stdinstdout-struct.
			struct STDINSTDOUT tt = { .buffer_in = { 0 }, .buffer_out = { 0 },
					.offset_in = 0, .offset_out = 0 };

			// Lets geet cooking, on SSL.
			ssl = SSL_new(ctx); /* get new SSL state with context */
			SSL_set_fd(ssl, client); /* set connection socket to SSL state */

			unsigned int sd = 0;

			if (SSL_accept(ssl) == FAIL) /* do SSL-protocol accept */
				ERR_print_errors_fp(stderr);

			else {

				tt.offset_in += SSL_read(ssl, &tt.buffer_in[tt.offset_in],
						sizeof(tt.buffer_in)); /* get request */

#ifdef __DEBUG__
				printf("X509-inetd-superserver message:\n%s, bytes: %d \n",
						tt.buffer_in, tt.offset_in);
#endif

				/*
				 * We have a special case, into which a nullbyte is sent.
				 * This is received, and we treat the request anyways.
				 * This allows me, to create a know status on the client-side,
				 * if the ssl-ca-handshake was ssuccessful or not, easily.
				 */
				if (tt.offset_in == 1) {
					tt.offset_in = 0;
				}

				showCerts(ssl, &tt); /* get any certificates */

				if (tt.offset_in > 0) {

					/**
					 * A) Run file. The same principles apply, abort if child exits(>0)
					 * B) Blocking, thus we use prefork.
					 * C) Multiple-files
					 * D) The flag can be omitted, then we skip them entirely.
					 */
					int abort = 0;
					if (strlen(files) > 0) {
						abort = executeFile(files, &tt);
					}

					/**
					 * A) Run through directories.
					 * B) Blocking, thus we use prefork.
					 * C) Multiple-directories.
					 * D) The flag can be omitted, then we skip it entirely.
					 */
					if (strlen(directory) > 0 && abort == 0) {

#ifdef __DEBUG__
						printf("Splitting string \"%s\" into tokens:\n",
								directory);
#endif
						char * pch = strtok(directory, ":");
						while (pch != NULL) {
							executeDirectory(pch, &tt);
							pch = strtok(NULL, ":");
						}
					}

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
						printf(
								"Output length: %zu, bytes sent: %d, value: \n%s\n",
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

		} // end while-server-loop, when 1000 requests, have been served, spin it off.

		// Kil the child, make sure its started from above.
		exit(0);

	} else if (pid > 0) {
		// This blocks, execution, and waits, for the exit
		children++;

	}
}

int main(int argc, char *argv[]) {

// Make sure we're root.
//    if (!isRoot()) {
//        printf("This program must be run as root/sudo user\n");
//        exit(0);
//    }

	setupSignals();

	int server, c, index;

	while ((c = getopt(argc, argv, "h:p:d:c:a:m:f:g:u:")) != -1)
		switch (c) {
		case 'h':
			strcpy(hostname, optarg);
			break;
		case 'p':
			strcpy(portnum, optarg);
			break;
		case 'd':
			strcpy(directory, optarg);
			break;
		case 'f':
			strcpy(files, optarg);
			break;
		case 'c':
			strcpy(crt, optarg);
			break;
		case 'a':
			strcpy(authority, optarg);
			break;
		case 'm':
			maxchildren = atoi(optarg);
			break;
		case 'u':
			uid = atoi(optarg);
			break;
		case 'g':
			gid = atoi(optarg);
			break;

		case '?':
			if (optopt == 'c')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			exit(EXIT_FAILURE);
		default:
			printf(
					"\n-h(ost) = %s, -p(ort) = %s,"
							"\n-f(ile, multiple paths seperated with a ':') = %s,"
							"\n-d(irectory, multiple directories seperated with a ':') = %s,"
							"\n-c(ertificate-bundle) = %s,"
							"\n-a(uthority) = %s,"
							"\n-m(ax children) = %d\n"
							"\n-u(ser id) = %d\n"
							"\n-g(group ud) = %d\n", hostname, portnum, files,
					directory, crt, authority, maxchildren, uid, gid);
			abort();
		}

	for (index = optind; index < argc; index++) {
		printf("Non-option argument %s\n", argv[index]);
		return 0;
	}

	SSL_CTX *ctx;

	SSL_library_init();
	ctx = initServerCTX(); /* initialize SSL */

	/* Load certs */
	if (-1 == loadCertificates(ctx, crt, crt)) {
		printf("error: Could not load certificates, %s, key: %s\n", crt, crt);
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	SSL_CTX_set_options(ctx,
			SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

	if (1 != SSL_CTX_load_verify_locations(ctx, authority, "/etc/ssl/certs")) {
		printf("error: Could not load authority from file %s\n", authority);
	}

	; /* create server socket */
	if (-1 == (server = openListener(atoi(portnum)))) {
		printf("error: Could not connect, to %s:%d\n", hostname, atoi(portnum));
		exit(EXIT_FAILURE);
	}

	// Spin off the original servers, and then
	unsigned int i = 0;
	for (i = 0; i < maxchildren; i++) {
		forkChild(ctx, server);
	}

	// Top op with more,
	while (1) {
		sleep(1);
		unsigned int i = 0;

		for (i = children; i < maxchildren; i++) {
			forkChild(ctx, server);
		}
	}

	close(server); /* close server socket */
	SSL_CTX_free(ctx); /* release context */
}

