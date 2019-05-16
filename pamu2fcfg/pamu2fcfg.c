/*
 * Copyright (C) 2014-2018 Yubico AB - See COPYING
 */

#include <u2f-server.h>
#include <u2f-host.h>

#define BUFSIZE 1024
#define PAM_PREFIX "pam://"
#define TIMEOUT 15
#define FREQUENCY 1

#define AGENT_BUF_LEN             4096
#define SSH_REQUEST_U2F_REGISTER  40
#define SSH_AGENT_FAILURE         5
#define SSH_AGENT_SUCCESS         6

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <pwd.h>

#include "cmdline.h"

void do_local(u2fs_ctx_t *ctx, struct gengetopt_args_info *args_info, char *origin, char **response);
void do_ssh_agent(char *ssh_agent_socket_name, u2fs_ctx_t *ctx, char *origin, char **response);

int main(int argc, char *argv[]) {
  int exit_code = EXIT_FAILURE;
  struct gengetopt_args_info args_info;
  char buf[BUFSIZE];
  char *response;
  u2fs_ctx_t *ctx;
  u2fs_reg_res_t *reg_result;
  u2fs_rc s_rc;
  char *origin = NULL;
  char *appid = NULL;
  char *user = NULL;
  char *ssh_agent_socket_name = NULL;
  struct passwd *passwd;
  const char *kh = NULL;
  const char *pk = NULL;
  unsigned i;

  if (cmdline_parser(argc, argv, &args_info) != 0)
    exit(EXIT_FAILURE);

  if (args_info.help_given) {
    cmdline_parser_print_help();
    printf("\nReport bugs at <https://github.com/Yubico/pam-u2f>.\n");
    exit(EXIT_SUCCESS);
  }

  s_rc = u2fs_global_init(args_info.debug_flag ? U2FS_DEBUG : 0);
  if (s_rc != U2FS_OK) {
    fprintf(stderr, "error: u2fs_global_init (%d): %s\n", s_rc,
            u2fs_strerror(s_rc));
    exit(EXIT_FAILURE);
  }

  s_rc = u2fs_init(&ctx);
  if (s_rc != U2FS_OK) {
    fprintf(stderr, "error: u2fs_init (%d): %s\n", s_rc, u2fs_strerror(s_rc));
    exit(EXIT_FAILURE);
  }

  if (args_info.origin_given)
    origin = args_info.origin_arg;
  else {
    if (!strcpy(buf, PAM_PREFIX)) {
      fprintf(stderr, "strcpy failed\n");
      exit(EXIT_FAILURE);
    }
    if (gethostname(buf + strlen(PAM_PREFIX), BUFSIZE - strlen(PAM_PREFIX)) ==
        -1) {
      perror("gethostname");
      exit(EXIT_FAILURE);
    }
    origin = buf;
  }

  if (args_info.verbose_given)
    fprintf(stderr, "Setting origin to %s\n", origin);

  s_rc = u2fs_set_origin(ctx, origin);
  if (s_rc != U2FS_OK) {
    fprintf(stderr, "error: u2fs_set_origin (%d): %s\n", s_rc,
            u2fs_strerror(s_rc));
    exit(EXIT_FAILURE);
  }

  if (args_info.appid_given)
    appid = args_info.appid_arg;
  else {
    appid = origin;
  }

  if (args_info.verbose_given)
    fprintf(stderr, "Setting appid to %s\n", appid);

  s_rc = u2fs_set_appid(ctx, appid);
  if (s_rc != U2FS_OK) {
    fprintf(stderr, "error: u2fs_set_appid (%d): %s\n", s_rc,
            u2fs_strerror(s_rc));
    exit(EXIT_FAILURE);
  }

  if (args_info.username_given)
    user = args_info.username_arg;
  else {
    passwd = getpwuid(getuid());
    if (passwd == NULL) {
      perror("getpwuid");
      exit(EXIT_FAILURE);
    }
    user = passwd->pw_name;
  }

  // Use SSH agent if defined
  ssh_agent_socket_name = getenv("SSH_AUTH_SOCK");
  
  if (ssh_agent_socket_name != NULL) {
    do_ssh_agent(ssh_agent_socket_name, ctx, origin, &response);
  }
  else {
    do_local(ctx, &args_info, origin, &response);
  }
  
  s_rc = u2fs_registration_verify(ctx, response, &reg_result);
  if (s_rc != U2FS_OK) {
    fprintf(stderr, "error: (%d) %s\n", s_rc, u2fs_strerror(s_rc));
    exit(EXIT_FAILURE);
  }

  kh = u2fs_get_registration_keyHandle(reg_result);
  if (!kh) {
    fprintf(stderr, "Unable to extract keyHandle: (%d) %s\n", s_rc,
            u2fs_strerror(s_rc));
    exit(EXIT_FAILURE);
  }

  pk = u2fs_get_registration_publicKey(reg_result);
  if (!pk) {
    fprintf(stderr, "Unable to extract public key: (%d) %s\n", s_rc,
            u2fs_strerror(s_rc));
    exit(EXIT_FAILURE);
  }

  if (!args_info.nouser_given)
    printf("%s", user);

  printf(":%s,", kh);
  for (i = 0; i < U2FS_PUBLIC_KEY_LEN; i++) {
    printf("%02x", pk[i] & 0xFF);
  }
  
  exit_code = EXIT_SUCCESS;

  u2fs_done(ctx);
  u2fs_global_done();
  exit(exit_code);
}

void do_local(u2fs_ctx_t *ctx, struct gengetopt_args_info *args_info,
	      char *origin, char **response) {
  
  char *p;
  u2fh_rc h_rc;
  u2fs_rc s_rc;
  u2fh_devs *devs = NULL;
  int i;
  unsigned max_index = 0;

  if (u2fh_global_init(args_info->debug_flag ? U2FH_DEBUG : 0) != U2FH_OK ||
      u2fh_devs_init(&devs) != U2FH_OK) {
    fprintf(stderr, "Unable to initialize libu2f-host\n");
    exit(EXIT_FAILURE);
  }

  h_rc = u2fh_devs_discover(devs, &max_index);
  if (h_rc != U2FH_OK && h_rc != U2FH_NO_U2F_DEVICE) {
    fprintf(stderr, "Unable to discover device(s), %s (%d)\n",
            u2fh_strerror(h_rc), h_rc);
    exit(EXIT_FAILURE);
  }

  if (h_rc == U2FH_NO_U2F_DEVICE) {
    for (i = 0; i < TIMEOUT; i += FREQUENCY) {
      fprintf(stderr, "\rNo U2F device available, please insert one now, you "
                      "have %2d seconds",
              TIMEOUT - i);
      fflush(stderr);
      sleep(FREQUENCY);

      h_rc = u2fh_devs_discover(devs, &max_index);
      if (h_rc == U2FH_OK) {
        fprintf(stderr, "\nDevice found!\n");
        break;
      }

      if (h_rc != U2FH_NO_U2F_DEVICE) {
        fprintf(stderr, "\nUnable to discover device(s), %s (%d)",
                u2fh_strerror(h_rc), h_rc);
        exit(EXIT_FAILURE);
      }
    }
  }

  if (h_rc != U2FH_OK) {
    fprintf(stderr, "\rNo device found. Aborting.                              "
                    "           \n");
    exit(EXIT_FAILURE);
  }

  s_rc = u2fs_registration_challenge(ctx, &p);
  if (s_rc != U2FS_OK) {
    fprintf(stderr, "Unable to generate registration challenge, %s (%d)\n",
            u2fs_strerror(s_rc), s_rc);
    exit(EXIT_FAILURE);
  }

  h_rc = u2fh_register(devs, p, origin, response, U2FH_REQUEST_USER_PRESENCE);
  if (h_rc != U2FH_OK) {
    fprintf(stderr, "Unable to generate registration challenge, %s (%d)\n",
            u2fh_strerror(h_rc), h_rc);
    exit(EXIT_FAILURE);
  }
  
}

void do_ssh_agent(char *ssh_agent_socket_name, u2fs_ctx_t *ctx, char *origin, char **response) {

  int socket_fd;
  struct sockaddr_un addr;
  char agent_buffer[AGENT_BUF_LEN];
  uint32_t agent_buffer_len;
  unsigned char message_type;
  uint32_t origin_len;
  uint32_t challenge_len;
  uint32_t response_len;
  uint32_t be_value;
  int count;
  uint32_t nread;
  u2fs_rc s_rc;
  char *challenge;

  origin_len = strlen(origin);

  socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (socket_fd == -1) {
    perror("Unable to open socket");
    exit(EXIT_FAILURE);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, ssh_agent_socket_name, sizeof(addr.sun_path)-1);

  if (connect(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    perror("Unable to connect to SSH agent socket");
    exit(EXIT_FAILURE);
  }

  s_rc = u2fs_registration_challenge(ctx, &challenge);
  if (s_rc != U2FS_OK) {
    fprintf(stderr, "Unable to generate registration challenge, %s (%d)\n",
            u2fs_strerror(s_rc), s_rc);
    exit(EXIT_FAILURE);
  }

  challenge_len = strlen(challenge);

  agent_buffer_len = origin_len + challenge_len + 2*sizeof(uint32_t) + sizeof(unsigned char);
  
  if (agent_buffer_len > AGENT_BUF_LEN - sizeof(uint32_t)) {
    fprintf(stderr, "Registration origin + challenge string too long\n");
    exit(EXIT_FAILURE);
  }

  message_type = SSH_REQUEST_U2F_REGISTER;

  be_value = htonl(agent_buffer_len);
  memcpy(agent_buffer, &be_value, sizeof(uint32_t));
  
  memcpy(agent_buffer + sizeof(uint32_t), &message_type, sizeof(unsigned char));

  be_value = htonl(origin_len);
  memcpy(agent_buffer + sizeof(uint32_t) + sizeof(unsigned char), &be_value, sizeof(uint32_t));
  memcpy(agent_buffer + 2*sizeof(uint32_t) + sizeof(unsigned char), origin, origin_len);
  
  be_value = htonl(challenge_len);
  memcpy(agent_buffer + 2*sizeof(uint32_t) + sizeof(unsigned char) + origin_len,
	 &be_value, sizeof(uint32_t));
  memcpy(agent_buffer + 3*sizeof(uint32_t) + sizeof(unsigned char) + origin_len,
	 challenge, challenge_len);
  
  count = write(socket_fd, agent_buffer, agent_buffer_len + sizeof(uint32_t));
  if (count < 0) {
    perror("Unable to write to SSH agent");
    exit(EXIT_FAILURE);
  }
  else if (count < agent_buffer_len + sizeof(uint32_t)) {
    fprintf(stderr, "Short write while communicating with SSH agent: %d\n", count);
    exit(EXIT_FAILURE);
  }

  count = read(socket_fd, &be_value, sizeof(uint32_t));
  if (count < 0) {
    perror("Unable to read from SSH agent");
    exit(EXIT_FAILURE);
  }
  else if (count < sizeof(uint32_t)) {
    fprintf(stderr, "Short read while communicating with SSH agent: %d\n", count);
    exit(EXIT_FAILURE);
  }

  agent_buffer_len = ntohl(be_value);

  if (agent_buffer_len < sizeof(unsigned char) + sizeof(uint32_t)) {
    fprintf(stderr, "SSH agent data too short: %d but expected at least %ld\n",
	    agent_buffer_len, sizeof(unsigned char) + sizeof(uint32_t));
    exit(EXIT_FAILURE);
  }
  
  nread = 0;
  while (nread < agent_buffer_len) {
    
    count = read(socket_fd, agent_buffer + nread, agent_buffer_len - nread);
    if (count < 0) {
      perror("Unable to read from SSH agent");
      exit(EXIT_FAILURE);
    }

    nread += count;
  }

  memcpy(&message_type, agent_buffer, sizeof(unsigned char));

  if (message_type == SSH_AGENT_FAILURE) {
    fprintf(stderr, "SSH agent returned failure\n");
    exit(EXIT_FAILURE);
  }
  else if (message_type != SSH_AGENT_SUCCESS) {
    fprintf(stderr, "SSH agent returned unknown response: %d\n", message_type);
    exit(EXIT_FAILURE);
  }

  memcpy(&be_value, agent_buffer + sizeof(unsigned char), sizeof(uint32_t));
  response_len = ntohl(be_value);

  if (agent_buffer_len < sizeof(unsigned char) + sizeof(uint32_t) + response_len) {
    fprintf(stderr, "SSH agent data too short: %d but expected %ld\n",
	    agent_buffer_len, sizeof(unsigned char) + sizeof(uint32_t) + response_len);
    exit(EXIT_FAILURE);
  }

  *response = malloc(response_len + 1);
  if (!(*response)) {
    fprintf(stderr, "Malloc failed\n");
    exit(EXIT_FAILURE);
  }

  (*response)[response_len] = 0;

  memcpy(*response, agent_buffer + sizeof(unsigned char) + sizeof(uint32_t),
	 response_len);

  close(socket_fd);

}
