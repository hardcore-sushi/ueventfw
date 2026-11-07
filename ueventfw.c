/*
 * ueventfw - run a command with host uevent access from a private network
 * namespace.
 *
 * A NETLINK_KOBJECT_UEVENT socket created in a private network namespace only
 * sees objects tagged for that namespace.  To provide the host's uevents,
 * ueventfw intercepts the command's uevent socket() calls, opens the socket
 * in the supervisor's network namespace (normally the initial/host one), and
 * injects the descriptor into the command.
 *
 * Process layout:
 *
 *   supervisor (no filter)              command (filter installed)
 *   --------------------------------------------------------------
 *   fork() ---------------------------> child
 *                                       install seccomp filter
 *   <--- listener fd (SCM_RIGHTS) ------ socketpair
 *                                       exec <command>
 *   poll listener
 *     RECV notification for socket(AF_NETLINK, *, NETLINK_KOBJECT_UEVENT)
 *     socket() in supervisor network namespace
 *     SECCOMP_IOCTL_NOTIF_ADDFD -> inject descriptor into command
 *
 * Only socket(AF_NETLINK, *, NETLINK_KOBJECT_UEVENT) is trapped.
 *
 * The child passes the listener to the supervisor over a Unix socketpair with
 * SCM_RIGHTS and then execs the command.  Descriptors are injected with
 * SECCOMP_IOCTL_NOTIF_ADDFD.
 *
 * Usage:
 *   ueventfw <command> [args...]
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

/* seccomp_data.args is an array of 64-bit values even on 32-bit ABIs.  On
 * big-endian systems the low 32 bits (where small int arguments live) are in
 * the second half of each value. */
#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) ||     \
    defined(__BIG_ENDIAN__)
#define UEVENTFW_ARG_LO_OFFSET 4
#else
#define UEVENTFW_ARG_LO_OFFSET 0
#endif

static int g_debug;
#define dbg(...)                                                               \
  do {                                                                         \
    if (g_debug)                                                               \
      fprintf(stderr, __VA_ARGS__);                                            \
  } while (0)

static struct seccomp_notif_sizes g_sizes;

/* The supervisor's pid, used to forward termination signals from the
 * supervisor to the command. */
static volatile sig_atomic_t g_child_pid;

/* Ask the supervisor only for uevent sockets; allow everything else. */
static const struct sock_filter filter[] = {
    /* A = syscall number */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* if A != SYS_socket -> ALLOW (last instruction) */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 0, 5),
    /* A = args[0] (domain) */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             offsetof(struct seccomp_data, args[0]) + UEVENTFW_ARG_LO_OFFSET),
    /* if A != AF_NETLINK -> ALLOW (last instruction) */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_NETLINK, 0, 3),
    /* A = args[2] (protocol) */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             offsetof(struct seccomp_data, args[2]) + UEVENTFW_ARG_LO_OFFSET),
    /* if A != NETLINK_KOBJECT_UEVENT -> ALLOW (last instruction) */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NETLINK_KOBJECT_UEVENT, 0, 1),
    /* match -> notify the supervisor */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    /* everything else is allowed */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

/* Runs in the child.  Returns the notification listener fd, or -1. */
static int install_seccomp_filter(void) {
  const struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = (struct sock_filter *)filter,
  };

  int notify_fd = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                          SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
  if (notify_fd == -1 && errno == EACCES) {
    /* Without CAP_SYS_ADMIN, seccomp requires no_new_privs.  This also
     * prevents privilege gain through setuid/setgid executables in the
     * target, so use it only as a fallback. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
      return -1;
    notify_fd = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                        SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
  }
  return notify_fd;
}

/* Message layout shared by send_fd() and recv_fd(). */
struct fd_msg {
  char byte;
  struct iovec iov;
  union {
    char buf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr align;
  } control;
  struct msghdr msg;
};

static void init_fd_msg(struct fd_msg *m) {
  memset(m, 0, sizeof(*m));
  m->iov.iov_base = &m->byte;
  m->iov.iov_len = sizeof(m->byte);
  m->msg.msg_iov = &m->iov;
  m->msg.msg_iovlen = 1;
  m->msg.msg_control = m->control.buf;
  m->msg.msg_controllen = sizeof(m->control.buf);
}

/* Send fd over a connected Unix socket with SCM_RIGHTS. */
static int send_fd(int sock, int fd) {
  struct fd_msg m;
  struct cmsghdr *cmsg;
  ssize_t n;

  init_fd_msg(&m);
  cmsg = CMSG_FIRSTHDR(&m.msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
  memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

  do {
    n = sendmsg(sock, &m.msg, MSG_NOSIGNAL);
  } while (n == -1 && errno == EINTR);

  if (n != (ssize_t)sizeof(m.byte)) {
    if (n != -1)
      errno = EIO;
    return -1;
  }
  return 0;
}

/* Receive an fd sent with send_fd().  Returns -1 on error or EOF. */
static int recv_fd(int sock) {
  struct fd_msg m;
  struct cmsghdr *cmsg;
  ssize_t n;
  int fd;

  init_fd_msg(&m);

  do {
    n = recvmsg(sock, &m.msg, MSG_CMSG_CLOEXEC);
  } while (n == -1 && errno == EINTR);

  if (n <= 0) {
    if (n == 0)
      errno = ECONNRESET;
    return -1;
  }
  if (m.msg.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) {
    errno = EMSGSIZE;
    return -1;
  }

  cmsg = CMSG_FIRSTHDR(&m.msg);
  if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET ||
      cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len != CMSG_LEN(sizeof(fd))) {
    errno = EINVAL;
    return -1;
  }

  memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
  return fd;
}

static void send_errno(int notify_fd, struct seccomp_notif_resp *resp,
                       const struct seccomp_notif *req, int err) {
  memset(resp, 0, g_sizes.seccomp_notif_resp);
  resp->id = req->id;
  resp->error = -err;
  resp->val = 0;

  if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) == -1 && errno != ENOENT)
    perror("ueventfw: SECCOMP_IOCTL_NOTIF_SEND");
}

/* Inject srcfd into the target as the result of its socket() call and reply. */
static void inject_socket_fd(int notify_fd, struct seccomp_notif_resp *resp,
                             const struct seccomp_notif *req, int srcfd) {
  struct seccomp_notif_addfd addfd = {
      .id = req->id,
      .flags = SECCOMP_ADDFD_FLAG_SEND,
      .srcfd = (uint32_t)srcfd,
      .newfd_flags = (req->data.args[1] & SOCK_CLOEXEC) ? O_CLOEXEC : 0,
  };
  int injected = ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);

  if (injected == -1) {
    /* Injection failed; the target is still blocked, so reply with the
     * error. */
    int err = errno;
    send_errno(notify_fd, resp, req, err);
    return;
  }
  dbg("injected fd %d into target\n", injected);
}

static void handle_notification(int notify_fd, struct seccomp_notif_resp *resp,
                                const struct seccomp_notif *req) {
  /* The filter should already guarantee this shape, but validate again
   * before touching the target. */
  if (req->data.nr != SYS_socket || req->data.args[0] != AF_NETLINK ||
      req->data.args[2] != NETLINK_KOBJECT_UEVENT) {
    dbg("rejecting unexpected notification\n");
    send_errno(notify_fd, resp, req, EINVAL);
    return;
  }

  /* The supervisor lives in the namespace whose uevents we want, so the
   * socket is created here. */
  int fd = socket(AF_NETLINK, (int)req->data.args[1], NETLINK_KOBJECT_UEVENT);
  if (fd == -1) {
    int err = errno;
    perror("ueventfw: socket in supervisor network namespace");
    send_errno(notify_fd, resp, req, err);
    return;
  }

  inject_socket_fd(notify_fd, resp, req, fd);
  close(fd);
}

static int child_exit_code(int status) {
  return WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_FAILURE;
}

static int wait_child_status(pid_t child) {
  int status;
  pid_t ret;

  do {
    ret = waitpid(child, &status, 0);
  } while (ret == -1 && errno == EINTR);

  g_child_pid = 0;
  return ret == child ? child_exit_code(status) : EXIT_FAILURE;
}

static void kill_and_reap(pid_t child) {
  g_child_pid = 0;
  kill(child, SIGKILL);
  while (waitpid(child, NULL, 0) == -1 && errno == EINTR)
    ;
}

static int supervisor_loop(int notify_fd, pid_t child) {
  int status = 0;
  int child_reaped = 0;

  if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &g_sizes) == -1) {
    perror("ueventfw: SECCOMP_GET_NOTIF_SIZES");
    return EXIT_FAILURE;
  }
  if (g_sizes.seccomp_notif == 0 || g_sizes.seccomp_notif_resp == 0) {
    fprintf(stderr, "ueventfw: kernel reported invalid notification sizes\n");
    return EXIT_FAILURE;
  }

  struct seccomp_notif *req = calloc(1, g_sizes.seccomp_notif);
  struct seccomp_notif_resp *resp = calloc(1, g_sizes.seccomp_notif_resp);
  if (req == NULL || resp == NULL) {
    perror("ueventfw: calloc");
    free(req);
    free(resp);
    return EXIT_FAILURE;
  }

  dbg("supervisor: waiting for uevent socket() notifications\n");

  for (;;) {
    if (!child_reaped) {
      pid_t ret = waitpid(child, &status, WNOHANG);
      if (ret == child) {
        child_reaped = 1;
        g_child_pid = 0;
      } else if (ret == -1 && errno != EINTR) {
        perror("ueventfw: waitpid");
        free(req);
        free(resp);
        return EXIT_FAILURE;
      }
    }

    struct pollfd pfd = {.fd = notify_fd, .events = POLLIN};
    int ret = poll(&pfd, 1, 250);
    if (ret == -1) {
      if (errno == EINTR)
        continue;
      perror("ueventfw: poll");
      free(req);
      free(resp);
      return EXIT_FAILURE;
    }
    if (ret == 0)
      continue;

    if (pfd.revents & POLLHUP) {
      /* No task has the filter attached anymore. */
      int rc =
          child_reaped ? child_exit_code(status) : wait_child_status(child);
      g_child_pid = 0;
      free(req);
      free(resp);
      return rc;
    }

    if (pfd.revents & (POLLERR | POLLNVAL)) {
      fprintf(stderr, "ueventfw: seccomp listener error\n");
      free(req);
      free(resp);
      return EXIT_FAILURE;
    }

    if (!(pfd.revents & POLLIN))
      continue;

    memset(req, 0, g_sizes.seccomp_notif);
    if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, req) == -1) {
      /* ENOENT means a pending notification was cancelled, not that
       * all tasks are gone.  POLLHUP covers that case. */
      if (errno == EINTR || errno == ENOENT)
        continue;
      perror("ueventfw: SECCOMP_IOCTL_NOTIF_RECV");
      free(req);
      free(resp);
      return EXIT_FAILURE;
    }

    dbg("notification id=%llu pid=%d nr=%d type=%llu\n",
        (unsigned long long)req->id, req->pid, req->data.nr,
        (unsigned long long)req->data.args[1]);

    handle_notification(notify_fd, resp, req);
  }
}

static void forward_signal(int sig) {
  pid_t child = (pid_t)g_child_pid;

  if (child > 0)
    kill(child, sig);
  else
    _exit(128 + sig);
}

static int install_signal_handlers(void) {
  static const int signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT};
  struct sigaction sa = {.sa_handler = forward_signal, .sa_flags = 0};

  sigemptyset(&sa.sa_mask);
  for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
    if (sigaction(signals[i], &sa, NULL) == -1)
      return -1;
  }
  return 0;
}

static void usage(FILE *out) {
  fprintf(out,
          "usage: ueventfw <command> [args...]\n"
          "\n"
          "Run <command> under a seccomp filter that redirects its\n"
          "socket(AF_NETLINK, *, NETLINK_KOBJECT_UEVENT) calls to a\n"
          "supervisor.  The supervisor opens the socket in the network\n"
          "namespace where ueventfw was started and injects the descriptor\n"
          "into <command>.  This lets a process in a private network\n"
          "namespace receive the uevents of the namespace where ueventfw\n"
          "runs.\n"
          "\n"
          "The filter applies to <command> and all of its descendants.\n"
          "\n"
          "Set UEVENTFW_DEBUG=1 to print diagnostic output.\n");
}

int main(int argc, char *argv[]) {
  int fd_sock[2];
  pid_t child;

  if (argc < 2) {
    usage(stderr);
    return EXIT_FAILURE;
  }

  const char *debug = getenv("UEVENTFW_DEBUG");
  g_debug = debug != NULL && *debug != '\0' && strcmp(debug, "0") != 0;

  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, fd_sock) == -1) {
    perror("ueventfw: socketpair");
    return EXIT_FAILURE;
  }

  child = fork();
  if (child == -1) {
    perror("ueventfw: fork");
    return EXIT_FAILURE;
  }

  if (child == 0) {
    close(fd_sock[1]);

    int notify_fd = install_seccomp_filter();
    if (notify_fd == -1) {
      int err = errno;
      dprintf(STDERR_FILENO, "ueventfw: cannot install seccomp filter: %s\n",
              strerror(err));
      _exit(EXIT_FAILURE);
    }

    if (send_fd(fd_sock[0], notify_fd) == -1) {
      int err = errno;
      dprintf(STDERR_FILENO, "ueventfw: cannot pass listener fd: %s\n",
              strerror(err));
      _exit(EXIT_FAILURE);
    }
    close(notify_fd);
    close(fd_sock[0]);

    execvp(argv[1], &argv[1]);

    int err = errno;
    dprintf(STDERR_FILENO, "ueventfw: %s: %s\n", argv[1], strerror(err));
    _exit(EXIT_FAILURE);
  }

  g_child_pid = (sig_atomic_t)child;

  if (install_signal_handlers() == -1) {
    perror("ueventfw: sigaction");
    kill_and_reap(child);
    return EXIT_FAILURE;
  }

  close(fd_sock[0]);

  int notify_fd = recv_fd(fd_sock[1]);
  if (notify_fd == -1) {
    if (errno == ECONNRESET)
      fprintf(stderr, "ueventfw: child exited before passing listener fd\n");
    else
      perror("ueventfw: recv_fd");
    kill_and_reap(child);
    return EXIT_FAILURE;
  }

  close(fd_sock[1]);

  return supervisor_loop(notify_fd, child);
}
