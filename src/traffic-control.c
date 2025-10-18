#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/class.h>
#include <netlink/route/cls/flower.h>
#include <netlink/route/link.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/tc.h>
#include <netlink/route/qdisc/htb.h>
#include <netlink/route/action.h>
#include <pthread.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdatomic.h>

#include "conf.h"
#include "heap.h"
#include "log.h"
#include "sblist.h"
#include "traffic-control.h"

#define TC_WARN(FMT, ...) \
        log_message (LOG_WARNING, FMT, __VA_ARGS__)

#define TC_ERR(FMT, ...) \
        log_message (LOG_ERR, FMT, __VA_ARGS__)

sblist *devices;
pthread_rwlock_t dev_lock = PTHREAD_RWLOCK_INITIALIZER;

struct htab *traffic_control_filters;
pthread_rwlock_t filter_lock = PTHREAD_RWLOCK_INITIALIZER;

/*
* Netlink
*/
typedef struct {
        struct nl_sock *sock;
        struct nl_cache *link_cache;
} netlink_t;

netlink_t *netlink = NULL;

/*
 * A traffic control enabled network device.
 */
typedef struct {
        char *name;                       /* Network device name */
        sblist *classes;                  /* List of traffic control classes */
        pthread_rwlock_t *class_rwlock;   /* Read-write lock for classes */
        struct rtnl_link *link;           /* Netlink link object */
        struct rtnl_qdisc *qdisc;         /* Root qdisc */
        struct rtnl_class *default_class; /* Default HTB class */
        atomic_int min_minor_num_class;   /* Minimum available minor number for classes (atomic) */
        atomic_int min_minor_num_filt;    /* Minimum available minor number for filters (atomic) */
        netlink_t *netlink;               /* Netlink socket and cache */
} traffic_control_dev_t;

/*
 * A traffic control class (name:bandwidth) and its associated Netlink class.
 */
typedef struct {
        char *name;                      /* CDN name */
        uint64_t bandwidth_kbps;         /* Bandwidth limit in kbps */
        struct rtnl_class *cls;          /* Netlink traffic control class */
        pthread_rwlock_t *update_rwlock;  /* Read-write lock for class update */
} traffic_control_class_t;

/*
 * TC filter.
 */
typedef struct {
        uint32_t handle;            /* Handle for the filter */
        uint16_t proto;             /* Protocol for the filter in network byte order */
        traffic_control_dev_t *dev; /* Associated network device */
} traffic_control_filter_t;

/*
 * Atomic helper functions for thread-safe minor number management
 */

/* Get the next available minor number for a class and increment atomically */
static inline int get_next_class_minor(traffic_control_dev_t *dev) {
        return atomic_fetch_add(&dev->min_minor_num_class, 1);
}

/* Get the next available minor number for a filter and increment atomically */
static inline int get_next_filter_minor(traffic_control_dev_t *dev) {
        return atomic_fetch_add(&dev->min_minor_num_filt, 1);
}

/* Initialize atomic values */
static inline void init_atomic_minors(traffic_control_dev_t *dev, int class_start, int filter_start) {
        atomic_store(&dev->min_minor_num_class, class_start);
        atomic_store(&dev->min_minor_num_filt, filter_start);
}

/* Get current values (for read-only purposes) */
static inline int get_current_class_minor(traffic_control_dev_t *dev) {
        return atomic_load(&dev->min_minor_num_class);
}

static inline int get_current_filter_minor(traffic_control_dev_t *dev) {
        return atomic_load(&dev->min_minor_num_filt);
}

int setup_netlink(void)
{
        netlink = safemalloc(sizeof(netlink_t));
        if (!netlink) {
                TC_ERR("Failed to allocate memory for Netlink.", "");
                return -1;
        }
        netlink->sock = nl_socket_alloc();
        if (!netlink->sock) {
                TC_ERR("Failed to allocate Netlink socket.", "");
                safefree(netlink);
                return -1;
        }
        if (nl_connect(netlink->sock, NETLINK_ROUTE) < 0) {
                TC_ERR("Failed to connect to Netlink socket.", "");
                nl_socket_free(netlink->sock);
                safefree(netlink);
                return -1;
        }
        if (rtnl_link_alloc_cache(netlink->sock, AF_UNSPEC, &netlink->link_cache) < 0) {
                TC_ERR("Failed to allocate link cache.", "");
                nl_socket_free(netlink->sock);
                safefree(netlink);
                return -1;
        }
        if ((devices = sblist_new(sizeof(traffic_control_dev_t), 16)) == NULL) {
                TC_ERR("Failed to allocate device list.", "");
                nl_cache_free(netlink->link_cache);
                nl_socket_free(netlink->sock);
                safefree(netlink);
                return -1;
        }
        if ((traffic_control_filters = htab_create(64)) == NULL) {
                TC_ERR("Failed to allocate traffic control filter hash table.", "");
                sblist_free(devices);
                nl_cache_free(netlink->link_cache);
                nl_socket_free(netlink->sock);
                safefree(netlink);
                return -1;
        }
        return 0;
}

void cleanup_netlink(void)
{
        if (netlink) {
                if (netlink->link_cache) {
                        nl_cache_free(netlink->link_cache);
                }
                if (netlink->sock) {
                        nl_socket_free(netlink->sock);
                }
                safefree(netlink);
        }
}

static struct rtnl_class *
init_tc_class(
        int major,
        int minor,
        uint64_t bandwidth_kbps,
        struct rtnl_link *link,
        struct nl_sock *sock
);

static void cleanup_tc_class(struct nl_sock *sock, struct rtnl_class *class);

static void cleanup_traffic_control_class(
        struct nl_sock *sock,
        traffic_control_class_t *tc_class
);

static void cleanup_traffic_control_dev(traffic_control_dev_t *dev)
{
        size_t i;
        traffic_control_class_t *tc;

        if (!dev) return;

        if (dev->link) {
                cleanup_tc_class(dev->netlink->sock, dev->default_class);
                rtnl_qdisc_delete(dev->netlink->sock, dev->qdisc);
                rtnl_qdisc_put(dev->qdisc);
                rtnl_link_put(dev->link);
        }

        if (dev->classes) {
                for (i = 0; i < sblist_getsize(dev->classes); i++) {
                        tc = sblist_get(dev->classes, i);
                        if (tc) {
                                cleanup_traffic_control_class(dev->netlink->sock, tc);
                        }
                }
                sblist_free(dev->classes);
        }

        pthread_rwlock_destroy(dev->class_rwlock);
        safefree(dev->class_rwlock);
        safefree(dev->name);
}

void cleanup_traffic_control_dev_list(void)
{
        size_t i;
        traffic_control_dev_t *dev;

        if (!devices) return;

        for (i = 0; i < sblist_getsize(devices); i++) {
                dev = sblist_get(devices, i);
                if (dev) {
                        cleanup_traffic_control_dev(dev);
                }
        }

        sblist_free(devices);
        devices = NULL;
}

int setup_traffic_control_dev(char *dev_name)
{
        struct rtnl_link *link = NULL;
        struct rtnl_qdisc *qdisc = NULL;
        struct rtnl_class *default_class = NULL;
        int ifindex;
        size_t i;
        traffic_control_dev_t dev;

        ifindex = rtnl_link_name2i(netlink->link_cache, dev_name);
        if (ifindex == 0) {
                TC_ERR("Network device %s not found.", dev_name);
                return -1;
        }

        link = rtnl_link_get(netlink->link_cache, ifindex);
        if (!link) {
                TC_ERR("Failed to get link for device %s.", dev_name);
                return -1;
        }

        /* Create root HTB qdisc */
        qdisc = rtnl_qdisc_alloc();
        if (!qdisc) {
                TC_ERR("Failed to allocate root qdisc.", "");
                rtnl_link_put(link);
                return -1;
        }
        rtnl_tc_set_link(TC_CAST(qdisc), link);
        rtnl_tc_set_parent(TC_CAST(qdisc), TC_H_ROOT);
        rtnl_tc_set_handle(TC_CAST(qdisc), TC_HANDLE(1, 0));
        if (rtnl_tc_set_kind(TC_CAST(qdisc), "htb") < 0) {
                TC_ERR("Failed to set qdisc kind to htb.", "");
                rtnl_qdisc_put(qdisc);
                rtnl_link_put(link);
                return -1;
        }
        if (rtnl_htb_set_defcls(qdisc, 1) < 0) {
                TC_ERR("Failed to set default class for qdisc.", "");
                rtnl_qdisc_put(qdisc);
                rtnl_link_put(link);
                return -1;
        }
        if (rtnl_qdisc_add(netlink->sock, qdisc, NLM_F_CREATE | NLM_F_EXCL) < 0) {
                TC_ERR("Failed to add root qdisc to device %s.", dev_name);
                rtnl_qdisc_put(qdisc);
                rtnl_link_put(link);
                return -1;
        }

        /* Create the default HTB class */
        default_class = init_tc_class(1, 1, 10000000000ULL, link, netlink->sock); // 10 Gbps default
        if (!default_class) {
                TC_ERR("Failed to allocate default class.", "");
                rtnl_qdisc_delete(netlink->sock, qdisc);
                rtnl_qdisc_put(qdisc);
                rtnl_link_put(link);
                return -1;
        }

        dev.name = strdup(dev_name);
        if (!dev.name) {
                TC_ERR("Failed to allocate memory for device name.", "");
                cleanup_tc_class(netlink->sock, default_class);
                rtnl_qdisc_delete(netlink->sock, qdisc);
                rtnl_qdisc_put(qdisc);
                rtnl_link_put(link);
                return -1;
        }
        dev.class_rwlock = safemalloc(sizeof(pthread_rwlock_t));
        if (!dev.class_rwlock) {
                TC_ERR("Failed to allocate memory for class rwlock.", "");
                safefree(dev.name);
                cleanup_tc_class(netlink->sock, default_class);
                rtnl_qdisc_delete(netlink->sock, qdisc);
                rtnl_qdisc_put(qdisc);
                rtnl_link_put(link);
                return -1;
        }
        if (pthread_rwlock_init(dev.class_rwlock, NULL) != 0) {
                TC_ERR("Failed to initialize class rwlock.", "");
                safefree(dev.name);
                safefree(dev.class_rwlock);
                cleanup_tc_class(netlink->sock, default_class);
                rtnl_qdisc_delete(netlink->sock, qdisc);
                rtnl_qdisc_put(qdisc);
                rtnl_link_put(link);
                return -1;
        }
        dev.classes = sblist_new(sizeof(traffic_control_class_t), 16);
        if (!dev.classes) {
                TC_ERR("Failed to create minor list for device %s.", dev_name);
                safefree(dev.name);
                cleanup_tc_class(netlink->sock, default_class);
                rtnl_qdisc_delete(netlink->sock, qdisc);
                rtnl_qdisc_put(qdisc);
                rtnl_link_put(link);
                return -1;
        }
        dev.link = link;
        init_atomic_minors(&dev, 2, 1); // Start class minors at 2 (1 is default), filter minors at 1
        dev.netlink = netlink; // Share the global netlink instance
        dev.default_class = default_class;
        dev.qdisc = qdisc;

        // Add the dev to the global list
        pthread_rwlock_wrlock(&dev_lock);
        for (i = 0; i < sblist_getsize(devices); i++) {
                traffic_control_dev_t *existing_dev = sblist_get(devices, i);
                if (existing_dev && strcmp(existing_dev->name, dev.name) == 0) {
                        pthread_rwlock_unlock(&dev_lock);
                        TC_ERR("Traffic control device %s already exists.", dev.name);
                        cleanup_traffic_control_dev(&dev);
                        return -1;
                }
        }
        if (sblist_add(devices, &dev) == 0) {
                // Failed to add to list
                pthread_rwlock_unlock(&dev_lock);
                TC_ERR("Failed to add device %s to global list.", dev.name);
                cleanup_traffic_control_dev(&dev);
                return -1;
        }
        pthread_rwlock_unlock(&dev_lock);

        return 0;
}

static struct rtnl_class *
init_tc_class(int major, int minor, uint64_t bandwidth_kbps, struct rtnl_link *link, struct nl_sock *sock)
{
        struct rtnl_class *class = rtnl_class_alloc();
        if (!class) {
                TC_ERR("Failed to allocate class.", "");
                return NULL;
        }
        rtnl_tc_set_link(TC_CAST(class), link);
        rtnl_tc_set_parent(TC_CAST(class), TC_HANDLE(1, 0)); // Parent is root qdisc
        rtnl_tc_set_handle(TC_CAST(class), TC_HANDLE(major, minor));
        if (rtnl_tc_set_kind(TC_CAST(class), "htb") < 0) {
                TC_ERR("Failed to set class kind to htb.", "");
                rtnl_class_put(class);
                return NULL;
        }
        if (rtnl_htb_set_rate(class, bandwidth_kbps * 1000 / 8) < 0) { // in bytes/sec
                TC_ERR("Failed to set class rate.", "");
                rtnl_class_put(class);
                return NULL;
        }
        if (rtnl_htb_set_ceil(class, bandwidth_kbps * 1000 / 8) < 0) { // in bytes/sec
                TC_ERR("Failed to set class ceil.", "");
                rtnl_class_put(class);
                return NULL;
        }
        if (rtnl_class_add(sock, class, NLM_F_CREATE | NLM_F_EXCL) < 0) {
                TC_ERR("Failed to add class to device.", "");
                rtnl_class_put(class);
                return NULL;
        }
        return class;
}

static void cleanup_tc_class(struct nl_sock *sock, struct rtnl_class *class)
{
        if (class) {
                // Remove from kernel first (if it was successfully added)
                rtnl_class_delete(sock, class);
                rtnl_class_put(class);
        }
}

static traffic_control_class_t *init_traffic_control_class(
        char *name,
        uint64_t bandwidth_kbps,
        int major,
        int minor,
        struct rtnl_link *link,
        struct nl_sock *sock
) {
        struct rtnl_class *class = NULL;
        traffic_control_class_t *traffic_control_class = NULL;


        class = init_tc_class(major, minor, bandwidth_kbps, link, sock);
        if (!class) {
                TC_ERR("Failed to initialize traffic control class.", "");
                return NULL;
        }
        traffic_control_class = malloc(sizeof(traffic_control_class_t));
        if (!traffic_control_class) {
                TC_ERR("Failed to allocate memory for traffic control class.", "");
                cleanup_tc_class(sock, class);
                return NULL;
        }
        traffic_control_class->name = strdup(name);
        if (!traffic_control_class->name) {
                TC_ERR("Failed to allocate memory for class name.", "");
                cleanup_tc_class(sock, class);
                safefree(traffic_control_class);
                return NULL;
        }
        traffic_control_class->cls = class;
        traffic_control_class->bandwidth_kbps = bandwidth_kbps;
        traffic_control_class->update_rwlock = safemalloc(sizeof(pthread_rwlock_t));
        if (!traffic_control_class->update_rwlock) {
                TC_ERR("Failed to allocate memory for update rwlock.", "");
                safefree(traffic_control_class->name);
                cleanup_tc_class(sock, class);
                safefree(traffic_control_class);
                return NULL;
        }
        pthread_rwlock_init(traffic_control_class->update_rwlock, NULL);

        return traffic_control_class;
}

/**
 * Update the bandwidth of a traffic control class.
 * If anything goes wrong, the exsting class is not
 * affected.
 */
static int update_tc_class_bandwidth(
        traffic_control_class_t *tc_class,
        uint64_t new_bandwidth_kbps,
        struct nl_sock *sock
) {
        if (!tc_class || !tc_class->cls) {
                TC_ERR("Invalid traffic control class for update.", "");
                return -1;
        }
        if (rtnl_htb_set_rate(tc_class->cls, new_bandwidth_kbps * 1000 / 8) < 0) { // in bytes/sec
                TC_ERR("Failed to set new class rate.", "");
                return -1;
        }
        if (rtnl_htb_set_ceil(tc_class->cls, new_bandwidth_kbps * 1000 / 8) < 0) { // in bytes/sec
                TC_ERR("Failed to set new class ceil.", "");
                return -1;
        }
        if (rtnl_class_add(sock, tc_class->cls, 0) < 0) {
                TC_ERR("Failed to update class in kernel.", "");
                return -1;
        }
        tc_class->bandwidth_kbps = new_bandwidth_kbps;
        return 0;
}

static void cleanup_traffic_control_class(struct nl_sock *sock, traffic_control_class_t *tc_class)
{
        if (tc_class) {
                cleanup_tc_class(sock, tc_class->cls);
                safefree(tc_class->name);
                pthread_rwlock_destroy(tc_class->update_rwlock);
                safefree(tc_class->update_rwlock);
        }
}

static traffic_control_class_t *find_traffic_control_class_by_name(traffic_control_dev_t *dev, char *name) {
        size_t i;
        for (i = 0; i < sblist_getsize(dev->classes); i++) {
                traffic_control_class_t *tc_class = sblist_get(dev->classes, i);
                if (tc_class && strcmp(tc_class->name, name) == 0) {
                        return tc_class;
                }
        }
        return NULL;
}

static traffic_control_dev_t *find_traffic_control_device_by_name(char *name) {
        size_t i;
        for (i = 0; i < sblist_getsize(devices); i++) {
                traffic_control_dev_t *dev = sblist_get(devices, i);
                if (dev && strcmp(dev->name, name) == 0) {
                        return dev;
                }
        }
        return NULL;
}

int setup_cdn_traffic_control(
        char *dev_name,
        char *class_name,
        uint64_t bandwidth_kbps
) {
        traffic_control_class_t *tc_class = NULL;
        traffic_control_dev_t *dev = NULL;

        if (!class_name || !dev_name) {
                TC_ERR("Invalid CDN class name or device name.", "");
                return -1;
        }

        // Find the device by name
        pthread_rwlock_rdlock(&dev_lock);
        dev = find_traffic_control_device_by_name(dev_name);
        pthread_rwlock_unlock(&dev_lock);
        if (!dev) {
                TC_ERR("Traffic control device %s not found.", dev_name);
                return -1;
        }

        // Check if class with same name already exists
        pthread_rwlock_rdlock(dev->class_rwlock);
        tc_class = find_traffic_control_class_by_name(dev, class_name);
        pthread_rwlock_unlock(dev->class_rwlock);
        if (tc_class) {
                if (tc_class->bandwidth_kbps == bandwidth_kbps) {
                        // Same class already exists, nothing to do
                        return 0;
                } else {
                        pthread_rwlock_wrlock(tc_class->update_rwlock);
                        // Update existing class bandwidth
                        if (update_tc_class_bandwidth(tc_class, bandwidth_kbps, dev->netlink->sock) < 0) {
                                TC_ERR("Failed to update bandwidth for existing class %s.", class_name);
                                pthread_rwlock_unlock(tc_class->update_rwlock);
                                return -1;
                        }
                        pthread_rwlock_unlock(tc_class->update_rwlock);
                        return 0;
                }
        }

        pthread_rwlock_wrlock(dev->class_rwlock);
        // Check again in case it was added while we were waiting for the lock
        tc_class = find_traffic_control_class_by_name(dev, class_name);
        if (tc_class) {
                pthread_rwlock_unlock(dev->class_rwlock);
                if (tc_class->bandwidth_kbps == bandwidth_kbps) {
                        return 0;
                } else {
                        pthread_rwlock_wrlock(tc_class->update_rwlock);
                        if (update_tc_class_bandwidth(tc_class, bandwidth_kbps, dev->netlink->sock) < 0) {
                                pthread_rwlock_unlock(tc_class->update_rwlock);
                                TC_ERR("Failed to update bandwidth for existing class %s.", class_name);
                                return -1;
                        }
                        pthread_rwlock_unlock(tc_class->update_rwlock);
                        return 0;
                }
        }
        tc_class = init_traffic_control_class(
                class_name,
                bandwidth_kbps,
                1,  // Major
                get_next_class_minor(dev), // Minor
                dev->link,
                dev->netlink->sock
        );
        if (!tc_class) {
                pthread_rwlock_unlock(dev->class_rwlock);
                TC_ERR("Failed to initialize CDN traffic control class %s.", class_name);
                return -1;
        }
        sblist_add(dev->classes, tc_class);
        pthread_rwlock_unlock(dev->class_rwlock);

        return 0;
}

/*
 * Convert file descriptor to string for use as hash table key
 */
static void fd_to_string(int fd, char *fd_str, size_t fd_str_size) {
        snprintf(fd_str, fd_str_size, "%d", fd);
}

static uint32_t get_ipv4_addr(struct sockaddr_storage *addr) {
        if (addr->ss_family == AF_INET) {
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)addr;
                return ipv4->sin_addr.s_addr;  /* Already in network byte order */
        }
        return 0;  /* Invalid or not IPv4 */
}

static struct in6_addr *get_ipv6_addr(struct sockaddr_storage *addr) {
        if (addr->ss_family == AF_INET6) {
                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)addr;
                return &ipv6->sin6_addr;  /* Already in network byte order */
        }
        return NULL;  /* Invalid or not IPv6 */
}

/*
 * Socket information structure to hold destination details
 */
typedef struct {
        struct sockaddr_storage dest_addr;  /* Destination IP address */
        in_port_t dest_port;                /* Destination port */
        char device_name[IFNAMSIZ];         /* Network device name */
        int valid;                          /* Whether the information is valid */
} socket_info_t;

/*
 * Get destination IP address and port from a socket file descriptor
 */
static int get_socket_destination(int sockfd, struct sockaddr_storage *dest_addr, in_port_t *dest_port) {
        socklen_t addr_len = sizeof(struct sockaddr_storage);

        /* Get peer address (destination for outgoing connections) */
        if (getpeername(sockfd, (struct sockaddr *)dest_addr, &addr_len) < 0) {
                TC_ERR("Failed to get peer address for socket %d: %s", sockfd, strerror(errno));
                return -1;
        }

        /* Extract port based on address family */
        if (dest_addr->ss_family == AF_INET) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)dest_addr;
                *dest_port = ntohs(addr_in->sin_port);
        } else if (dest_addr->ss_family == AF_INET6) {
                struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)dest_addr;
                *dest_port = ntohs(addr_in6->sin6_port);
        } else {
                TC_ERR("Unsupported address family: %d", dest_addr->ss_family);
                return -1;
        }

        return 0;
}

/*
 * Get the network device name by matching socket source IP with interface IPs
 */
static int get_route_device(int sockfd, char *device_name, size_t device_name_size) {
        struct sockaddr_storage src_addr;
        socklen_t src_addr_len = sizeof(src_addr);
        struct ifaddrs *ifaddr, *ifa;
        char src_ip_str[INET6_ADDRSTRLEN];
        int found = 0;

        /* Get the source address of the socket */
        if (getsockname(sockfd, (struct sockaddr *)&src_addr, &src_addr_len) < 0) {
                TC_ERR("Failed to get socket source address: %s", strerror(errno));
                return -1;
        }

        /* Convert source address to string for comparison */
        if (src_addr.ss_family == AF_INET) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)&src_addr;
                if (inet_ntop(AF_INET, &addr_in->sin_addr, src_ip_str, sizeof(src_ip_str)) == NULL) {
                        TC_ERR("Failed to convert IPv4 source address to string.", "");
                        return -1;
                }
        } else if (src_addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&src_addr;
                if (inet_ntop(AF_INET6, &addr_in6->sin6_addr, src_ip_str, sizeof(src_ip_str)) == NULL) {
                        TC_ERR("Failed to convert IPv6 source address to string.", "");
                        return -1;
                }
        } else {
                TC_ERR("Unsupported address family for source: %d", src_addr.ss_family);
                return -1;
        }

        /* Get list of network interfaces */
        if (getifaddrs(&ifaddr) == -1) {
                TC_ERR("Failed to get interface addresses: %s", strerror(errno));
                return -1;
        }
    
        /* Find the interface that has the same IP as our socket's source IP */
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr == NULL) continue;

                /* Skip loopback interfaces unless that's what we're actually using */
                if ((ifa->ifa_flags & IFF_LOOPBACK) && strncmp(src_ip_str, "127.", 4) != 0 && strcmp(src_ip_str, "::1") != 0) continue;

                /* Only consider interfaces that are up and running */
                if (!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_RUNNING)) continue;

                /* Check if this interface has the same IP as our socket's source */
                if (ifa->ifa_addr->sa_family == src_addr.ss_family) {
                        char ifa_ip_str[INET6_ADDRSTRLEN];

                        if (src_addr.ss_family == AF_INET) {
                                struct sockaddr_in *ifa_in = (struct sockaddr_in *)ifa->ifa_addr;
                                if (inet_ntop(AF_INET, &ifa_in->sin_addr, ifa_ip_str, sizeof(ifa_ip_str)) == NULL) {
                                        continue;
                                }
                        } else if (src_addr.ss_family == AF_INET6) {
                                struct sockaddr_in6 *ifa_in6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                                if (inet_ntop(AF_INET6, &ifa_in6->sin6_addr, ifa_ip_str, sizeof(ifa_ip_str)) == NULL) {
                                        continue;
                                }
                        }

                        /* Compare source IP with interface IP */
                        if (strcmp(src_ip_str, ifa_ip_str) == 0) {
                                strncpy(device_name, ifa->ifa_name, device_name_size - 1);
                                device_name[device_name_size - 1] = '\0';
                                found = 1;
                                break;
                        }
                }
        }

        freeifaddrs(ifaddr);

        if (!found) {
                TC_ERR("No interface found for source IP %s", src_ip_str);
                return -1;
        }

        return 0;
}

/*
 * Get comprehensive socket information: destination IP, port, and device
 */
static int get_socket_info(int sockfd, socket_info_t *sock_info) {
        if (!sock_info) {
                TC_ERR("Invalid socket_info_t pointer.", "");
                return -1;
        }

        /* Initialize structure */
        memset(sock_info, 0, sizeof(socket_info_t));
        sock_info->valid = 0;

        /* Get destination address and port */
        if (get_socket_destination(sockfd, &sock_info->dest_addr, &sock_info->dest_port) < 0) {
                return -1;
        }

        /* Get the network device by matching socket source IP with interface IPs */
        if (get_route_device(sockfd, sock_info->device_name, sizeof(sock_info->device_name)) < 0) {
                return -1;
        }

        sock_info->valid = 1;
        return 0;
}

static int init_tc_filter(
    int major,
    int minor,
    uint32_t classid,
    struct sockaddr_storage *addr,
    in_port_t port,
    struct nl_sock *sock,
    struct rtnl_link *link
) {
        struct nl_msg *msg;
        struct tcmsg tc;
        struct nlattr *options;

        msg = nlmsg_alloc();
        if (!msg) {
                TC_ERR("Failed to allocate message.", "");
                return -1;
        }

        memset(&tc, 0, sizeof(tc));
        tc.tcm_family = AF_UNSPEC;
        tc.tcm_ifindex = rtnl_link_get_ifindex(link);
        tc.tcm_parent = TC_HANDLE(1, 0);
        tc.tcm_handle = TC_HANDLE(major, minor);
        tc.tcm_info = 0;

        /* Configure flower filter based on address family */
        if (addr->ss_family == AF_INET) {
                uint32_t ip = get_ipv4_addr(addr);
                if (ip == 0) {
                        TC_ERR("Invalid IPv4 address.", "");
                        nlmsg_free(msg);
                        return -1;
                }
                
                /* Set protocol to IPv4 */
                tc.tcm_info = TC_H_MAKE(1 << 16, htons(ETH_P_IP)); // Priority 1, protocol IP
        
                if (nlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, RTM_NEWTFILTER, sizeof(tc), NLM_F_CREATE | NLM_F_EXCL) == NULL) {
                        TC_ERR("Failed to put nlmsg header.", "");
                        nlmsg_free(msg);
                        return -1;
                }
                memcpy(nlmsg_data(nlmsg_hdr(msg)), &tc, sizeof(tc));

                // Add classifier type attribute
                if (nla_put_string(msg, TCA_KIND, "flower") < 0) {
                        TC_ERR("Failed to set classifier kind to flower.", "");
                        nlmsg_free(msg);
                        return -1;
                }

                // Start options
                options = nla_nest_start(msg, TCA_OPTIONS);
                if (!options) {
                        TC_ERR("Failed to start options attribute.", "");
                        nlmsg_free(msg);
                        return -1;
                }

                // Add ethernet type (IPV4)
                if (nla_put_u16(msg, TCA_FLOWER_KEY_ETH_TYPE, htons(ETH_P_IP)) < 0) {
                        TC_ERR("Failed to set ethernet type to IPv4.", "");
                        nlmsg_free(msg);
                        return -1;
                }

                // Add IPv4 destination address matching
                if (nla_put_u32(msg, TCA_FLOWER_KEY_IPV4_DST, ip) < 0) {
                        TC_ERR("Failed to set IPv4 destination address.", "");
                        nlmsg_free(msg);
                        return -1;
                }
        } else if (addr->ss_family == AF_INET6) {
                struct in6_addr *ipv6 = get_ipv6_addr(addr);
                if (!ipv6) {
                        TC_WARN("Invalid IPv6 address.", "");
                        nlmsg_free(msg);
                        return -1;
                }
                
                /* Set protocol to IPv6 */
                tc.tcm_info = TC_H_MAKE(1 << 16, htons(ETH_P_IPV6)); // Priority 1, protocol IPv6

                if (nlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, RTM_NEWTFILTER, sizeof(tc), NLM_F_CREATE | NLM_F_EXCL) == NULL) {
                        TC_WARN("Failed to put nlmsg header.", "");
                        nlmsg_free(msg);
                        return -1;
                }
                memcpy(nlmsg_data(nlmsg_hdr(msg)), &tc, sizeof(tc));

                /* Add classifier type attribute */
                if (nla_put_string(msg, TCA_KIND, "flower") < 0) {
                        TC_ERR("Failed to set classifier kind to flower.", "");
                        nlmsg_free(msg);
                        return -1;
                }

                /* Start options */
                options = nla_nest_start(msg, TCA_OPTIONS);
                if (!options) {
                        TC_ERR("Failed to start options attribute.", "");
                        nlmsg_free(msg);
                        return -1;
                }

                /* Add ethernet type (IPV6) */
                if (nla_put_u16(msg, TCA_FLOWER_KEY_ETH_TYPE, htons(ETH_P_IPV6)) < 0) {
                        TC_ERR("Failed to set ethernet type to IPv6.", "");
                        nlmsg_free(msg);
                        return -1;
                }

                /* Add IPv6 source address matching */
                if (nla_put(msg, TCA_FLOWER_KEY_IPV6_DST, sizeof(struct in6_addr), ipv6) < 0) {
                        TC_ERR("Failed to set IPv6 destination address.", "");
                        nlmsg_free(msg);
                        return -1;
                }
        } else {
                TC_WARN("Unsupported address family: %d", addr->ss_family);
                nlmsg_free(msg);
                return -1;
        }
        // Add TCP destination port matching if port is non-zero
        if (port != 0) {
                // Add IP protocol (TCP)
                if (nla_put_u8(msg, TCA_FLOWER_KEY_IP_PROTO, IPPROTO_TCP) < 0) {
                        TC_ERR("Failed to set IP protocol to TCP.", "");
                        nlmsg_free(msg);
                        return -1;
                }
                if (nla_put_u16(msg, TCA_FLOWER_KEY_TCP_DST, htons(port)) < 0) {
                        TC_ERR("Failed to set TCP destination port.", "");
                        nlmsg_free(msg);
                        return -1;
                }
        }

        // Add classid attribute
        if (nla_put_u32(msg, TCA_FLOWER_CLASSID, classid) < 0) {
                TC_ERR("Failed to set flower action classid.", "");
                nlmsg_free(msg);
                return -1;
        }

        // End options nesting
        nla_nest_end(msg, options);

        // Send the message to the kernel
        if (nl_send_auto_complete(sock, msg) < 0) {
                TC_ERR("Failed to send message to kernel.", "");
                nlmsg_free(msg);
                return -1;
        }

        // Wait for ACK from kernel
        if (nl_wait_for_ack(sock) < 0) {
                TC_ERR("Failed to receive ACK from kernel.", "");
                nlmsg_free(msg);
                return -1;
        }

        // Free the message as we are done
        nlmsg_free(msg);

        return 0;
}

static void cleanup_tc_filter(uint32_t handle, uint16_t proto, struct nl_sock *sock, struct rtnl_link *link)
{
        struct nl_msg *del_msg;
        struct tcmsg tcm;

        del_msg = nlmsg_alloc();
        if (!del_msg) {
                TC_ERR("Failed to allocate memory for delete message.", "");
                return;
        }

        tcm.tcm_family = AF_UNSPEC;
        tcm.tcm_ifindex = rtnl_link_get_ifindex(link);
        tcm.tcm_handle = handle;
        tcm.tcm_parent = TC_HANDLE(1, 0);
        tcm.tcm_info = TC_H_MAKE(1 << 16, proto);

        if (nlmsg_put(del_msg, NL_AUTO_PID, NL_AUTO_SEQ, RTM_DELTFILTER, sizeof(tcm), 0) == NULL) {
                TC_ERR("Failed to put nlmsg header for delete.", "");
                nlmsg_free(del_msg);
                return;
        }
        memcpy(nlmsg_data(nlmsg_hdr(del_msg)), &tcm, sizeof(tcm));

        if (nla_put_string(del_msg, TCA_KIND, "flower") < 0) {
                TC_ERR("Failed to set classifier kind to flower for delete.", "");
                nlmsg_free(del_msg);
                return;
        }

        if (nl_send_auto_complete(sock, del_msg) < 0) {
                TC_ERR("Failed to send delete message to kernel.", "");
                nlmsg_free(del_msg);
                return;
        }

        // Wait for ACK from kernel
        if (nl_wait_for_ack(sock) < 0) {
                TC_ERR("Failed to receive ACK from kernel for delete.", "");
                nlmsg_free(del_msg);
                return;
        }

        nlmsg_free(del_msg);
}

static void cleanup_traffic_control_filter(traffic_control_filter_t *tc_filter) {
        if (tc_filter) {
                cleanup_tc_filter(
                        tc_filter->handle,
                        tc_filter->proto,
                        tc_filter->dev->netlink->sock,
                        tc_filter->dev->link
                );
                safefree(tc_filter);
        }
}

/*
 * Initialize traffic control filter for a new connection
 */
int setup_traffic_control_conn(int fd, char *name)
{
        socket_info_t sock_info;
        char fd_str[32];
        traffic_control_dev_t *dev = NULL;
        traffic_control_class_t *tc_class = NULL;
        int filter_minor;
        traffic_control_filter_t *tc_filter = NULL;
        char *key = NULL;
        int insert_result;

        // Convert fd to string for use as hash table key
        fd_to_string(fd, fd_str, sizeof(fd_str));

        // Get the device, IP address and port associated with fd
        if(get_socket_info(fd, &sock_info) < 0) {
                TC_WARN("Failed to get socket information.", "");
                return -1;
        }

        // Find the traffic control device for this interface
        pthread_rwlock_rdlock(&dev_lock);
        for (size_t i = 0; i < sblist_getsize(devices); i++) {
                traffic_control_dev_t *d = sblist_get(devices, i);
                if (strcmp(d->name, sock_info.device_name) == 0) {
                        dev = d;
                        break;
                }
        }
        pthread_rwlock_unlock(&dev_lock);
        if (!dev) {
                TC_WARN("Traffic control device for %s not found.", sock_info.device_name);
                return -1;
        }

        // Find the class by name
        pthread_rwlock_rdlock(dev->class_rwlock);
        tc_class = find_traffic_control_class_by_name(dev, name);
        pthread_rwlock_unlock(dev->class_rwlock);
        if (!tc_class) {
                TC_ERR("Traffic control class %s not found on device %s.", name, dev->name);
                return -1;
        }

        // Initialize the filter
        filter_minor = get_next_filter_minor(dev);
        if (init_tc_filter(
                2,
                filter_minor,
                rtnl_tc_get_handle(TC_CAST(tc_class->cls)),
                &sock_info.dest_addr,
                sock_info.dest_port,
                dev->netlink->sock,
                dev->link
        ) < 0) {
                TC_WARN("Failed to initialize traffic control filter for fd %d.", fd);
                return -1;
        }

        // Create traffic control filter structure
        tc_filter = safemalloc(sizeof(traffic_control_filter_t));
        if (!tc_filter) {
                TC_WARN("Failed to allocate memory for traffic control filter.", "");
                cleanup_tc_filter(TC_HANDLE(2, filter_minor),
                                  sock_info.dest_addr.ss_family == AF_INET ? htons(ETH_P_IP) : htons(ETH_P_IPV6),
                                  dev->netlink->sock,
                                  dev->link);
                return -1;
        }
        tc_filter->dev = dev;
        tc_filter->handle = TC_HANDLE(2, filter_minor);
        tc_filter->proto = sock_info.dest_addr.ss_family == AF_INET ? htons(ETH_P_IP) : htons(ETH_P_IPV6);

        // Insert into hash table using string key (thread-safe)
        key = strdup(fd_str);
        if (!key) {
                TC_ERR("Failed to allocate memory for hash table key.", "");
                cleanup_traffic_control_filter(tc_filter);
                return -1;
        }
        pthread_rwlock_wrlock(&filter_lock);
        insert_result = htab_insert(traffic_control_filters, key, HTV_P(tc_filter));
        pthread_rwlock_unlock(&filter_lock);

        if (insert_result != 1) {
                TC_WARN("Failed to insert traffic control filter into hash table.", "");
                cleanup_traffic_control_filter(tc_filter);
                safefree(key);
                return -1;
        }

        return 0;
}

/*
 * Remove traffic control filter by file descriptor
 */
void cleanup_traffic_control_conn(int fd) {
         traffic_control_filter_t *tc_filter = NULL;
         char fd_str[32];
         char *key = NULL;
         htab_value *value = NULL;
        
        // Lookup the filter in the hash table
        fd_to_string(fd, fd_str, sizeof(fd_str));
        pthread_rwlock_rdlock(&filter_lock);
        value = htab_find2(traffic_control_filters, fd_str, &key);
        pthread_rwlock_unlock(&filter_lock);
        if (!value) {
                TC_WARN("Failed to find traffic control filter for fd %d.", fd);
                return;
        }

        // Delete the filter from the hash table
        pthread_rwlock_wrlock(&filter_lock);
        if (htab_delete(traffic_control_filters, fd_str) != 1) {
                TC_WARN("Failed to delete traffic control filter from hash table for fd %d.", fd);
        }
        pthread_rwlock_unlock(&filter_lock);
        safefree(key);

        // Cleanup the filter
        tc_filter = value->p ? (traffic_control_filter_t *)value->p : NULL;
        if (!tc_filter) {
                TC_WARN("Traffic control filter pointer is NULL for fd %d.", fd);
                return;
        }
        cleanup_traffic_control_filter(tc_filter);
}

/*
 * Remove all the traffic control filters in the htab.
 */
void cleanup_all_traffic_control_conns(void)
{
        char *k;
        htab_value *v;
        size_t it = 0;
        while((it = htab_next(traffic_control_filters, it, &k, &v))) {
                cleanup_traffic_control_filter(v->p);
                safefree(k);
        }
        htab_destroy(traffic_control_filters);
}
