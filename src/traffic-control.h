/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 2008 Robert James Kaes <rjk@wormbytes.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef TRAFFIC_CONTROL_H
#define TRAFFIC_CONTROL_H

int setup_netlink(void);
void cleanup_netlink(void);
int setup_traffic_control_dev(char *dev_name);
void cleanup_traffic_control_dev_list(void);
int setup_cdn_traffic_control(char *dev_name, char *class_name, uint64_t bandwidth_kbps);
int setup_traffic_control_conn(int fd, char *name);
void cleanup_traffic_control_conn(int fd);
void cleanup_all_traffic_control_conns(void);

#endif /* TRAFFIC_CONTROL_H */
