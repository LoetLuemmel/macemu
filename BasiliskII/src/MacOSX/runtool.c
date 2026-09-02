/*
 *  runtool.m - Run an external program as root for networking
 *  Copyright (C) 2010, Daniel Sumorok
 *
 *  Basilisk II (C) 1997-2008 Christian Bauer
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#include <errno.h>

#include <unistd.h>

#include <net/if.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <fcntl.h>

#include <strings.h>

#include <Carbon/Carbon.h>

FILE * run_tool(const char *if_name, const char *tool_name);

FILE * run_tool(const char *if_name, const char *tool_name)
{
	OSStatus auth_status;
	FILE *fp = NULL;
	char *args[] = {NULL, NULL, NULL};
	char path_buffer[256];
	AuthorizationFlags auth_flags;
	AuthorizationRef auth_ref;
	AuthorizationItem auth_items[1];
	AuthorizationRights auth_rights;
	CFBundleRef bundle_ref;
	CFURLRef url_ref;
	CFStringRef path_str;
	CFStringRef tool_name_str;
	char c;

	bundle_ref = CFBundleGetMainBundle();
	if(bundle_ref == NULL) {
		return NULL;
	}

	tool_name_str = CFStringCreateWithCString(NULL, tool_name,
						  kCFStringEncodingUTF8);

	url_ref = CFBundleCopyResourceURL(bundle_ref, tool_name_str,
					 NULL, NULL);
	CFRelease(tool_name_str);

	if(url_ref == NULL) {
		return NULL;
	}

	path_str = CFURLCopyFileSystemPath(url_ref, kCFURLPOSIXPathStyle);
	CFRelease(url_ref);

	if(path_str == NULL) {
		return NULL;
	}

	if(!CFStringGetCString(path_str, path_buffer, sizeof(path_buffer),
			       kCFStringEncodingUTF8)) {
		CFRelease(path_str);
		return NULL;
	}
	CFRelease(path_str);

	args[0] = (char *)tool_name;
	args[1] = (char *)if_name;

	/* If the helper is already setuid-root, run it directly — no
	 * AuthorizationExecuteWithPrivileges, hence no password dialog. The tool
	 * speaks its protocol over fd 0 (a bidirectional socket: it write()s the
	 * ready byte and incoming frames to fd 0 and read()s outgoing frames from
	 * it), so we hand it one end of a socketpair as fd 0, exactly the channel
	 * the Authorization path sets up. Anything short of a clean setuid-root
	 * spawn falls through to the auth path below. (AppleBridge, 2026-09-02) */
	{
		struct stat st;

		if (stat(path_buffer, &st) == 0 &&
		    st.st_uid == 0 && (st.st_mode & S_ISUID)) {
			int sv[2];

			if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
				pid_t pid = fork();

				if (pid == 0) {
					close(sv[0]);
					dup2(sv[1], 0);
					if (sv[1] != 0)
						close(sv[1]);
					execl(path_buffer, path_buffer,
					      if_name, (char *)NULL);
					_exit(127);
				} else if (pid > 0) {
					close(sv[1]);
					fp = fdopen(sv[0], "r+");
					if (fp == NULL)
						close(sv[0]);
				} else {
					close(sv[0]);
					close(sv[1]);
				}
			}
		}
	}

	if (fp != NULL)
		goto have_fp;

	auth_flags = kAuthorizationFlagExtendRights |
		kAuthorizationFlagInteractionAllowed |
		kAuthorizationFlagPreAuthorize;
 
	auth_items[0].name = "system.privilege.admin";
	auth_items[0].valueLength = 0;
	auth_items[0].value = NULL;
	auth_items[0].flags = 0;

	auth_rights.count = sizeof (auth_items) / sizeof (auth_items[0]);
	auth_rights.items = auth_items;
  
	auth_status = AuthorizationCreate(&auth_rights,
					  kAuthorizationEmptyEnvironment,
					  auth_flags,
					  &auth_ref);
  
	if (auth_status != errAuthorizationSuccess) {
		fprintf(stderr, "%s: AuthorizationCreate() failed.\n",
			__func__);
		return NULL;
	}

	auth_status = AuthorizationExecuteWithPrivileges(auth_ref,
							 path_buffer,
							 kAuthorizationFlagDefaults,
							 args + 1,
							 &fp);

	if (auth_status != errAuthorizationSuccess) {
		fprintf(stderr, "%s: AuthorizationExecWithPrivileges() failed.\n", 
			__func__);
		return NULL;
	}

 have_fp:
	if(fread(&c, 1, 1, fp) != 1) {
	  fclose(fp);
	  return NULL;
	}

	return fp;
}
