/*
 * Rdisc for Ubuntu
 * Contact us on
 * juakali.networks@gmail.com
 * We ask for a donation to a charity in Tanzania to help orphaned Kids
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <error.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <linux/route.h> 
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <mip.h>
#include "sockios.h"
#include "stdarg.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/udp.h>
#include <stdint.h>
#include <time.h>


/*
 * 			M A I N
 */
char    *sendaddress, *recvaddress;


int main(int argc, char **argv) 
{
 
	struct sockaddr_in from = { 0 };
	char **av = argv;
	struct sockaddr_in *to = &whereto;
	struct sockaddr_in joinaddr;
	sigset_t sset, sset_empty;
	char buff[PCKT_LEN];

#ifdef RDISC_SERVER
	int val;

	/* atexit(close_stdout); */
	min_adv_int =( max_adv_int * 3 / 4);
	lifetime = (3*max_adv_int);
#endif

	argc--, av++;
	while (argc > 0 && *av[0] == '-') {
		while (*++av[0]) {
			switch (*av[0]) {
			case 'd':
				debug = 1;
				break;
			case 't':
				trace = 1;
				break;
			case 'v':
				verbose++;
				break;
			case 's':
				solicit = 1;
				break;
			case 'm':
				agent_advert = 1;
				break;
			case 'r':
				reg_request = 1;
				break;
			case 'a':
				best_preference = 0;
				break;
			case 'b':
				best_preference = 1;
				break;
			case 'f':
				forever = 1;
				break;
			case 'V':
				/* printf(IPUTILS_VERSION("rdisc")); */
				printf("Compiled %s ENABLE_RDISC_SERVER.\n",
#ifdef RDISC_SERVER
						"with"
#else
						"without"
#endif
				);
				exit(0);
#ifdef RDISC_SERVER
			case 'T':
				argc--, av++;
				if (argc != 0) {
					val = strtol(av[0], (char **)NULL, 0);
					if (val < 4 || val > 1800)
						error(1, 0, "Bad Max Advertisement Interval: %d",
							     val);
					max_adv_int = val;
					min_adv_int =( max_adv_int * 3 / 4);
					lifetime = (3*max_adv_int);
				} else {
					prusage();
					/* NOTREACHED*/
				}
				goto next;
			case 'p':
				argc--, av++;
				if (argc != 0) {
					val = strtol(av[0], (char **)NULL, 0);
					preference = val;
				} else {
					prusage();
					/* NOTREACHED*/
				}
				goto next;
#endif
			default:
				prusage();
				/* NOTREACHED*/
			}
		}
#ifdef RDISC_SERVER
next:
#endif
		argc--, av++;
	}
	if( argc < 1)  {
		if (support_multicast()) {
			sendaddress = ALL_ROUTERS_ADDRESS;
#ifdef RDISC_SERVER
			if (agent_advert || reg_request)
				sendaddress = ALL_HOSTS_ADDRESS;
#endif
		} else
			sendaddress = "255.255.255.255";
	} else {
		sendaddress = av[0];
		argc--;
	}

	if (argc < 1) {
		if (support_multicast()) {
			recvaddress = ALL_HOSTS_ADDRESS;
			
			if (agent_advert || reg_request)
				recvaddress = ALL_ROUTERS_ADDRESS;
		

		} else
			recvaddress = "255.255.255.255";
	} else {
		recvaddress = av[0];
		argc--;
	}
	if (argc != 0) {
		error(0, 0, "Extra parameters");
		prusage();
		/* NOTREACHED */
	}

#ifdef RDISC_SERVER
	if (solicit && agent_advert && reg_request) {
		prusage();
		/* NOTREACHED */
	}
#endif

	if (!(solicit && !forever)) {
		do_fork();
/*
 * Added the next line to stop forking a second time
 * Fraser Gardiner - Sun Microsystems Australia
 */
		forever = 1;
	}

	if (reg_request){
		
		if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
     			logperror("socket failed");
			exit(5);
    	 	}
	
            registration_request(60, sockfd);
			};
		/*			if ((socketfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
     			logperror("socket failed");
			exit(5);
    	 	}
*/
//	if (agent_advert){

	/* 	if ((sock_check = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
     			logperror("socket failed");
				logmsg(LOG_INFO, "ffffffffffffffffff:\n");
			exit(5);
    	 	}
			logmsg(LOG_INFO, "mmmmmmmmmmmmmmmmmmmmm:\n");

			while (read(sock_check, buff, PCKT_LEN)) {
            registration_request(60);
			logmsg(LOG_INFO, "ggggggggggggggggggggggggggggggg:\n");

		}*/
	//}


	memset( (char *)&whereto, 0, sizeof(struct sockaddr_in) );
	to->sin_family = AF_INET;

	to->sin_addr.s_addr = inet_addr(sendaddress);

	memset( (char *)&joinaddr, 0, sizeof(struct sockaddr_in) );
	joinaddr.sin_family = AF_INET;

	joinaddr.sin_addr.s_addr = inet_addr(recvaddress);
/*Cleanup: Reactivate this code
 #ifdef RDISC_SERVER
	if (responder)
		iputils_srand();
#endif*/

	if ((socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		logperror("socket");
		exit(5);
	}


	setlinebuf( stdout );

	signal_setup(SIGINT, finish );
	signal_setup(SIGTERM, graceful_finish );
	signal_setup(SIGHUP, initifs );
	signal_setup(SIGALRM, timer );

	sigemptyset(&sset);
	sigemptyset(&sset_empty);
	sigaddset(&sset, SIGALRM);
	sigaddset(&sset, SIGHUP);
	sigaddset(&sset, SIGTERM);
	sigaddset(&sset, SIGINT);

	init();
	if (join(socketfd, &joinaddr) < 0) {
		logmsg(LOG_ERR, "Failed joining addresses\n");
		exit (2);
	}

	timer();	/* start things going */

	for (;;) {
		unsigned char	packet[MAXPACKET];
		int len = sizeof (packet);
		socklen_t fromlen = sizeof (from);
		int cc;
		int dd;


		logmsg(LOG_INFO, "Checkuing the point we are at...:\n");

		logmsg(LOG_INFO, "Len %d:\n", len);
		logmsg(LOG_INFO, "socketfd %d:\n", socketfd);


		cc=recvfrom(socketfd, (char *)packet, len, 0,
			    (struct sockaddr *)&from, &fromlen);
	
		logmsg(LOG_INFO, "We ggg have reached at the point here...:\n");

		logmsg(LOG_INFO, "ccc %d:\n", cc);

		/*dd=recvfrom(sock_check, (char *)packet, len, 0,
			    (struct sockaddr *)&from, &fromlen);

		logmsg(LOG_INFO, "Yes we have reached at the point here...:\n");

		logmsg(LOG_INFO, "dddd %d:\n", dd);
*/
		/*if (cc<0) {
			if (errno == EINTR)
				continue;
			logperror("recvfrom");
			continue;
		}*/
		
		sigprocmask(SIG_SETMASK, &sset, NULL);
	        pr_pack( (char *)packet, cc, &from );
		sigprocmask(SIG_SETMASK, &sset_empty, NULL);
	}
	/*NOTREACHED*/
}
/*
 * 			S O L I C I T O R
 *
 * Compose and transmit an ICMP ROUTER SOLICITATION REQUEST packet.
 * The IP packet will be added on by the kernel.
 */
void
solicitor(struct sockaddr_in *sin)
{
	static unsigned char outpack[MAXPACKET];
	struct icmphdr *icmph = (struct icmphdr *) ALLIGN(outpack);;
	int packetlen, i;

	icmph->type = ICMP_ROUTERSOLICIT;
	icmph->code = 0;
	icmph->checksum = 0;
	icmph->un.gateway = 0; /* Reserved */
	packetlen = 8;
	/* Compute ICMP checksum here */
        icmph->checksum = in_cksum((unsigned short *)icmph, packetlen);

	logmsg(LOG_INFO, "isbroadcast: %d\n", isbroadcast(sin));
	logmsg(LOG_INFO, "ismulticast: %d\n", ismulticast(sin));
	logmsg(LOG_INFO, "Sending solicitations to %s\n", pr_name(sin->sin_addr));

	
	if (ismulticast(sin))
		i = sendmcast(socketfd, (char *)outpack, packetlen, sin);
	else if (isbroadcast(sin))
		i = sendbcast(socketfd, (char *)outpack, packetlen);

	else
		i = sendto(socketfd, (char *)outpack, packetlen, 0,
			   (struct sockaddr *)sin, sizeof(struct sockaddr));

	if( i < 0 || i != packetlen )  {
		if( i<0 ) {
		    logperror("solicitor:sendto");
		}
		logmsg(LOG_ERR, "wrote %s %d chars, ret=%d\n", sendaddress, packetlen, i );
	}
	
}


/*
 * 		A G E N T	A D V E R T I S E M E N T
 *
 * Compose and transmit an ICMP AGENT ADVERTISEMENT packet.
 * The IP packet will be added on by the kernel.
 */
void
advertise(struct sockaddr_in *sin, int lft)
{
	static unsigned char outpack[MAXPACKET];
	struct icmp_ra *rap = (struct icmp_ra *) ALLIGN(outpack);
	struct icmp_ra_ext *rap_ext = (struct icmp_ra_ext *) ALLIGN(outpack);
	struct icmp_ra_addr *ap;
	int packetlen, i, cc;

	if (verbose) {
		logmsg(LOG_INFO, "Sending advertisement to %s\n",
			 pr_name(sin->sin_addr));
	}

	for (i = 0; i < num_interfaces; i++) {
		rap->icmp_type = ICMP_ROUTERADVERT;
		rap->icmp_code = ICMP_AGENTADVERT;
		rap->icmp_cksum = 0;
		rap->icmp_num_addrs = 0;
		rap->icmp_wpa = 2;
		rap->icmp_lifetime = htons(lft);
		packetlen = 8;
	/*	rap_ext->mip_adv_ext_type = ICMP_REGREQUEST;*/


		/*
		 * TODO handle multiple logical interfaces per
		 * physical interface. (increment with rap->icmp_wpa * 4 for
		 * each address.)
		 */
		ap = (struct icmp_ra_addr *)ALLIGN(outpack + ICMP_MINLEN);
		ap->ira_addr = interfaces[i].localaddr.s_addr;
		ap->ira_preference = htonl(interfaces[i].preference);
		packetlen += rap->icmp_wpa * 4;
		rap->icmp_num_addrs++;

		/* Compute ICMP checksum here */
		rap->icmp_cksum = in_cksum( (unsigned short *)rap, packetlen );

		if (isbroadcast(sin))
			cc = sendbcastif(socketfd, (char *)outpack, packetlen,
					&interfaces[i]);
		else if (ismulticast(sin))
			cc = sendmcastif(socketfd, (char *)outpack, packetlen, sin,
					&interfaces[i]);
		else {
			struct interface *ifp = &interfaces[i];
			/*
			 * Verify that the interface matches the destination
			 * address.
			 */
			if ((sin->sin_addr.s_addr & ifp->netmask.s_addr) ==
			    (ifp->address.s_addr & ifp->netmask.s_addr)) {
				if (debug) {
					logmsg(LOG_DEBUG, "Unicast to %s ",
						 pr_name(sin->sin_addr));
					logmsg(LOG_DEBUG, "on interface %s, %s\n",
						 ifp->name,
						 pr_name(ifp->address));
				}
				cc = sendto(socketfd, (char *)outpack, packetlen, 0,
					    (struct sockaddr *)sin,
					    sizeof(struct sockaddr));
			} else
				cc = packetlen;
		}
		if( cc < 0 || cc != packetlen )  {
			if (cc < 0) {
				logperror("sendto");
			} else {
				logmsg(LOG_ERR, "wrote %s %d chars, ret=%d\n",
				       sendaddress, packetlen, cc );
			}
		}
	}
}

/*
 *  M O B I L E   R E G I S T R A T I O N     R E Q U E S T
 *
 * Compose and transmit an ICMP MOBILE REGISTRATION REQUEST  packet.
 * The IP packet will be added on by the kernel.
*/

void
registration_request(int lft, int sockfd)
{
  	static unsigned char outpack[MAXPACKET];
    //struct reg_req *rreq = (struct reg_req *) ALLIGN(outpack);


	struct sockaddr_in addr;

    int packetlen, i;
	int sock;
	struct iphdr *ip;
    char buff[PCKT_LEN];




	memset(buff, 0, PCKT_LEN);

    logmsg(LOG_INFO, "Start logging 1111\n");
	ip = (struct iphdr *)buff;

	struct reg_req  *rreq = (struct reg_req *)buff;



	while (read(sockfd, buff, PCKT_LEN)) {


			// create a raw socket with UDP protocol

			sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);		    		

	  		if (sock < 0) {
    			perror("socket() error");
    			exit(2);
  			}

      		addr.sin_family = AF_INET;
      		addr.sin_port = htons(434);
      		addr.sin_addr.s_addr = inet_addr(inet_ntoa(*(struct in_addr *)&(ip->saddr)));
			//addr.sin_addr.s_addr = inet_addr("172.20.10.117");
			rreq->reg_req_type = ICMP_REGREQUEST;
			rreq->flags = 0;
			rreq->reg_req_lifetime = htons(lft);
 			rreq->home_addr = inet_addr(inet_ntoa(*(struct in_addr *)&(ip->daddr)));
			rreq-> gw_fa_addr = inet_addr(inet_ntoa(*(struct in_addr *)&(ip->daddr)));
			rreq->care_of_addr = inet_addr(inet_ntoa(*(struct in_addr *)&(ip->saddr)));
			rreq->reg_req_id = get_time();

	  		packetlen = sizeof(struct reg_req);

      		if (sendto(sock, buff, packetlen, 0,
             	(struct sockaddr *)&addr, sizeof(addr)) < 0)
         		{
                 	perror("sendto()");
                 	exit(3);
        		}

			close(sock);

      		}
			

      		close(socketfd);
		if( i < 0 || i != packetlen )  {
                	if( i<0 ) {
                    	logperror("registratin_request:sendto");
               	 }
                	logmsg(LOG_ERR, "wrote %s %d chars, ret=%d\n", sendaddress, packetlen, i);
	}

}

int sendmcast(int socket, char *packet, int packetlen, struct sockaddr_in *sin)
{
	int i, cc;

	for (i = 0; i < num_interfaces; i++) {

		if ((interfaces[i].flags & (IFF_BROADCAST|IFF_POINTOPOINT|IFF_MULTICAST)) == 0)
			continue;
	       cc = sendmcastif(socket, packet, packetlen, sin, &interfaces[i]);
		if (cc!= packetlen) {
			return (cc);
		}
	}
	return (packetlen);
}


int sendmcastif(int socket, char *packet, int packetlen, struct sockaddr_in *sin,
	    struct interface *ifp)
	{
	int cc;
	struct ip_mreqn mreqn;
	memset(&mreqn, 0, sizeof(mreqn));
	mreqn.imr_ifindex = ifp->ifindex;
	mreqn.imr_address = ifp->localaddr;
	printf("Multicast to interface %s, %s\n", ifp->name, pr_name(mreqn.imr_address));

	if (setsockopt(socket, IPPROTO_IP, IP_MULTICAST_IF,
		       (char *)&mreqn,
		       sizeof(mreqn)) < 0) {
				printf("setsockopt (IP_MULTICAST_IF): Cannot send multicast packet over interface %s, %s\n", ifp->name, pr_name(mreqn.imr_address));
		return (-1);

	}
	cc = sendto(socket, packet, packetlen, 0,
		    (struct sockaddr *)sin, sizeof (struct sockaddr));
	if (cc!= packetlen) {
		printf("sendmcast: Cannot send multicast packet over interface %s, %s\n",
		       ifp->name, pr_name(mreqn.imr_address));
	}
	return (cc);
}

int
sendbcast(int socket, char *packet, int packetlen)
{
	int i, cc;

	for (i = 0; i < num_interfaces; i++) {
		if ((interfaces[i].flags & (IFF_BROADCAST|IFF_POINTOPOINT)) == 0)
			continue;
		cc = sendbcastif(socket, packet, packetlen, &interfaces[i]);
		if (cc!= packetlen) {
			return (cc);
		}
	}
	return (packetlen);
}

int
sendbcastif(int socket, char *packet, int packetlen, struct interface *ifp)
{
	int on;
	int cc;
	struct sockaddr_in baddr;

	baddr.sin_family = AF_INET;
	baddr.sin_addr = ifp->bcastaddr;
	if (debug)
		logmsg(LOG_DEBUG, "Broadcast to %s\n",
			 pr_name(baddr.sin_addr));
	on = 1;
	setsockopt(socket, SOL_SOCKET, SO_BROADCAST, (char*)&on, sizeof(on));
	cc = sendto(socket, packet, packetlen, 0,
		    (struct sockaddr *)&baddr, sizeof (struct sockaddr));
	if (cc!= packetlen) {
		logperror("sendbcast: sendto");
		logmsg(LOG_ERR, "Cannot send broadcast packet to %s\n",
		       pr_name(baddr.sin_addr));
	}
	on = 0;
	setsockopt(socket, SOL_SOCKET, SO_BROADCAST, (char*)&on, sizeof(on));
	return (cc);
}

int support_multicast()
{
	int sock;
	unsigned char ttl = 1;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		logperror("support_multicast: socket");
		return (0);
	}

	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL,
		       (char *)&ttl, sizeof(ttl)) < 0) {
		(void) close(sock);
		return (0);
	}
	(void) close(sock);
	return (1);
}

int join(int sock, struct sockaddr_in *sin)
{
	int i, j;
	struct ip_mreqn mreq;
	int *joined;

	if (isbroadcast(sin))
		return (0);

	if ((joined = calloc(num_interfaces, sizeof(int))) == NULL) {
		logperror("cannot allocate memory");
		return (-1);
	}
	mreq.imr_multiaddr = sin->sin_addr;
	for (i = 0; i < num_interfaces; i++) {
		for (j = 0; j < i; j++) {
			if (joined[j] == interfaces[i].ifindex)
				break;
		}
		if (j != i)
			continue;

		mreq.imr_ifindex = interfaces[i].ifindex;
		mreq.imr_address.s_addr = 0;

		if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
			       (char *)&mreq, sizeof(mreq)) < 0) {
			logperror("setsockopt (IP_ADD_MEMBERSHIP)");
			free(joined);
			return (-1);
		}

		joined[i] = interfaces[i].ifindex;
	}
	free(joined);
	return (0);
}

int is_directly_connected(struct in_addr in)
{
	int i;

	for (i = 0; i < num_interfaces; i++) {
		/* Check that the subnetwork numbers match */

		if ((in.s_addr & interfaces[i].netmask.s_addr ) ==
		    (interfaces[i].remoteaddr.s_addr & interfaces[i].netmask.s_addr))
			return (1);
	}
	return (0);
}

/* Note: this might leave the kernel with no default route for a short time. */
void age_table(int time)
{
	struct table **tpp, *tp;
	int recalculate_max = 0;
	int max = max_preference();

	tpp = &table;
	while (*tpp != NULL) {
		tp = *tpp;
		tp->remaining_time -= time;
		if (tp->remaining_time <= 0) {
			*tpp = tp->next;
			if (tp->in_kernel)
				del_route(tp->router);
			if (best_preference &&
			    tp->preference == max)
				recalculate_max++;
			free((char *)tp);
		} else {
			tpp = &tp->next;
		}
	}
	if (recalculate_max) {
		int max_pref = max_preference();

		if (max_pref != (int) INELIGIBLE_PREF) {
			tp = table;
			while (tp) {
				if (tp->preference == max_pref && !tp->in_kernel) {
					add_route(tp->router);
					tp->in_kernel++;
				}
				tp = tp->next;
			}
		}
	}
}

void discard_table(void)
{
	struct table **tpp, *tp;

	tpp = &table;
	while (*tpp != NULL) {
		tp = *tpp;
		*tpp = tp->next;
		if (tp->in_kernel)
			del_route(tp->router);
		free((char *)tp);
	}
}

void record_router(struct in_addr router, int pref, int ttl)
{
	struct table *tp;
	int old_max = max_preference();
	int changed_up = 0;	/* max preference could have increased */
	int changed_down = 0;	/* max preference could have decreased */

	if (ttl < 4)
		pref = INELIGIBLE_PREF;

	if (debug)
		logmsg(LOG_DEBUG, "Recording %s, ttl %d, preference 0x%x\n",
			 pr_name(router),
			 ttl,
			 pref);
	tp = find_router(router);
	if (tp) {
		if (tp->preference > pref &&
		    tp->preference == old_max)
			changed_down++;
		else if (pref > tp->preference)
			changed_up++;
		tp->preference = pref;
		tp->remaining_time = ttl;
	} else {
		if (pref > old_max)
			changed_up++;
		tp = (struct table *)ALLIGN(malloc(sizeof(struct table)));
		if (tp == NULL) {
			logmsg(LOG_ERR, "Out of memory\n");
			return;
		}
		tp->router = router;
		tp->preference = pref;
		tp->remaining_time = ttl;
		tp->in_kernel = 0;
		tp->next = table;
		table = tp;
	}
	if (!tp->in_kernel &&
	    (!best_preference || tp->preference == max_preference()) &&
	    tp->preference != (int) INELIGIBLE_PREF) {
		add_route(tp->router);
		tp->in_kernel++;
	}
	if (tp->preference == (int) INELIGIBLE_PREF && tp->in_kernel) {
		del_route(tp->router);
		tp->in_kernel = 0;
	}
	if (best_preference && changed_down) {
		/* Check if we should add routes */
		int new_max = max_preference();
		if (new_max != (int) INELIGIBLE_PREF) {
			tp = table;
			while (tp) {
				if (tp->preference == new_max &&
				    !tp->in_kernel) {
					add_route(tp->router);
					tp->in_kernel++;
				}
				tp = tp->next;
			}
		}
	}
	if (best_preference && (changed_up || changed_down)) {
		/* Check if we should remove routes already in the kernel */
		int new_max = max_preference();
		tp = table;
		while (tp) {
			if (tp->preference < new_max && tp->in_kernel) {
				del_route(tp->router);
				tp->in_kernel = 0;
			}
			tp = tp->next;
		}
	}
}

struct table *find_router(struct in_addr addr)
{
	struct table *tp;

	tp = table;
	while (tp) {
		if (tp->router.s_addr == addr.s_addr)
			return (tp);
		tp = tp->next;
	}
	return (NULL);
}

void add_route(struct in_addr addr)
{
	if (debug)
		logmsg(LOG_DEBUG, "Add default route to %s\n", pr_name(addr));
	rtioctl(addr, SIOCADDRT);
}

void del_route(struct in_addr addr)
{
	if (debug)
		logmsg(LOG_DEBUG, "Delete default route to %s\n", pr_name(addr));
	rtioctl(addr, SIOCDELRT);
}

void rtioctl(struct in_addr addr, int op)
{
	int sock;
	struct rtentry rt;
	struct sockaddr_in *sin;

	memset((char *)&rt, 0, sizeof(struct rtentry));
	rt.rt_dst.sa_family = AF_INET;
	rt.rt_gateway.sa_family = AF_INET;
	rt.rt_genmask.sa_family = AF_INET;
	sin = (struct sockaddr_in *)ALLIGN(&rt.rt_gateway);
	sin->sin_addr = addr;
	rt.rt_flags = RTF_UP | RTF_GATEWAY;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		logperror("rtioctl: socket");
		return;
	}
	if (ioctl(sock, op, (char *)&rt) < 0) {
		if (!(op == SIOCADDRT && errno == EEXIST))
			logperror("ioctl (add/delete route)");
	}
	(void) close(sock);
}

/*
 *			P R _ N A M E
 *
 * Return a string name for the given IP address.
 */
char *pr_name(struct in_addr addr)
{
	struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr = addr };
	char hnamebuf[NI_MAXHOST] = "";
	static char buf[sizeof(hnamebuf) + INET6_ADDRSTRLEN + sizeof(" ()")];

	getnameinfo((struct sockaddr *) &sin, sizeof sin, hnamebuf, sizeof hnamebuf, NULL, 0, 0);
	snprintf(buf, sizeof buf, "%s (%s)", hnamebuf, inet_ntoa(addr));
	return(buf);
}

/*
 *			I N _ C K S U M
 *
 * Checksum routine for Internet Protocol family headers (C Version)
 *
 */
#if BYTE_ORDER == LITTLE_ENDIAN
# define ODDBYTE(v)	(v)
#elif BYTE_ORDER == BIG_ENDIAN
# define ODDBYTE(v)	((unsigned short)(v) << 8)
#else
# define ODDBYTE(v)	htons((unsigned short)(v) << 8)
#endif

unsigned short in_cksum(unsigned short *addr, int len)
{
	int nleft = len;
	unsigned short *w = addr;
	unsigned short answer;
	int sum = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while( nleft > 1 )  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if( nleft == 1 )
		sum += ODDBYTE(*(unsigned char *)w);	/* le16toh() may be unavailable on old systems */

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

unsigned short csum(unsigned short *buf, int nwords)
{
  unsigned long sum;
  for(sum=0; nwords>0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum &0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}


void init()
{
	initifs();
#ifdef RDISC_SERVER
	{
		int i;
		for (i = 0; i < interfaces_size; i++)
			interfaces[i].preference = preference;
	}
#endif
}


void initifs()
{
	int	sock;
	struct ifconf ifc;
	struct ifreq ifreq, *ifr;
	struct sockaddr_in *sin;
	int n, i;
	char *buf;
	int numifs;
	unsigned bufsize;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		logperror("initifs: socket");
		return;
	}
#ifdef SIOCGIFNUM
	if (ioctl(sock, SIOCGIFNUM, (char *)&numifs) < 0) {
		numifs = MAXIFS;
	}
#else
	numifs = MAXIFS;
#endif
	bufsize = numifs * sizeof(struct ifreq);
	buf = (char *)malloc(bufsize);
	if (buf == NULL) {
		logmsg(LOG_ERR, "out of memory\n");
		(void) close(sock);
		return;
	}
	if (interfaces != NULL)
		(void) free(interfaces);
	interfaces = (struct interface *)ALLIGN(malloc(numifs *
					sizeof(struct interface)));
	if (interfaces == NULL) {
		logmsg(LOG_ERR, "out of memory\n");
		(void) close(sock);
		(void) free(buf);
		return;
	}
	interfaces_size = numifs;

	ifc.ifc_len = bufsize;
	ifc.ifc_ifcu.ifcu_buf = buf;
	
	if (ioctl(sock, SIOCGIFCONF, (char *)&ifc) < 0) {
		logperror("initifs: ioctl (get interface configuration--)");
		(void) close(sock);
		(void) free(buf);
		return;
	}
	ifr = ifc.ifc_req;
	for (i = 0, n = ifc.ifc_len/sizeof (struct ifreq); n > 0; n--, ifr++) {
		ifreq = *ifr;

		if (ioctl(sock, SIOCGIFFLAGS, (char *)&ifreq) < 0) {
			logperror("initifs: ioctl (get interface flags)");
			continue;
		}
		if (ifr->ifr_addr.sa_family != AF_INET)
			continue;
		if ((ifreq.ifr_flags & IFF_UP) == 0)
			continue;
		if (ifreq.ifr_flags & IFF_LOOPBACK)
			continue;
		if ((ifreq.ifr_flags & (IFF_MULTICAST|IFF_BROADCAST|IFF_POINTOPOINT)) == 0)
			continue;
		strncpy(interfaces[i].name, ifr->ifr_name, IFNAMSIZ-1);

		sin = (struct sockaddr_in *)ALLIGN(&ifr->ifr_addr);
		interfaces[i].localaddr = sin->sin_addr;
		interfaces[i].flags = ifreq.ifr_flags;
		interfaces[i].netmask.s_addr = (uint32_t)0xffffffff;
		if (ioctl(sock, SIOCGIFINDEX, (char *)&ifreq) < 0) {
			logperror("initifs: ioctl (get ifindex)");
			continue;
		}
		interfaces[i].ifindex = ifreq.ifr_ifindex;
		if (ifreq.ifr_flags & IFF_POINTOPOINT) {
			if (ioctl(sock, SIOCGIFDSTADDR, (char *)&ifreq) < 0) {
				logperror("initifs: ioctl (get destination addr)");
				continue;
			}
			sin = (struct sockaddr_in *)ALLIGN(&ifreq.ifr_addr);
			/* A pt-pt link is identified by the remote address */
			interfaces[i].address = sin->sin_addr;
			interfaces[i].remoteaddr = sin->sin_addr;
			/* Simulate broadcast for pt-pt */
			interfaces[i].bcastaddr = sin->sin_addr;
			interfaces[i].flags |= IFF_BROADCAST;
		} else {
			/* Non pt-pt links are identified by the local address */
			interfaces[i].address = interfaces[i].localaddr;
			interfaces[i].remoteaddr = interfaces[i].address;
			if (ioctl(sock, SIOCGIFNETMASK, (char *)&ifreq) < 0) {
				logperror("initifs: ioctl (get netmask)");
				continue;
			}
			sin = (struct sockaddr_in *)ALLIGN(&ifreq.ifr_addr);
			interfaces[i].netmask = sin->sin_addr;
			if (ifreq.ifr_flags & IFF_BROADCAST) {
				if (ioctl(sock, SIOCGIFBRDADDR, (char *)&ifreq) < 0) {
					logperror("initifs: ioctl (get broadcast address)");
					continue;
				}
				sin = (struct sockaddr_in *)ALLIGN(&ifreq.ifr_addr);
				interfaces[i].bcastaddr = sin->sin_addr;
			}
		}
		i++;
	}
	num_interfaces = i;
	(void) close(sock);
	(void) free(buf);
}

void signal_setup(int signo, void (*handler)(void))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));

	sa.sa_handler = (void (*)(int))handler;
	sigaction(signo, &sa, NULL);
}

void timer()
{
	static int time;
	static int left_until_getifconf;
	static int left_until_solicit;


	time += TIMER_INTERVAL;

	left_until_getifconf -= TIMER_INTERVAL;
	left_until_advertise -= TIMER_INTERVAL;
	left_until_solicit -= TIMER_INTERVAL;

	if (left_until_getifconf < 0) {
		initifs();
		left_until_getifconf = GETIFCONF_TIMER;
	}
#ifdef RDISC_SERVER
	if ((agent_advert || reg_request) && left_until_advertise <= 0) {
		ntransmitted++;
		if (agent_advert)
                        advertise(&whereto, lifetime);
                if (reg_request)
                        registration_request(lifetime, sockfd);

		if (ntransmitted < initial_advertisements)
			left_until_advertise = initial_advert_interval;
		else
			left_until_advertise = min_adv_int +
				((max_adv_int - min_adv_int) *
				 (rand() % 1000)/1000);
	} else
#endif
	if (solicit && left_until_solicit <= 0) {
		ntransmitted++;
		solicitor(&whereto);
		if (ntransmitted < max_solicitations)
			left_until_solicit = solicitation_interval;
		else {
			solicit = 0;
			if (!forever && nreceived == 0)
				exit(5);
		}
	}
	age_table(TIMER_INTERVAL);
	alarm(TIMER_INTERVAL);
}

void do_fork(void)
{
	if (trace)
		return;
	if (daemon(0, 0) < 0)
		error(1, errno, "failed to daemon()");
	initlog();
}


void graceful_finish()
{
	discard_table();
	finish();
	exit(0);
}

void prusage(void)
{
	fprintf(stderr,
		"\nUsage\n"
		"  rdisc [options] <send address> <receive address>\n"
		"\nOptions:\n"
		"  -a               accept all routers\n"
		"  -b               accept best only (default)\n"
		"  -d               enable debug syslog messages\n"
		"  -f               run forever\n"
		"  -x               reiimfTse this. only for testing copilling\n"
		"  -m               Agent Advertising mode\n"
		"  -r               Registration Request mode\n"
		"  -s               send solicitation messages at startup\n"
		"  -p <preference>  set <preference> in advertisement\n"
		"  -T <seconds>     set max advertisement interval in <seconds>\n"
		"  -t               test mode, do not go background\n"
		"  -v               verbose mode\n"
		"  -V               print version and exit\n"
		"\nFor more details see rdisc(8).\n"
	);
	exit(1);
}

int max_preference(void)
{
	struct table *tp;
	int max = (int)INELIGIBLE_PREF;

	tp = table;
	while (tp) {
		if (tp->preference > max)
			max = tp->preference;
		tp = tp->next;
	}
	return (max);
}

/*
 *			P R _ P A C K
 *
 * Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
void pr_pack(char *buf, int cc, struct sockaddr_in *from)
{
	struct iphdr *iph;
	struct icmphdr *icmph;
	int i;
	int hlen;

	iph = (struct iphdr *) ALLIGN(buf);
	hlen = iph->ihl << 2;
	if (cc < hlen + 8) {
		if (verbose)
			logmsg(LOG_INFO, "packet too short (%d bytes) from %s\n", cc,
				 pr_name(from->sin_addr));
		return;
	}
	cc -= hlen;
	icmph = (struct icmphdr *)ALLIGN(buf + hlen);

	switch (icmph->type) {
	case ICMP_ROUTERADVERT:
	{
		struct icmp_ra *rap = (struct icmp_ra *)ALLIGN(icmph);
		struct icmp_ra_addr *ap;

#ifdef RDISC_SERVER
		if (agent_advert || reg_request)
			break;
#endif

		/* TBD verify that the link is multicast or broadcast */
		/* XXX Find out the link it came in over? */
		if (in_cksum((unsigned short *)ALLIGN(buf+hlen), cc)) {
			if (verbose)
				logmsg(LOG_INFO, "ICMP %s from %s: Bad checksum\n",
					 pr_type((int)rap->icmp_type),
					 pr_name(from->sin_addr));
			return;
		}
		if (rap->icmp_code != 0) {
			if (verbose)
				logmsg(LOG_INFO, "ICMP %s from %s: Code = %d\n",
					 pr_type((int)rap->icmp_type),
					 pr_name(from->sin_addr),
					 rap->icmp_code);
			return;
		}
		if (rap->icmp_num_addrs < 1) {
			if (verbose)
				logmsg(LOG_INFO, "ICMP %s from %s: No addresses\n",
					 pr_type((int)rap->icmp_type),
					 pr_name(from->sin_addr));
			return;
		}
		if (rap->icmp_wpa < 2) {
			if (verbose)
				logmsg(LOG_INFO, "ICMP %s from %s: Words/addr = %d\n",
					 pr_type((int)rap->icmp_type),
					 pr_name(from->sin_addr),
					 rap->icmp_wpa);
			return;
		}
		if (cc <
		    8 + rap->icmp_num_addrs * rap->icmp_wpa * 4) {
			if (verbose)
				logmsg(LOG_INFO, "ICMP %s from %s: Too short %d, %d\n",
					      pr_type((int)rap->icmp_type),
					      pr_name(from->sin_addr),
					      cc,
					      8 + rap->icmp_num_addrs * rap->icmp_wpa * 4);
			return;
		}

		if (verbose)
			logmsg(LOG_INFO, "ICMP %s from %s, lifetime %d\n",
				      pr_type((int)rap->icmp_type),
				      pr_name(from->sin_addr),
				      ntohs(rap->icmp_lifetime));

		/* Check that at least one router address is a neighbour
		 * on the arriving link.
		 */
		for (i = 0; (unsigned)i < rap->icmp_num_addrs; i++) {
			struct in_addr ina;
			ap = (struct icmp_ra_addr *)
				ALLIGN(buf + hlen + 8 +
				       i * rap->icmp_wpa * 4);
			ina.s_addr = ap->ira_addr;
			if (verbose)
				logmsg(LOG_INFO, "\taddress %s, preference 0x%x\n",
					      pr_name(ina),
					      (unsigned int)ntohl(ap->ira_preference));
			if (is_directly_connected(ina))
				record_router(ina,
					      ntohl(ap->ira_preference),
					      ntohs(rap->icmp_lifetime));
		}
		nreceived++;
		if (!forever) {
			do_fork();
			forever = 1;
/*
 * The next line was added so that the alarm is set for the new procces
 * Fraser Gardiner Sun Microsystems Australia
 */
			(void) alarm(TIMER_INTERVAL);
		}
		break;
	}

#ifdef RDISC_SERVER
	case ICMP_ROUTERSOLICIT:
	{
		struct sockaddr_in sin;

		if (!agent_advert || !reg_request)
			break;

		/* TBD verify that the link is multicast or broadcast */
		/* XXX Find out the link it came in over? */

		if (in_cksum((unsigned short *)ALLIGN(buf+hlen), cc)) {
			if (verbose)
				logmsg(LOG_INFO, "ICMP %s from %s: Bad checksum\n",
					      pr_type((int)icmph->type),
					      pr_name(from->sin_addr));
			return;
		}
		if (icmph->code != 0) {
			if (verbose)
				logmsg(LOG_INFO, "ICMP %s from %s: Code = %d\n",
					      pr_type((int)icmph->type),
					      pr_name(from->sin_addr),
					      icmph->code);
			return;
		}

		if (cc < ICMP_MINLEN) {
			if (verbose)
				logmsg(LOG_INFO, "ICMP %s from %s: Too short %d, %d\n",
					      pr_type((int)icmph->type),
					      pr_name(from->sin_addr),
					      cc,
					      ICMP_MINLEN);
			return;
		}

		if (verbose)
			logmsg(LOG_INFO, "ICMP %s from %s\n",
				      pr_type((int)icmph->type),
				      pr_name(from->sin_addr));

		/* Check that ip_src is either a neighbour
		 * on the arriving link or 0.
		 */
		sin.sin_family = AF_INET;
		if (iph->saddr == 0) {
			/* If it was sent to the broadcast address we respond
			 * to the broadcast address.
			 */
			if (IN_CLASSD(ntohl(iph->daddr)))
				sin.sin_addr.s_addr = htonl(0xe0000001);
			else
				sin.sin_addr.s_addr = INADDR_BROADCAST;
			/* Restart the timer when we broadcast */
			left_until_advertise = min_adv_int +
				((max_adv_int - min_adv_int)
				 * (rand() % 1000)/1000);
		} else {
			sin.sin_addr.s_addr = iph->saddr;
			if (!is_directly_connected(sin.sin_addr)) {
				if (verbose)
					logmsg(LOG_INFO, "ICMP %s from %s: source not directly connected\n",
						      pr_type((int)icmph->type),
						      pr_name(from->sin_addr));
				break;
			}
		}
		nreceived++;
		ntransmitted++;
		if (agent_advert)
                        advertise(&sin, lifetime);
                if (reg_request)
                        registration_request(lifetime, sockfd);

		break;
	}
#endif
	}
}

/*
 * 			P R _ T Y P E
 *
 * Convert an ICMP "type" field to a printable string.
 */


char *pr_type(int t)
{
	static char *ttab[] = {
		"Echo Reply",
		"ICMP 1",
		"ICMP 2",
		"Dest Unreachable",
		"Source Quench",
		"Redirect",
		"ICMP 6",
		"ICMP 7",
		"Echo",
		"Router Advertise",
		"Router Solicitation",
		"Time Exceeded",
		"Parameter Problem",
		"Timestamp",
		"Timestamp Reply",
		"Info Request",
		"Info Reply",
		"Netmask Request",
		"Netmask Reply"
	};

	if ( t < 0 || t > 16 )
		return("OUT-OF-RANGE");

	return(ttab[t]);
}

/*
 *                      F I N I S H
 *
 * Print out statistics, and give up.
 * Heavily buffered STDIO is used here, so that all the statistics
 * will be written with 1 sys-write call.  This is nice when more
 * than one copy of the program is running on a terminal;  it prevents
 * the statistics output from becoming intermingled.
 */
void
finish()
{
#ifdef RDISC_SERVER
        if (agent_advert || reg_request) {
                /* Send out a packet with a preference so that all
                 * hosts will know that we are dead.
                 *
                 * Wrong comment, wrong code.
                 *      ttl must be set to 0 instead. --ANK
                 */
                logmsg(LOG_ERR, "terminated\n");
                ntransmitted++;
                if (agent_advert)
			advertise(&whereto, 0);
		if (reg_request)
                        registration_request(0, sockfd);

        }
#endif
        logmsg(LOG_INFO, "\n----%s MIP Statistics----\n"
                         "%d packets transmitted, "
                         "%d packets received, \n",
                         sendaddress, ntransmitted, nreceived);
        (void) fflush(stdout);
        exit(0);
}

/*
 * LOGGER
 */

void initlog(void)
{
        logging++;
        openlog("in.rdiscd", LOG_PID | LOG_CONS, LOG_DAEMON);
}


void logmsg(int const prio, char const *const fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        if (logging)
                vsyslog(prio, fmt, ap);
        else
                vfprintf(stderr, fmt, ap);
        va_end(ap);
}

void logperror(char *str)
{
        if (logging)
                syslog(LOG_ERR, "%s: %s", str, strerror(errno));
        else
                (void) fprintf(stderr, "%s: %s\n", str, strerror(errno));
}

int get_time()
        {

struct timespec tms;

/* POSIX.1-2008 way */
    if (clock_gettime(CLOCK_REALTIME,&tms)) {
        return -1;
    }
    /* seconds, multiplied with 1 million */
    int64_t micros = tms.tv_sec * 1000000;
    /* Add full microseconds */
    micros += tms.tv_nsec/1000;
    /* round up if necessary */
    if (tms.tv_nsec % 1000 >= 500) {
        ++micros;
    }

    return micros;
 }

