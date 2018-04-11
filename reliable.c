#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include "rlib.h"
#include "buffer.h"

#define MSS 500         // Max Segment Size
#define HS 12           // Header Size
#define ACKS 8          // Ack-pkt Size

typedef struct rel_state_send {
    int unack;
    int next;
    int eof_read;
    int eof_num;
} rel_state_send_t;

typedef struct rel_state_receive {
    int eof_received;
    int next;
} rel_state_receive_t;

struct reliable_state {
    rel_t *next;			/* Linked list for traversing all connections */
    rel_t **prev;

    conn_t *c;			/* This is the connection object */

    buffer_t* send_buffer;
    buffer_t* rec_buffer;

    rel_state_send_t* state_send;
    rel_state_receive_t *state_receive;

    int timeout; 

    int window; 

};
rel_t *rel_list;


/*  Checks if Packet is valid
 *  @return 1 iff packet valid, 0 otherwise */
int
checkPacket(packet_t *pkt, size_t n) {
    if (n < 8) return 0; 
    uint16_t pkt_size = ntohs(pkt->len);
    if (pkt_size > n || pkt_size > MSS + HS) return 0;

    int cs = pkt->cksum;
    pkt->cksum = 0;
    int ret = cs == cksum(pkt, pkt_size);
    pkt->cksum = cs;
    return ret;
}


void
sendAckPacket(rel_t *r) {

    packet_t *ack_p = xmalloc(ACKS);
    ack_p->len = htons(8);
    ack_p->ackno = htonl(r->state_receive->next);
    ack_p->cksum = 0;
    ack_p->cksum = cksum(ack_p, ACKS);

    conn_sendpkt(r->c, ack_p, ACKS);
}





/* Creates a new reliable protocol session, returns NULL on failure.
* ss is always NULL */
rel_t *
rel_create (conn_t *c, const struct sockaddr_storage *ss,
const struct config_common *cc)
{
    rel_t *r;

    r = xmalloc (sizeof (*r));
    memset (r, 0, sizeof (*r));

    if (!c) {
        c = conn_create (r, ss);
        if (!c) {
            free (r);
            return NULL;
        }
    }

    r->c = c;
    r->next = rel_list;
    r->prev = &rel_list;
    if (rel_list)
    rel_list->prev = &r->next;
    rel_list = r;

    /* Do any other initialization you need here... */

    r->send_buffer = xmalloc(sizeof(buffer_t));
    r->send_buffer->head = NULL;

    r->rec_buffer = xmalloc(sizeof(buffer_t));
    r->rec_buffer->head = NULL;

    r->state_send = xmalloc(sizeof(rel_state_send_t));
    r->state_receive = xmalloc(sizeof(rel_state_receive_t));

    r->state_send->next = 1;
    r->state_send->unack = 1;
    r->state_send->eof_num = 0;
    r->state_send->eof_read = 0;

    r->state_receive->next = 1;
    r->state_receive->eof_received = 0;

    r->window = cc->window;
    r->timeout = cc->timeout;

    return r;
}

void
rel_destroy (rel_t *r)
{
    if (r->next) {
        r->next->prev = r->prev;
    }
    *r->prev = r->next;
    conn_destroy (r->c);

    /* Free any other allocated memory here */
    buffer_clear(r->send_buffer);
    free(r->send_buffer);
    buffer_clear(r->rec_buffer);
    free(r->rec_buffer);
    
    free(r->state_send);
    free(r->state_receive);

}

// n is the expected length of pkt
void
rel_recvpkt (rel_t *r, packet_t *pkt, size_t n)
{
    // print_pkt(pkt, pkt->data, n);

    if (!checkPacket(pkt, n)) return;

    uint16_t pkt_size = ntohs(pkt->len);


    fprintf(stderr, "state_receive->next %x \n", r->state_receive->next);
    fprintf(stderr, "state_send->next %x \n", r->state_send->next);
    print_pkt(pkt, NULL, n);


    // If pkt is Acknowledge-Packet
    if (pkt_size == 8) {

        // if expected ackno, update send state and send buffer
        if (ntohl(pkt->ackno) > r->state_send->unack) {
            r->state_send->unack = ntohl(pkt->ackno);
            buffer_remove(r->send_buffer, ntohl(pkt->ackno));

            // check if connection can be destroyed
            if (ntohl(pkt->ackno) - 1 == r->state_send->eof_num) {
                r->state_send->eof_read = 1;
                if (r->state_receive->eof_received) conn_destroy(r->c);
            }

            rel_read(r);
        }

        rel_read(r);

        return;
    }

    // If Pkt is Data-Packet
    if (pkt_size >= 12) {
        
        // Pkt is out of window
        if (ntohl(pkt->seqno) >= r->state_receive->next + r->window || ntohl(pkt->seqno) < r->state_receive->next) {
            sendAckPacket(r);
            return;
        }

        // Pkt is already in buffer
        if (buffer_contains(r->rec_buffer, ntohl(pkt->seqno))) {
            sendAckPacket(r);
            return;
        }

        buffer_insert(r->rec_buffer, pkt, 1);

        rel_output(r);
    }

    
}

void
rel_read (rel_t *s)
{
    if (s->state_send->eof_num != 0) return;

    // check if in sender window
    if (s->state_send->next - s->state_send->unack >= s->window) return;
    
    packet_t *p = xmalloc(sizeof(packet_t));  
    
    // Get Data to send
    int input_bytes = conn_input(s->c, p->data, MSS);
    if (!input_bytes) {
        return;
    }

    uint16_t packetsize;

    if (input_bytes == -1) {
        // Pkt is EOF
        packetsize = HS;
        s->state_send->eof_num = s->state_send->next;
    }
    else 
        packetsize = (uint16_t) input_bytes + (uint16_t) HS;

    // create packet
    p->len = htons(packetsize);
    p->seqno = htonl(s->state_send->next);
    p->ackno = 0;
    p->cksum = 0;
    p->cksum = cksum(p, packetsize);

    // write packet to buffer with current time
    struct timeval now;
    gettimeofday(&now, NULL);
    long now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;
    buffer_insert(s->send_buffer, p, now_ms);        // long last_retransmit = 1

    // send packet
    conn_sendpkt(s->c, p, packetsize);
    s->state_send->next++;

    // check if more bytes to read
    rel_read(s);
}

void
rel_output (rel_t *r)
{

    // buffer_print(r->rec_buffer);

    if (!buffer_size(r->rec_buffer)) return;

    packet_t pkt = buffer_get_first(r->rec_buffer)->packet;

    if (ntohl(pkt.seqno) != r->state_receive->next) return;

    if (conn_bufspace(r->c) < ntohs(pkt.len) - HS) return;

    // check if eof-packet. if so, check if connection can be destroyed
    if (ntohs(pkt.len) == HS) {
        buffer_remove_first(r->rec_buffer);
        conn_output(r->c, &pkt.data, 0); // send eof to output
        r->state_receive->next++;
        sendAckPacket(r);
        r->state_receive->eof_received = 1;
        if (r->state_send->eof_read) conn_destroy(r->c);
        return;
    }
         
    // send data to output and update receive buffer
    conn_output(r->c, &pkt.data, ntohs(pkt.len) - HS);
    buffer_remove_first(r->rec_buffer);
    r->state_receive->next++;
    
    sendAckPacket(r);

    rel_output(r);
}

void
rel_timer ()
{
    // Go over all reliable senders, and have them send out
    // all packets whose timer has expired
    rel_t *current = rel_list;
    while (current != NULL) {
        buffer_node_t *buf = buffer_get_first(current->send_buffer);

        // go over all packets in send buffer
        while (buf != NULL) {
            // Get current Time
            struct timeval now;
            gettimeofday(&now, NULL);
            long now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;

            // if timeout ms passed since last transmit, retransmit
            if (now_ms - buf->last_retransmit > current->timeout) {
                buf->last_retransmit = now_ms;
                conn_sendpkt(current->c, &buf->packet, ntohs(buf->packet.len));
            }
            
            buf = buf->next;
        }

        current = rel_list->next;
    }
}
