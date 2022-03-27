/*
* @Author: Cristi Cretan
* @Date:   2022-03-26 16:52:22
* @Last Modified by:   Cristi Cretan
* @Last Modified time: 2022-03-27 22:12:26
*/
#include "snortdb.h"
#include <string.h>
#include <stdio.h>

#define TO_IP(x) x >> 24, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff
#define IT_OR_NULL(x) strlen(x) == 0 ? "NULL" : x
// #define IT_OR_ZERO(x) x == NULL ? 0 : x

static long s_pos = 0, s_off = 0;
static long last_event_id = 0;

void finish_with_error(MYSQL *con)
{
    fprintf(stderr, "%s\n", mysql_error(con));
    mysql_close(con);
    exit(1);
}

static void event3_to_db(u2record *record, MYSQL *con)
{
    uint8_t *field;
    int i;

    Serial_Unified2IDSEvent event;

    memcpy(&event, record->data, sizeof(Serial_Unified2IDSEvent));

    field = (uint8_t*)&event;
    for(i=0; i<11; i++, field+=4) {
        *(uint32_t*)field = ntohl(*(uint32_t*)field);
    }

    /* last 3 fields, with the exception of the last most since it's just one byte */
    *(uint16_t*)field = ntohs(*(uint16_t*)field); /* sport_itype */
    field += 2;
    *(uint16_t*)field = ntohs(*(uint16_t*)field); /* dport_icode */
    field +=6;
    *(uint32_t*)field = ntohl(*(uint32_t*)field); /* mpls_label */
    field += 4;
    /* policy_id and vlanid */
    for(i=0; i<2; i++, field+=2) {
        *(uint16_t*)field = ntohs(*(uint16_t*)field);
    }
    /* done changing the network ordering */

    char query[512];

    memset(query, 0, 512);

    sprintf(query,
        "INSERT INTO events (sensor_id, event_id, event_second, event_microsecond, signature_id, "
        "generator_id, signature_revision, classification_id, "
        "priority_id, ip_source, ip_destination, sport_itype, "
        "dport_icode, protocol, impact_flag, blocked, mpls_label, "
        "vlanId, pad2, app_name, rules_Pk_Rule_Id) "
        "VALUES (%u, %u, %u, %u, "
        "%u, %u, %u, %u, "
        "%u, \"%u.%u.%u.%u\", \"%u.%u.%u.%u\", "
        "%u, %u, %u, %u, %u, "
        "%u, %u, %u, %s, 1)",
        event.sensor_id, event.event_id,
        event.event_second, event.event_microsecond,
        event.signature_id, event.generator_id,
        event.signature_revision, event.classification_id,
        event.priority_id, TO_IP(event.ip_source),
        TO_IP(event.ip_destination), event.sport_itype,
        event.dport_icode, event.protocol,
        event.impact_flag, event.blocked,
        event.mpls_label, event.vlanId, event.pad2, IT_OR_NULL(event.app_name));

    // printf("query: %s\n\n", query);
    if (mysql_query(con, query)) {
        finish_with_error(con);
    }

    if (mysql_query(con, "SELECT MAX(Pk_Event_Id) from snortdb.events")) {
        finish_with_error(con);
    }

    MYSQL_RES *result = mysql_store_result(con);

    if (result == NULL) {
        finish_with_error(con);
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    last_event_id = atoi(row[0]);
    mysql_free_result(result);

    return;
}

#define BUFLEN 4096
#define QUERY_LEN 4096+512

static void packet_to_db(u2record *record, MYSQL *con)
{
    char packet_buf[BUFLEN];
    char hex_buf[BUFLEN];
    uint32_t counter;
    uint8_t *field;

    unsigned offset = sizeof(Serial_Unified2Packet)-4;
    unsigned reclen = record->length - offset;

    Serial_Unified2Packet packet;
    memcpy(&packet, record->data, sizeof(Serial_Unified2Packet));

    /* network to host ordering */
    /* The first 7 fields need to be convertted */
    field = (uint8_t*)&packet;
    for(counter=0; counter<7; counter++, field+=4) {
        *(uint32_t*)field = ntohl(*(uint32_t*)field);
    }
    /* done changing from network ordering */

    if (record->length <= offset)
        return;

    if (packet.packet_length != reclen) {
        printf("ERROR: logged %u but packet_length = %u\n",
                record->length-offset, packet.packet_length);

        if (packet.packet_length < reclen) {
            reclen = packet.packet_length;
            s_off = reclen + offset;
        }
    }

    memcpy(packet_buf, record->data+offset, reclen);

    char *pout = hex_buf;
    char *pin = packet_buf;
    const char *hex = "0123456789ABCDEF";
    for(size_t i = 0; i < reclen; ++i){
        *pout++ = hex[(*pin>>4)&0xF];
        *pout++ = hex[(*pin++)&0xF];
    }

    char query[QUERY_LEN];
    sprintf(query, "INSERT INTO packets (sensor_id, event_id, event_second, packet_second, packet_microsecond, "
            "linktype, packet_length, packet_data, events_Pk_Event_Id)"
            "VALUES (%u, %u, %u, %u, %u, %u, %u, x'%s', %lu);",
                    packet.sensor_id, packet.event_id, packet.event_second,
                    packet.packet_second, packet.packet_microsecond, packet.linktype,
                    packet.packet_length, hex_buf, last_event_id);

    if (mysql_query(con, query)) {
        finish_with_error(con);
    }

    return;
}

static u2iterator *new_iterator(char *filename) {
    FILE *f = fopen(filename, "rb");
    u2iterator *ret;

    if(!f) {
        printf("new_iterator: Failed to open file: %s\n\tErrno: %s\n",
          filename, strerror(errno));
        return NULL;
    }

    ret = (u2iterator*)malloc(sizeof(u2iterator));

    if(!ret) {
        printf("new_iterator: Failed to malloc %lu bytes.\n", (unsigned long)sizeof(u2iterator));
        fclose(f);
        return NULL;
    }

    ret->file = f;
    ret->filename = strdup(filename);
    return ret;
}

static inline void free_iterator(u2iterator *it) {
    if(it->file) fclose(it->file);
    if(it->filename) free(it->filename);
    if(it) free(it);
}

int u2_to_db(char *file, MYSQL *con)
{
	u2record record;
    u2iterator *it = new_iterator(file);

    memset(&record, 0, sizeof(record));

    if (!it) {
        printf("u2_to_db: Failed to create new iterator with file: %s\n", file);
        return -1;
    }

    while (get_record(it, &record) == SUCCESS) {
        if (record.type == UNIFIED2_IDS_EVENT_APPID) {
            event3_to_db(&record, con);
        } else if (record.type == UNIFIED2_PACKET) {
            packet_to_db(&record, con);
        }
    }

// TBD: the rest of the packet types
//     while( get_record(it, &record) == SUCCESS ) {
//         if(record.type == UNIFIED2_IDS_EVENT) {
//             event_dump(&record);
//         }
//         else if(record.type == UNIFIED2_IDS_EVENT_VLAN) {
//             event2_dump(&record);
//         }
//         else if(record.type == UNIFIED2_PACKET) {
//             packet_dump(&record);
//         }
//         else if(record.type == UNIFIED2_IDS_EVENT_IPV6) {
//             event6_dump(&record);
//         }
//         else if(record.type == UNIFIED2_IDS_EVENT_IPV6_VLAN) {
//             event2_6_dump(&record);
//         }
//         else if(record.type == UNIFIED2_EXTRA_DATA) {
//             extradata_dump(&record);
//         }
// #if defined(FEAT_OPEN_APPID)
//         else if(record.type == UNIFIED2_IDS_EVENT_APPID) {
//             event3_dump(&record);
//         }
//         else if(record.type == UNIFIED2_IDS_EVENT_APPID_IPV6) {
//             event3_6_dump(&record);
//         }
//         else if(record.type == UNIFIED2_IDS_EVENT_APPSTAT) {
//             appid_dump(&record);
//         }
// #endif /* defined(FEAT_OPEN_APPID) */
//     }

//     free_iterator(it);
//     if(record.data)
//         free(record.data);

    return 0;
}
