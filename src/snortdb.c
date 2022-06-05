/*
* @Author: Cristi Cretan
* @Date:   2022-03-26 16:52:22
* @Last Modified by:   Cristi Cretan
* @Last Modified time: 2022-06-05 15:31:00
*/
#include "snortdb.h"
#include <string.h>
#include <stdio.h>

#define QUERY_LEN 4096+512
#define TO_IP(x) x >> 24, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff
#define IT_OR_NULL(x) strlen(x) == 0 ? "NULL" : x
// #define IT_OR_ZERO(x) x == NULL ? 0 : x
#define BUFLEN 4096

static long s_pos = 0, s_off = 0;
static long last_event_id = 1;

static off_t filesize;
struct stat finfo;

int get_record(u2iterator *it, u2record *record) {
    uint32_t bytes_read;
    uint8_t *tmp;

    if(!it || !it->file) return FAILURE;

    /* check if the log was rotated */
    if(feof(it->file)) {
        /* Get next timestamped file? */
        puts("Hit the EOF .. and this is not being handled yet.");
        return FAILURE;
    }

    if ( s_off )
    {
        if (fseek(it->file, s_pos+s_off, SEEK_SET)) 
        {
            puts("Unable to SEEK on current file .. and this is not being handled yet.");
            return FAILURE;
        }
        s_off = 0;
    }

    /* read type and length */
    bytes_read = fread(record, 1, sizeof(uint32_t) * 2, it->file);
    /* But they're in network order! */
    record->type= ntohl(record->type);
    record->length= ntohl(record->length);

    if(record->type == UNIFIED2_PACKET) record->length+=4;

    if(bytes_read == 0)
       /* EOF */
       return FAILURE;

    if(bytes_read != sizeof(uint32_t)*2) {
        puts("get_record: (1) Failed to read all of record.");
        printf("\tRead %u of %lu bytes\n", bytes_read, (unsigned long)sizeof(uint32_t)*2);
        return FAILURE;
    }

    s_pos = ftell(it->file);

    tmp = (uint8_t *)realloc(record->data, record->length);
    
    if (!tmp)
    {
        puts("get_record: (2) Failed to allocate memory.");
        free(record->data);
        return FAILURE;
    }

    record->data = tmp;

    bytes_read = fread(record->data, 1, record->length, it->file);

    if(bytes_read != record->length) {
        puts("get_record: (3) Failed to read all of record data.");
        printf("\tRead %u of %u bytes\n", bytes_read, record->length);

        if ( record->type != UNIFIED2_PACKET || 
            bytes_read < ntohl(((Serial_Unified2Packet*)record->data)->packet_length)
        )
            return FAILURE;

        clearerr(it->file);
    }

    return SUCCESS;
}

void finish_with_error(MYSQL *con)
{
    fprintf(stderr, "%s\n", mysql_error(con));
    mysql_close(con);
    exit(1);
}

static void event_to_db(u2record *record, MYSQL *con)
{
    printf("event_to_db\n");
    uint8_t *field;
    int i;
    Serial_Unified2IDSEvent_legacy event;

     memcpy(&event, record->data, sizeof(Serial_Unified2IDSEvent_legacy));

    /* network to host ordering */
    /* In the event structure, only the last 40 bits are not 32 bit fields */
    /* The first 11 fields need to be convertted */
    field = (uint8_t*)&event;
    for(i=0; i<11; i++, field+=4) {
        *(uint32_t*)field = ntohl(*(uint32_t*)field);
    }

    /* last 3 fields, with the exception of the last most since it's just one byte */
    *(uint16_t*)field = ntohs(*(uint16_t*)field); /* sport_itype */
    field += 2;
    *(uint16_t*)field = ntohs(*(uint16_t*)field); /* dport_icode */
    /* done changing the network ordering */

    char query[QUERY_LEN];

    if (last_event_id != 1) {
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
    }

    memset(query, 0, QUERY_LEN);

    sprintf(query,
        "INSERT INTO events (sensor_id, event_id, event_second, event_microsecond, signature_id, "
        "generator_id, signature_revision, classification_id, "
        "priority_id, ip_source, ip_destination, sport_itype, "
        "dport_icode, protocol, impact_flag, blocked, rules_Pk_Rule_Id) "
        "VALUES (%u, %u, %u, %u, "
        "%u, %u, %u, %u, "
        "%u, \"%u.%u.%u.%u\", \"%u.%u.%u.%u\", "
        "%u, %u, %u, %u, %u, %lu)",
        event.sensor_id, event.event_id,
        event.event_second, event.event_microsecond,
        event.signature_id, event.generator_id,
        event.signature_revision, event.classification_id,
        event.priority_id, TO_IP(event.ip_source),
        TO_IP(event.ip_destination), event.sport_itype,
        event.dport_icode, event.protocol,
        event.impact_flag, event.blocked,
        last_event_id);

    if (mysql_query(con, query)) {
        finish_with_error(con);
    }

    return;
}

static void event2_to_db(u2record *record, MYSQL *con)
{
    printf("event2_to_db\n");
    uint8_t *field;
    int i;

    Serial_Unified2IDSEvent event;

    memcpy(&event, record->data, sizeof(Serial_Unified2IDSEvent));

    /* network to host ordering */
    /* In the event structure, only the last 40 bits are not 32 bit fields */
    /* The first 11 fields need to be convertted */
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

    char query[QUERY_LEN];

    if (last_event_id != 1) {
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
    }

    memset(query, 0, QUERY_LEN);

    sprintf(query,
        "INSERT INTO events (sensor_id, event_id, event_second, event_microsecond, signature_id, "
        "generator_id, signature_revision, classification_id, "
        "priority_id, ip_source, ip_destination, sport_itype, "
        "dport_icode, protocol, impact_flag, blocked, mpls_label, "
        "vlanId, pad2, rules_Pk_Rule_Id) "
        "VALUES (%u, %u, %u, %u, "
        "%u, %u, %u, %u, "
        "%u, \"%u.%u.%u.%u\", \"%u.%u.%u.%u\", "
        "%u, %u, %u, %u, %u, %u, %u, %u, %lu)",
        event.sensor_id, event.event_id,
        event.event_second, event.event_microsecond,
        event.signature_id, event.generator_id,
        event.signature_revision, event.classification_id,
        event.priority_id, TO_IP(event.ip_source),
        TO_IP(event.ip_destination), event.sport_itype,
        event.dport_icode, event.protocol,
        event.impact_flag, event.blocked, event.mpls_label, event.vlanId,
        event.pad2, last_event_id);

    if (mysql_query(con, query)) {
        finish_with_error(con);
    }

    return;
}

static void event3_to_db(u2record *record, MYSQL *con)
{
    printf("event3_to_db\n");
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

    char query[QUERY_LEN];

    if (last_event_id != 1) {
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
    }

    printf("dport_icode = %u\n", event.dport_icode);

    memset(query, 0, QUERY_LEN);

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
        "%u, %u, %u, %s, %lu)",
        event.sensor_id, event.event_id,
        event.event_second, event.event_microsecond,
        event.signature_id, event.generator_id,
        event.signature_revision, event.classification_id,
        event.priority_id, TO_IP(event.ip_source),
        TO_IP(event.ip_destination), event.sport_itype,
        event.dport_icode, event.protocol,
        event.impact_flag, event.blocked,
        event.mpls_label, event.vlanId, event.pad2, IT_OR_NULL(event.app_name), last_event_id);

    if (mysql_query(con, query)) {
        finish_with_error(con);
    }

    return;
}

static void event6_to_db(u2record *record, MYSQL *con)
{
    printf("event6_to_db\n");
    uint8_t *field;
    int i;
    Serial_Unified2IDSEventIPv6_legacy event;
    char ip6buf_source[INET6_ADDRSTRLEN+1];
    char ip6buf_dest[INET6_ADDRSTRLEN+1];

    memcpy(&event, record->data, sizeof(Serial_Unified2IDSEventIPv6_legacy));

    /* network to host ordering */
    /* In the event structure, only the last 40 bits are not 32 bit fields */
    /* The first fields need to be convertted */
    field = (uint8_t*)&event;
    for(i=0; i<9; i++, field+=4) {
        *(uint32_t*)field = ntohl(*(uint32_t*)field);
    }

    field = field + 2*sizeof(struct in6_addr);

    /* last 3 fields, with the exception of the last most since it's just one byte */
    *(uint16_t*)field = ntohs(*(uint16_t*)field); /* sport_itype */
    field += 2;
    *(uint16_t*)field = ntohs(*(uint16_t*)field); /* dport_icode */
    /* done changing the network ordering */

    inet_ntop(AF_INET6, &event.ip_source, ip6buf_source, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &event.ip_destination, ip6buf_dest, INET6_ADDRSTRLEN);

    char query[QUERY_LEN];

    if (last_event_id != 1) {
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
    }

    memset(query, 0, QUERY_LEN);

    sprintf(query,
        "INSERT INTO events (sensor_id, event_id, event_second, event_microsecond, signature_id, "
        "generator_id, signature_revision, classification_id, "
        "priority_id, ip_source, ip_destination, sport_itype, "
        "dport_icode, protocol, impact_flag, blocked, rules_Pk_Rule_Id) "
        "VALUES (%u, %u, %u, %u, "
        "%u, %u, %u, %u, "
        "%u, \"%s\", \"%s\", "
        "%u, %u, %u, %u, %u, %lu)",
        event.sensor_id, event.event_id,
        event.event_second, event.event_microsecond,
        event.signature_id, event.generator_id,
        event.signature_revision, event.classification_id,
        event.priority_id, ip6buf_source,
        ip6buf_dest, event.sport_itype,
        event.dport_icode, event.protocol,
        event.impact_flag, event.blocked,
        last_event_id);

    if (mysql_query(con, query)) {
        finish_with_error(con);
    }

    return;
}

static void event2_6_to_db(u2record *record, MYSQL *con)
{
    printf("event2_6_to_db\n");
    uint8_t *field;
    int i;
    char ip6buf_source[INET6_ADDRSTRLEN+1];
    char ip6buf_dest[INET6_ADDRSTRLEN+1];
    Serial_Unified2IDSEventIPv6 event;

    memcpy(&event, record->data, sizeof(Serial_Unified2IDSEventIPv6));

    /* network to host ordering */
    /* In the event structure, only the last 40 bits are not 32 bit fields */
    /* The first fields need to be convertted */
    field = (uint8_t*)&event;
    for(i=0; i<9; i++, field+=4) {
        *(uint32_t*)field = ntohl(*(uint32_t*)field);
    }

    field = field + 2*sizeof(struct in6_addr);

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

    inet_ntop(AF_INET6, &event.ip_source, ip6buf_source, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &event.ip_source, ip6buf_dest, INET6_ADDRSTRLEN);

    char query[QUERY_LEN];

    if (last_event_id != 1) {
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
    }

    memset(query, 0, QUERY_LEN);

    sprintf(query,
        "INSERT INTO events (sensor_id, event_id, event_second, event_microsecond, signature_id, "
        "generator_id, signature_revision, classification_id, "
        "priority_id, ip_source, ip_destination, sport_itype, "
        "dport_icode, protocol, impact_flag, blocked, mpls_label, "
        "vlanId, pad2, rules_Pk_Rule_Id) "
        "VALUES (%u, %u, %u, %u, "
        "%u, %u, %u, %u, "
        "%u, \"%s\", \"%s\", "
        "%u, %u, %u, %u, %u, %u, %u, %u, %lu)",
        event.sensor_id, event.event_id,
        event.event_second, event.event_microsecond,
        event.signature_id, event.generator_id,
        event.signature_revision, event.classification_id,
        event.priority_id, ip6buf_source,
        ip6buf_dest, event.sport_itype,
        event.dport_icode, event.protocol,
        event.impact_flag, event.blocked, event.mpls_label, event.vlanId,
        event.pad2, last_event_id);

    if (mysql_query(con, query)) {
        finish_with_error(con);
    }
}

static void event3_6_to_db(u2record *record, MYSQL *con)
{
    printf("event3_6_to_db\n");
    uint8_t *field;
    int i;
    char ip6buf_source[INET6_ADDRSTRLEN+1];
    char ip6buf_dest[INET6_ADDRSTRLEN+1];
    Serial_Unified2IDSEventIPv6 event;

    memcpy(&event, record->data, sizeof(Serial_Unified2IDSEventIPv6));

    /* network to host ordering */
    /* In the event structure, only the last 40 bits are not 32 bit fields */
    /* The first fields need to be convertted */
    field = (uint8_t*)&event;
    for(i=0; i<9; i++, field+=4) {
        *(uint32_t*)field = ntohl(*(uint32_t*)field);
    }

    field = field + 2*sizeof(struct in6_addr);

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

    inet_ntop(AF_INET6, &event.ip_source, ip6buf_source, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &event.ip_source, ip6buf_dest, INET6_ADDRSTRLEN);

    char query[QUERY_LEN];

    if (last_event_id != 1) {
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
    }

    memset(query, 0, QUERY_LEN);

    sprintf(query,
        "INSERT INTO events (sensor_id, event_id, event_second, event_microsecond, signature_id, "
        "generator_id, signature_revision, classification_id, "
        "priority_id, ip_source, ip_destination, sport_itype, "
        "dport_icode, protocol, impact_flag, blocked, mpls_label, "
        "vlanId, pad2, app_name, rules_Pk_Rule_Id) "
        "VALUES (%u, %u, %u, %u, "
        "%u, %u, %u, %u, "
        "%u, \"%s\", \"%s\", "
        "%u, %u, %u, %u, %u, "
        "%u, %u, %u, %s, %lu)",
        event.sensor_id, event.event_id,
        event.event_second, event.event_microsecond,
        event.signature_id, event.generator_id,
        event.signature_revision, event.classification_id,
        event.priority_id, ip6buf_source,
        ip6buf_dest, event.sport_itype,
        event.dport_icode, event.protocol,
        event.impact_flag, event.blocked,
        event.mpls_label, event.vlanId, event.pad2, IT_OR_NULL(event.app_name), last_event_id);

    if (mysql_query(con, query)) {
        finish_with_error(con);
    }
}

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
            "linktype, packet_length, events_Pk_Event_Id)"
            "VALUES (%u, %u, %u, %u, %u, %u, %u, %lu);",
                    packet.sensor_id, packet.event_id, packet.event_second,
                    packet.packet_second, packet.packet_microsecond, packet.linktype,
                    packet.packet_length, last_event_id);

    if (mysql_query(con, query)) {
        finish_with_error(con);
    }

    sprintf(query, "INSERT INTO blob_packets(packet_data, packets_Pk_Packet_Id) "
                "VALUES (x'%s', %lu);", hex_buf, last_event_id);

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

    fstat(fileno(f), &finfo);
    filesize = finfo.st_size;

    ret->file = f;
    ret->filename = strdup(filename);
    return ret;
}

static inline void free_iterator(u2iterator *it) {
    if(it->file) fclose(it->file);
    if(it->filename) free(it->filename);
    if(it) free(it);
}

void add_records(u2iterator *it, u2record *record, MYSQL *con)
{
    while (get_record(it, record) == SUCCESS) {
        if (record->type == UNIFIED2_IDS_EVENT) {
            event_to_db(record, con);
        } else if (record->type == UNIFIED2_IDS_EVENT_VLAN) {
            event2_to_db(record, con);
        } else if (record->type == UNIFIED2_PACKET) {
            packet_to_db(record, con);
        } else if (record->type == UNIFIED2_IDS_EVENT_IPV6) {
            event6_to_db(record, con);
        } else if (record->type == UNIFIED2_IDS_EVENT_IPV6_VLAN) {
            event2_6_to_db(record, con);
        } else if (record->type == UNIFIED2_EXTRA_DATA) {
            printf("Extradata not implemented yet\n");
        } else if (record->type == UNIFIED2_IDS_EVENT_APPID) {
            event3_to_db(record, con);
        } else if (record->type == UNIFIED2_IDS_EVENT_APPID_IPV6) {
            event3_6_to_db(record, con);
        } else if (record->type == UNIFIED2_IDS_EVENT_APPSTAT) {
            printf("Appid not implemented yet\n");
        }
    }
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

    add_records(it, &record, con);

    while (1) {
        sleep(5);
        fstat(fileno(it->file), &finfo);
        if (filesize != finfo.st_size) {
            add_records(it, &record, con);
        }
        filesize = finfo.st_size;
    }

    free_iterator(it);
    if(record.data)
        free(record.data);

    return 0;
}
