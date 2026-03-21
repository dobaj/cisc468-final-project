package com.p2pfs.protocol;

public enum MessageType {
    HELLO,
    HELLO_REPLY,
    AUTH,
    ENCRYPTED,
    FILE_LIST_REQUEST,
    FILE_LIST_RESPONSE,
    FILE_REQUEST,
    FILE_RESPONSE,
    FILE_OFFER,
    FILE_OFFER_RESPONSE,
    FILE_DATA,
    KEY_MIGRATION,
    ERROR
}
