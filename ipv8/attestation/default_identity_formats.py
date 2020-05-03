from .wallet.irmaexact.keydump import nijmegen_pk_1568208470


FORMATS = {
    "id_metadata": {
        "algorithm": "bonehexact",
        "key_size": 32,  # Pairings over 1024 bit space
        "hash": "sha256_4"  # 4 byte hash
    },
    "id_metadata_big": {
        "algorithm": "bonehexact",
        "key_size": 64,  # Pairings over 4096 bit space
        "hash": "sha256"  # 32 byte hash
    },
    "id_metadata_huge": {
        "algorithm": "bonehexact",
        "key_size": 96,  # Pairings over 9216 bit space
        "hash": "sha512"  # 64 byte hash
    },
    "id_metadata_range_18plus": {
        "algorithm": "pengbaorange",
        "key_size": 32,  # Pairings over 1024 bit space
        "min": 18,
        "max": 200
    },
    "id_irma_nijmegen_address_1568208470": {
        "algorithm": "irmaexact",
        "issuer_pk": nijmegen_pk_1568208470,  # Valid until Wednesday 11 September 2019 13:27:50 GMT
        "order": [u"street", u"houseNumber", u"zipcode", u"municipality", u"city"],
        "credential": u"pbdf.nijmegen.address",
        "keyCounter": 0,
        "validity": 13

    },
    "id_irma_nijmegen_personalData_1568208470": {
        "algorithm": "irmaexact",
        "issuer_pk": nijmegen_pk_1568208470,  # Valid until Wednesday 11 September 2019 13:27:50 GMT
        "order": [u"initials", u"firstnames", u"prefix", u"familyname", u"surname",
                  u"fullname", u"dateofbirth", u"gender", u"nationality"],
        "credential": u"pbdf.nijmegen.personalData",
        "keyCounter": 0,
        "validity": 13
    },
    "id_irma_nijmegen_ageLimits_1568208470": {
        "algorithm": "irmaexact",
        "issuer_pk": nijmegen_pk_1568208470,  # Valid until Wednesday 11 September 2019 13:27:50 GMT
        "order": [u"over12", u"over16", u"over18", u"over21", u"over65"],
        "credential": u"pbdf.nijmegen.ageLimits",
        "keyCounter": 0,
        "validity": 13
    },
    "id_irma_nijmegen_bsn_1568208470": {
        "algorithm": "irmaexact",
        "issuer_pk": nijmegen_pk_1568208470,  # Valid until Wednesday 11 September 2019 13:27:50 GMT
        "order": [u"bsn"],
        "credential": u"pbdf.nijmegen.bsn",
        "keyCounter": 0,
        "validity": 13
    }
}
