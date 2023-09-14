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
        "order": ["street", "houseNumber", "zipcode", "municipality", "city"],
        "credential": "pbdf.nijmegen.address",
        "keyCounter": 0,
        "validity": 13

    },
    "id_irma_nijmegen_personalData_1568208470": {
        "algorithm": "irmaexact",
        "issuer_pk": nijmegen_pk_1568208470,  # Valid until Wednesday 11 September 2019 13:27:50 GMT
        "order": ["initials", "firstnames", "prefix", "familyname", "surname",
                  "fullname", "dateofbirth", "gender", "nationality"],
        "credential": "pbdf.nijmegen.personalData",
        "keyCounter": 0,
        "validity": 13
    },
    "id_irma_nijmegen_ageLimits_1568208470": {
        "algorithm": "irmaexact",
        "issuer_pk": nijmegen_pk_1568208470,  # Valid until Wednesday 11 September 2019 13:27:50 GMT
        "order": ["over12", "over16", "over18", "over21", "over65"],
        "credential": "pbdf.nijmegen.ageLimits",
        "keyCounter": 0,
        "validity": 13
    },
    "id_irma_nijmegen_bsn_1568208470": {
        "algorithm": "irmaexact",
        "issuer_pk": nijmegen_pk_1568208470,  # Valid until Wednesday 11 September 2019 13:27:50 GMT
        "order": ["bsn"],
        "credential": "pbdf.nijmegen.bsn",
        "keyCounter": 0,
        "validity": 13
    }
}
