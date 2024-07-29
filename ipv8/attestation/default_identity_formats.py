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
    }
}
