"""Approved election groups, as an independent copy held by the verifier.

tests/test_verifier_independence.py checks these equal the deterministic
derivation from each seed (re-implemented in vmath.rederive).
"""

APPROVED_GROUPS = {
    "CHUNAVIQ-2048-256-V1": {
        "seed": ("chunaviq election group v1 / research use / 2048-256", 2048, 256),
        "secure": True,
        "p": int(
            "9e80dc8b0d4086c2050350bad9cd810f2671d3449e65f40dc69caf21ea203376"
            "74c6fefd2ff0ec37fa00d035bf0ac6a06302dd7fac9a3be3d543f01d5b350c3c"
            "bf91ac30b826ffafbea1cc278fe9cbbf5505419f79ee16b08dc7be4d170e6592"
            "46abf9ea30cd5119874c7a87c7fb7e806b0c015e25b26df600c8b35f6be23c60"
            "76a425543aee67c823365fb5a0cc5984bea3ff4adee8d3038ecfa2ffe5bed16e"
            "46e55a2c9a4841e06792aaf93e030f19a4762b84d36dfac881a76c888a5e1819"
            "7d7359f6180e6213982bf0f7f6beea1b4af0c913057684276634b0867c7cc942"
            "a9097c22333478462e62e59774b2188ca70e602f53120d658452f8378f0ac617",
            16,
        ),
        "q": int("cb32291ac580d97c5846c519605a698aac039d4687bb74e56c896e80f51cda09", 16),
        "g": int(
            "88b0041fe07862baecbcaeb6e88d8050ba0b67e360c4cd522ceb0ebbc39108f3"
            "d655b9d87d6e186bb58f177bc4a59a64d16725d606e1f2d0a3a61bf7f299f729"
            "bbdc3748165fd76474b3d38993eb529a5d1832c4f5db455d5bccdc27911d02d2"
            "df3a76a95d7cbc78f266c600b697ee71cd83cf63bb85a137f3cae2adc2f4ae7d"
            "09a132e8949e4150d34ea1c08100706c578671e5af6f66ed7de3df3ad1682809"
            "58140d9155deddc1e064f578053c9de0c373f9e5ee59db625d1c75b6e169d478"
            "41e3deadf31bfc87129a4632f6eb1238ac8099efb7e0a8c2bb55ae251dadca89"
            "8fb1482e0c04397a4b5e74438fc1f2279c9076148317de99e230ea95cbfc8236",
            16,
        ),
    },
    "TEST-INSECURE-512-160": {
        "seed": ("chunaviq TEST-ONLY insecure group v1 / 512-160", 512, 160),
        "secure": False,
        "p": int(
            "f9a54c321a0542cde9a0506024b75bedf776d9fc4a6406df7078b8216c82d2c9cb48eecde5852b6017a9f025daa2a6239158990442ad3c8e5899fa6282f16937",
            16,
        ),
        "q": int("fc2ce5bf313c87371a883efa95133e0ad4271db7", 16),
        "g": int(
            "934a0507a33f358522a7b462fef2eb1763af547b53484f2a1e25c7eba595eebf5ab8ef1b964e5fd20f7d42fc2187f9cc52baeff07f4e0872b3753cec04b5a93e",
            16,
        ),
    },
}
