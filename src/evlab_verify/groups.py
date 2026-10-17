"""Approved election groups, as an independent copy held by the verifier.

tests/test_verifier_independence.py checks these equal the deterministic
derivation from each seed (re-implemented in vmath.rederive).
"""

APPROVED_GROUPS = {
    "EVLAB-2048-256-V1": {
        "seed": ("evlab election group v1 / research use / 2048-256", 2048, 256),
        "secure": True,
        "p": int(
            "8e0cb1d465d466cc7cf13a395636d93fde50d5f331f2dbe16bf2f3147e5318d5"
            "6409ae5accb16d5a55dceef5d68ace9a592ed4c763212b096f9695cee8442cea"
            "cd1dcbe605739687759eb64d18f5733f08cb0d496a67ad8f31f317a18594735b"
            "da77d99f772a75c4a118ecbc6c7de89e0a61b40e2ca546df67c3141474080f91"
            "1fd6402819290b11ca18ce3ed17e933c493bd7f1bc88ff899c1bac0f881dea09"
            "72671991b467ac70dd81b4dba67b29b081dbb1508368f3eff754e3ffdff7b09e"
            "2dd8b7fe224c3d4deedeb66a25c8ce62774991281a9dc99b34b03b8f1b9fdb5b"
            "35af894e259afc1663fc617ac62713d059a11bf4073ab5adb2c372bf50524f7b",
            16,
        ),
        "q": int("e3edf1065989d26eb2b5244ebb7e5213835fe7a7ccb8d4335d6a58b79d08b2a1", 16),
        "g": int(
            "34b3dcb0dacb60b1a096b09b1bd3373c6ffd9df97d94c46ac4ebdb1ae3080fd4"
            "aa6256349639080e0f26665c29089cf3b673c9674489abf7216add7ff8d8cb93"
            "4b8a177abdfe165f2be3e6495544b7590e2b296d6438b6d612f478c90b047631"
            "99f51621445ed457eb14e7d478eff96d0b22f5d2d8631090f17817f7bebcb7f6"
            "459368132e7b31052979ec519268d2ed72a520e4bd3c71dc09e5a9b26c42683c"
            "6995a9d11a530b9bf0fee451c691064590925c1c67420f0494602fc216fa6375"
            "f303f2ea9599907f55b1b9f7aaafd140a942709113a1a31cf6a75101b3d918c7"
            "b0662077a9c026d2098417f21a7e0d541462c5bf590c09e66e5e3cdfbad8020",
            16,
        ),
    },
    "TEST-INSECURE-512-160": {
        "seed": ("evlab TEST-ONLY insecure group v1 / 512-160", 512, 160),
        "secure": False,
        "p": int(
            "d2677eb1e86905c7856244bdcaa00ca71f55b6588e0580a092ba6df360e96fbc78846e694c60c1a29a4cc803221f823919fe87827cd13648419f027c87787d85",
            16,
        ),
        "q": int("fdaef5a92c67c0be43ebcb5fb0ce9cdb56a26425", 16),
        "g": int(
            "c845dcfcb2dd0e823cf796895e9860b82c84f737628185fc8c5be8f0daa81e766b537ce64bf2cd5792048c2d528fd0235bb45aca9a20b0f6390927b9e23896df",
            16,
        ),
    },
}
