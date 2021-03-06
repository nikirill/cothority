package main

var TestFileSignatures = `-----BEGIN PGP SIGNATURE-----
Comment: GPGTools - https://gpgtools.org

iQEcBAABCgAGBQJWUw4RAAoJEM72OFPupyBK46AH/2HgfhHAxZXXuJ+SHaO5tsS1
BTmGwb8cw/DB4H6TAZja7lNu7peo8Pp1uu4a6cqH1uKT3LRNhA8A3cpy82qmKwwK
p+JifxpphY1zsCYLP+CMIy7vfbs1Mg0FbFTjEzd5OWA2y95UYSovi/vDgTAMwM5Z
TtUk4ZRqdyGWhCwe9FlyZ+CR0MImWIQCnSfIyw665eJCUPq6s8S/hgp+UKkiIgXC
t7Uf5Z2pXqhudAONLRYa5mEfKIwqPhsijYBiEoUQIQ0rMLGHo7xK+dg2LbGtBK9c
kBzEZvmbLYddYYRV5Vsh0liIjt372K9Sa+47q8GetBeg6J301M0olFmMTjSqjyQ=
=rba6
-----END PGP SIGNATURE-----

-----BEGIN PGP SIGNATURE-----
Comment: GPGTools - https://gpgtools.org

iQEcBAABCgAGBQJWUxAVAAoJEDUdumDlZ1LhvsAH/jgeiBE2tBMCS/2eNM+8VIpk
5bh8zIL10+c0GjD8e+LMT7alOoY5V+Yx/wXwXchDBJzQzEsJzTr7quQw9i9niUH7
v5EjefNAldWtbObcwn5HZmCQ1dHSliYItWcB+4NqBjz4kw8R3movjuLXzGJDIBw5
2yRa9sSs2BGcV4b6AwxH9kFjA8WIc/xG/3wvDezlM5XePEaR7fnqHRZyXZfWd69Y
tKUveMVs/D0zmVtt528GTWYwR1BApg4GRqhtCEDvzE1+doUjEvlxw65kBVIK3Ejo
w2g9m0+fqR1VGZf9u3szjTjtToZ5Yu3XeRaWVsDy8JWv5De8L0DpDydP2yjtmx8=
=syCZ
-----END PGP SIGNATURE-----

-----BEGIN PGP SIGNATURE-----
Comment: GPGTools - https://gpgtools.org

iQEcBAABCgAGBQJWUxBjAAoJEAvm96RPmuytQREIAKBlLS3k9Tr9b0lfjxCQc317
fkubyG+ROQTexJ8zX10INRxSQjJBTgewWKM2jEGSgseDuBb/mWXP6w3Caep0pDxK
ByBv2wIFK/xgonWcXndCDZ5HE3pdq1IXqYNBCobRVYS+LKff2NJCXbgRcKJIvaJ8
UK3pzjf/WDVdh7MetdEIJhc+TNfdt2/ds6Uqc4YfP7kwlW6Dlz20SNJn3F0LyIGh
FF1BkBZ0BElRzWtZwB7WRPtIUCBH9i68eso4ed2ANJHZ0aFfuZV3Qe03dRJFWojK
EV9mt6cwke/U98v1Toye+s3kGV4UjMhaqVPPeMqP+lFPRMrHuQTiPqOstrxpzVY=
=r4ZJ
-----END PGP SIGNATURE-----

-----BEGIN PGP SIGNATURE-----
Comment: GPGTools - https://gpgtools.org

iQEcBAABCgAGBQJWUxB8AAoJEJWMQ2P00o6zNvwH/1dKzUFNKavEB9CYUG7L4N9G
yuLG+qO5egwJAoBbaioKd7m1qHDzflfnTdgrrtNd6ULerxRv2UMAwLzqXkHLPig6
d4D2Ok7EtKJa/F68NRsyJe18mOULBzdkEIUUwAExkPHGddeqjMcLIa59uk+OKs22
r84z6Ua2CX6YTgYjow6WtD1yg9ZZ9uDTVHpnoWohIZEimJMEzF2ZbNxjCLbPYDjO
RQQBw8yt4aNbJQCWrjviG/DXzUmEVwtronlkAfMOeHc/wtzmWyrsoCGCvvMWdP+B
10gTKpaK8QptnxhLX7QoECzdvJbdo70EX4WtknBddTSW5F2SCQ280Dyk0iT4DJg=
=6RUc
-----END PGP SIGNATURE-----`

var TestFilePolicy = `Threshold:
3


Developers Public Keys:
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: GPGTools - https://gpgtools.org

mQENBFZMfrEBCACzgbUa0Y9Z6lAlxQTYn9m4jm/5pdd3V/frJTLdH+7BqUd7eObC
Y9xoKzxzn7M71e+UaqyiZtiwnw6TGYPcJaRYy6Z7bdwNT7Wqg2cmfIES6WPxSkeB
wMmi8Bts5ItgKanvBl/TrnuTpgzKnuUEqRGpCz7+JwswsoadCRZ4QJ+R7NmL/OJj
5i3YBSNIqHei5a2KyIO2qKVzei87ClxaAkzgSRQjg9UyGyV7PBiW1KC4bQcYWLIG
0EEgc+QB9ycmF/6CsujW7xD++jk760lJT46QAPQSTNTXkbNmBWDLfMPUKMXbdU3l
2Pw51ya86CVcLhCkFzWePZ7m3yMBtxQlQ0HZABEBAAG0FUFsaWNlIDxhbGljZUBm
b28uYmFyPokBPQQTAQoAJwUCVkx+sQIbAwUJB4YfgAULCQgHAwUVCgkICwUWAgMB
AAIeAQIXgAAKCRDO9jhT7qcgSlXoB/9Tde/eMDKjX3aAed2JOHiTRwnyg8aaOPkQ
6oIDez2p1eyN/3WcUmonCgDYVb+k+wdAboNmzxKFFlM+mnhTtBjYzXYSDaGuImeY
HnJc+bs4ctJnAv4ZZw36K9+iUXT/9XYr8E7U/XKJheAKkpaiC2cy2OF+z42ddbYw
riPhQJkFQZFbzmEsiOizPzx0+CuFgdW2L6dX8xEDZtOVAdrmT7tgeV+hrr7+xFEU
sCw7ZjHJARC+YqRH2oiqqLQ0ZYp7SFLcByin4FLJBqHeuCONhP1j6DHj5yDfNcyP
AD8s9dk9jx+G1adwg8ZbjJeo675wsnDWRusAG1Z5qmg9bozPwBJEuQENBFZMfrEB
CACzwKTgElFMIsjvcpRUseCrTCzqUH2lqpSwIr6O+jEzitEV9AHyDDS95CUJ5+CU
2J2/TE2EbJlNb3MfmIhIEOJVZ4ZnsTysHJu7ZzglyTgIb+PJ5LrQquTzIIOcd4+F
2MRMzAgWVFfUM2qQvUPj1z0GjrUwYA4AZ0jGAddnVkldg1uLuZ5Sv1nmNhUcscCD
8lZ/XRp1L2iq+hR88Nu6BTbH1YN/gJIorSu63xryQqfTVvFCMJmwVT2Dh8fhvKjh
HFgB+AwSfNT64OyJtvgTkDYXCj81y2JUvO5ik2Px1mfM1jMfSymupk+wFLKHlZ0E
FOIkT5PezRFKAqMpJKcQLX6DABEBAAGJASUEGAEKAA8FAlZMfrECGwwFCQeGH4AA
CgkQzvY4U+6nIEqaugf8Dh3gXtgRviQytbdsb1hzibAcTzRn3bVbk4YuOtohXrQd
WbQDwARC6TPw/Z7PX//bu7uBCiAwVXWQ4MeygUZawzlYr/3rhS0WzqaEGcmsc4oc
r2GhwRCoAOzdPLaCrNqYEYWZwVoeOX4sAwiEzVEpZSw7xzwaH3sgRF377aHDUSHn
ZBvHSPt3P/e3xdfLcMdVqzwhWgNRqjQJjseULkhFpmiPr3Olg4XudRzvghJIj0j6
VZO28N4ysdIlvsXJ2n6BNbm509tM+T8+UePjAs44i6luDZayA2qBQW6hpNWUhpsu
GXZgP336Jex20YMsmzUwFL8AVfDbYm6BIgnXC0uqZg==
=JGcz
-----END PGP PUBLIC KEY BLOCK-----

-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: GPGTools - https://gpgtools.org

mQENBFZMfoQBCACx7aPMbryi5U2Bj//epnSIPE8ZY7c6qxqwVFqcvW2LZB6FbtSA
g0VOjf0gqYUdpBjRCnz1Ip4j3be4WppZ9442vb4t/J1uQOI/vdxdkr5+K4v1k70H
pkIEVHjxFWE7IAknjaHExL4JGkscV9Rep/5BIrVLtgZR8H8EJbtjFOZt9gfDuxa1
eS/Xji0JLyvSQ6Hm9DCM3LXO8Q3gMUryJtOE+jNjsuiZhxTvTfaM/mbxNIk/wY69
8dkcOuMPeehV6aSnDm5gmK0DcNTRjVZjbjPb6iSN6yyVjQIOJpHarHSZUSPn2x+D
boYPhebXNVcrTwiy2ejcAnAvOtYt4Csf7c8RABEBAAG0FUJvYmJ5IDxib2JieUBm
b28uYmFyPokBPQQTAQoAJwUCVkx+hAIbAwUJB4YfgAULCQgHAwUVCgkICwUWAgMB
AAIeAQIXgAAKCRA1Hbpg5WdS4VKzCACPzbJ/2IB1lrM3Dp3QvmVvEuE9fd8lp61v
cPPYOUD4sbPSBgMIsRVvYZUbQ7YQkshHqsRwnYi8eqSeE1hOXsrnAUU1bWVP2iEg
JxHfalNsgnu9ODiL3LkbDODOMgjg5W4eAbcOHIYNZCq5O7Y75k6PKbGMGTnqiw/T
oG4+SUgfQ/iMSEMuFcFjzl0b//+SDVvlO2d5BuH5kt4RSjngWq3F1VMOcYHkxneQ
O3qcRVkQK5rc33gmH2yni5kYwxiUSqKJ5TZWa1XjwEzef9JNOKT0YSUddJDGVggT
Hbu3X55B6lLSbEvdEBlEdZdHf/fZ8Hsud67d3Tpdsk9EunhUCQ3BuQENBFZMfoQB
CAC9ES+AC4IcU1gLPVE2cOhzkI6jXUN1MkzTa5WnrjIXg/WEgMtk6R/7Z+9TBET4
qfWou2cx8ULCm++lH7/J6nAuweKXVULvWfZ90rmJmD+DbfnVJyxlmwUUzwiAEv5T
H867D+7o5mVEAiX8/ClAdG//pXN1t7Z+T6vZQkq8T9SLsChQqz6c1tZtYkOn63V5
Mj2UMt3lB+zTBTholseKZ3eCgQWqyd8mIqh7+p/XERf/Tg7YX1j22SD37SRopyAu
83d/gYvWyjKFt5HREVEQhc1bapAYweIRm5GlqApMKM9smtZah1S/9rUk6kiJ80f7
9djtq+wEjSZxel952wisUDOvABEBAAGJASUEGAEKAA8FAlZMfoQCGwwFCQeGH4AA
CgkQNR26YOVnUuGXDwf/Qdnh24n98NGegiJP0P3cPH1WRMpxwV4h3kTOLuyiGoAO
oa/9rqmMbbnF14iZDzs+eAlB0NMgCn2Y7B4rdIfLrg+Ny/cHh5qNFQ/Uo2MEAoUb
/Fgi+I/lggZXff3jMCGpOIlm5vWQn4HI8ZkwGbmTclnXdof3CGK4pXL0xXAhGlUc
6JigkpP54y+e+oeFkmxTVGvXzRXHgOrCQ4ez/Tx+SlRyoicA1R4C+YJCjFZJX8cU
XxfW0ARi2INDVliBZ93yORAijjAbUvuUnQqPag8z9oNIt1yqx5e6ujvR1mXZVvel
Si1eAL3sQOZMw0FagG9hkf0fkZHai9p4bcRPou8biA==
=TBCb
-----END PGP PUBLIC KEY BLOCK-----

-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: GPGTools - https://gpgtools.org

mQENBFZMfvsBCADLl4oda+owh1aEZ39RFFBemxuCgUtvvrrkVHj8qe1gfPkGRVHO
paLD+0vxQDgHvhdXYDQm2jF7FQcIHErPbGZXY+kAC3jgK1WY62thZxe5zcL8LJLm
A0bdXFcjqsr5GwMw4PX2HRNXTkSVNaUkukqGZJG2UIGzqANxgBaWO9ICwSC0hkHP
sWID4kQVy0eWZDE8BT91sW9182BGFfxGae0vcjl75V3Y7yoA6PrO5oWF4skNQP09
eJPhOLEPRW1hICnVQvkSnW6vV+3CxVFfEup5SpT8IDB5mXG09yACNt8m7BXFYUI1
l1mH5N4XESciVEcRuOg/JZmrwvL6zJXh+CHFABEBAAG0FUNpZGRlIDxjaWRkZUBm
b28uYmFyPokBPQQTAQoAJwUCVkx++wIbAwUJB4YfgAULCQgHAwUVCgkICwUWAgMB
AAIeAQIXgAAKCRAL5vekT5rsrfGKCAC33arnO/5Kw5wAAkivrPLmLEM/WE+mTRui
zunIoA+40EQEuc2yNU2PDtoO75dcMLl0JZ4HbvCDPuTT5wLEt0+ZvHl2VYv1tJaW
kkT9/onP1PTJpL4q35pLWi6FLkS9hYOfK0WL0R45O7u8dAS4B6z9AppH59ivtu+R
UoSvMz45wXU5lOZTct1duspl8UNvpaYsR4LPG0eJs+H5QPqeCQT/nmoErIzft8Nc
oPoHLzRepehAxo7KXhGCqt65z6hCIoMIKWjh1dGFHRaFitM9CQLJXr7Jka/oWbe3
Uh+Ycdyk/iM2t+L13FyWasZiEUA3QPAvcsK1Nn8uV6rxTmHKTLlGuQENBFZMfvsB
CAC0F3rwBUlSZesseHJMhzUp+uMjxFJJBNbMsNAUyVJ+YUO4530Jiz6GLi3ez6hg
ukhtiq1nP8+AJV7qjrleUnCVX/yW42pdj+Zqo/at3z/72yY8i0F/DeQCLwWLLwqC
mQzQegJjgZ5HDrXbcovOMdMyPWO4hquzAPDeYmDcReCEv9dyjnLF09Cp2ret1gQ7
F3bWFTDDzzebC21YuLjYiucrVQi3lWizm3IW4aVUAi4kg5wGFQCTHNQk6llGlfDW
Tw4/ohMZTH7Bid9Mp+Qk1VVYAutLkzJSD5WiAa1N/rO3iDy40OlnscyenIL8c1K3
0aEB/8dIAB5oeJguZtaL17rTABEBAAGJASUEGAEKAA8FAlZMfvsCGwwFCQeGH4AA
CgkQC+b3pE+a7K1yXgf/Rn3cM3s02J/u9QhQpclXSiYZyWn1gkqTVCG6O2T89iOa
YqnUJbBKYYNKgiAjTHFdEy4hsJnHQIHwfEU39yEEHRTs168BwyEXemOEmIECC7CT
cAaoQN0lZAocngUdiS+cX+Ec5esa/wZcuK72m7wzuYzrytfndeXf0+sSVPyPZfgQ
NH7p2LkYhsaSufojDhgvLA4In9qUXXyI6eph9JvjWazffuGOwWvkqoPrwdYsu+PM
skWXkROqqgsqzTIiQqDeJJEaUjwzWQ7L4jE51DB1hlW3PQBGpQuFAa2nbREqQfa9
SH6sKWTl7RRGww41dgZmAQ6hwGsjaYhNlh9rQtsWcw==
=yAUe
-----END PGP PUBLIC KEY BLOCK-----

-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: GPGTools - https://gpgtools.org

mQENBFZMivsBCACbSMIBLvc/9/NPkI/PkrLhlSF/yj1r98V/g/S9IhO20F2xnmg8
cisSoQT+0ejFZCb3c6F6rkY83I0gZgudR49yIDzAKj9Og12Ne85w9XdFXRjsICzD
bh4Yuuexq/VAgks0+L9K36vq2K0c7T4c39yXYaErA70qDRmjH4N8d4ERl0kMF+H/
nzHoDGnH7GJosZO+i7UMCxt1EcnRpQC0kzKlq8gDPOPH2nXc4X2TULUJoQWf3xvQ
tgmrpoAcFYnSxHNlH10SJYBTTS3JwylS4MX4gH5bSiSfgmd2N2YXgdfBKDa41bcn
Vgiaa4QDeftf49HIOVdQz5DBFu0Y0IS36zPbABEBAAG0FURpYW5hIDxkaWFuYUBm
b28uYmFyPokBPQQTAQoAJwUCVkyK+wIbAwUJB4YfgAULCQgHAwUVCgkICwUWAgMB
AAIeAQIXgAAKCRCVjENj9NKOs6fNB/9pNpT51uyKt/h+/7tmL3z/1Ya+RgRY42Sh
lsU0J+q8TJkChV33QysWqiW+IOobe8IV+TU95adJqzDhwgZbwqeVQwEOwHKZkj7h
wGFkq5NGu+poUep2QS3n0KG5XVWIcQMG9mG4P6Tvh8riXkcESECWYk5gvMQTqxTF
9a9ns2PG9vwX4YqZJxHfBeEsFD1Hc7T0Ok4oIMxqNcSZId5k66sZ/d6GwbBVQ75x
b9SdBOgyDoSvbb9tVa4D7+d+F3kii81eUZdTjzS+XmXdlOAnqoeLdl0vWpTUOttJ
dHjbK9DJFKrmnK2tB+4chATSCRb1+vubjqNhLNQTXfMBl8shAy1OuQENBFZMivsB
CADoCCX+8sMXKuRz8J5EoeKCXc+CX0wM0qGYK9baBjmlwLoF8bhmS90oyQ5s0OjL
E3yOVl8djn9/hdz5mx28AW2OGlVDauidZF5P5FpcLaF+rMMGd4FatiWqocYEsKgG
+4RCCob8ulQN773KB32z5OLg3wV/kLIhWp0gc9RaXwCEcOO86YyMiaIEsOUXqiBT
8tqfRTn3Ci+2sd0akF/WiFxQuEM1bK7rti2OrGMdnbs6+wJvTfqLUr9I5UHz6kH6
AKOY+GUSi3G7VIEutkH2GF8LVKdZz9HP+NSM9Z1/ppbP4BWo/xGv2gjMeV6ZErrk
BgQJ9s6EsXOXPtjuT5XzJa6ZABEBAAGJASUEGAEKAA8FAlZMivsCGwwFCQeGH4AA
CgkQlYxDY/TSjrOm9wf8CW5UXdQMoq8Esos5kIaMqfS33yQfCK16dPa9dzvlpLu6
ee6X+VwwWo/9rMnSDkzY48OajhtBiPAdaJRdzRc0+EzdXKsqGQCyYyh+zcvsPr1a
xcs5CdljyUsWMHsPLnOCkzk1mHmflJQh1sw3VEt3p8VfUe2pEa9ID1lXhJ8MjUGw
H/1zvpxcaB/Xn1kthBo05qoGwPLlvl1JSExFWFmtfAEV9IerhYTqFlb+7N3lsR+d
QpVvIT8QZ3R8dhisSFmyk8epVddAzyQLLRFxFNn3BnZWB5JAybrGai4Ff3DslVdq
gwWNvz4pKk69mxikPSkKcvTyvQuIPsteaDYdehUiAg==
=LJkL
-----END PGP PUBLIC KEY BLOCK-----


Cothority Public Key:
BFZMf2MBCADjrCHk+W+MTXh9ZiwAScnaROwEER39zuieHdz0g9whVVTubl8SakGp
`
