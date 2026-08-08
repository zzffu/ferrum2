use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const APPROVED_LOCK_IDENTITIES: &str = r#"aead|0.6.1|registry+https://github.com/rust-lang/crates.io-index|1973cfbc1a2daf9cf550e74e1f088c28e7f7d8c1e1418fb6c9dc5184b7e84c99
aes|0.9.1|registry+https://github.com/rust-lang/crates.io-index|f1fc76eaeac4c9164506c466d4ffdd8ec9d0c5bf57ee97177c4d8eceb3a0e138
aes-gcm|0.11.0|registry+https://github.com/rust-lang/crates.io-index|fdf011db2e21ce0d575593d749db5554b47fed37aff429e4dc50bc91ac93a028
aho-corasick|1.1.4|registry+https://github.com/rust-lang/crates.io-index|ddd31a130427c27518df266943a5308ed92d4b226cc639f5a8f1002816174301
anstyle|1.0.14|registry+https://github.com/rust-lang/crates.io-index|940b3a0ca603d1eade50a4846a2afffd5ef57a9feac2c0e2ec2e14f9ead76000
arrayref|0.3.9|registry+https://github.com/rust-lang/crates.io-index|76a2e8124351fda1ef8aaaa3bbd7ebbcb486bbcd4225aca0aa0d84bb2db8fecb
arrayvec|0.7.8|registry+https://github.com/rust-lang/crates.io-index|d3fb67a6e08acf24fdeccbac2cb6ac4305825bd1f117462e0e6f2f193345ad56
async-trait|0.1.91|registry+https://github.com/rust-lang/crates.io-index|ae36dc4177970ef04fde5178d3e2429882def40e57a451f919c098f72baa6cec
atomic-waker|1.1.2|registry+https://github.com/rust-lang/crates.io-index|1505bd5d3d116872e7271a6d4e16d81d0c8570876c8de68093a09ac269d8aac0
autocfg|1.5.1|registry+https://github.com/rust-lang/crates.io-index|f2032f911046de80f0a198e0901378627c33f59ea0ac00e363d481118bd70a53
base64|0.23.0|registry+https://github.com/rust-lang/crates.io-index|b25655df2c3cdd83c5e5b293b88acd880332b2ddadd7c30ac43144fdc0033da9
bitflags|2.13.1|registry+https://github.com/rust-lang/crates.io-index|b588b76d00fde79687d7646a9b5bdf3cc0f655e0bbd080335a95d7e96f3587da
blake3|1.8.5|registry+https://github.com/rust-lang/crates.io-index|0aa83c34e62843d924f905e0f5c866eb1dd6545fc4d719e803d9ba6030371fce
block-buffer|0.12.1|registry+https://github.com/rust-lang/crates.io-index|d2f6c7dbe95a6ed67ad9f18e57daf93a2f034c524b99fd2b76d18fdfeb6660aa
bumpalo|3.20.3|registry+https://github.com/rust-lang/crates.io-index|72f5acc6cb2ba439de613abc23857ec3d78374d8ed5ac84e9d11336e87da8649
bytes|1.12.1|registry+https://github.com/rust-lang/crates.io-index|fc652a48c352aef3ea3aed32080501cf3ef6ed5da78602a020c991775b0aff04
cc|1.4.0|registry+https://github.com/rust-lang/crates.io-index|5add81bb678e6cb321aff7fa0dc7689ad82b112dbc032cea19f91d6b8e3582b9
cfg-if|1.0.4|registry+https://github.com/rust-lang/crates.io-index|9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801
chacha20|0.10.1|registry+https://github.com/rust-lang/crates.io-index|d524456ba66e72eb8b115ff89e01e497f8e6d11d78b70b1aa13c0fbd97540a81
chacha20poly1305|0.11.0|registry+https://github.com/rust-lang/crates.io-index|9b89e1c441e926b9c82a8d023f6e1b7ae0adcfaa7d621814e4d60789bac751cb
cipher|0.5.2|registry+https://github.com/rust-lang/crates.io-index|e8cf2a2c93cd704877c0858356ed03480ff301ee950b43f1cbe4573b088bfa6c
clap|4.6.4|registry+https://github.com/rust-lang/crates.io-index|d91e0c145792ef73a6ad36d27c75ac09f1832222a3c209689d90f534685ee5b7
clap_builder|4.6.2|registry+https://github.com/rust-lang/crates.io-index|f09628afdcc538b57f3c6341e9c8e9970f18e4a481690a64974d7023bd33548b
clap_derive|4.6.4|registry+https://github.com/rust-lang/crates.io-index|d012d2b9d65aca7f18f4d9878a045bc17899bba951561ba5ec3c2ba1eed9a061
clap_lex|1.1.0|registry+https://github.com/rust-lang/crates.io-index|c8d4a3bb8b1e0c1050499d1815f5ab16d04f0959b233085fb31653fbfc9d98f9
cmov|0.5.4|registry+https://github.com/rust-lang/crates.io-index|0c9ea0ac24bc397ab3c98583a3c9ba74fa56b09a4449bbe172b9b1ddb016027a
combine|4.6.7|registry+https://github.com/rust-lang/crates.io-index|ba5a308b75df32fe02788e748662718f03fde005016435c444eea572398219fd
constant_time_eq|0.4.2|registry+https://github.com/rust-lang/crates.io-index|3d52eff69cd5e647efe296129160853a42795992097e8af39800e1060caeea9b
cpubits|0.1.1|registry+https://github.com/rust-lang/crates.io-index|15b85f9c39137c3a891689859392b1bd49812121d0d61c9caf00d46ed5ce06ae
cpufeatures|0.3.0|registry+https://github.com/rust-lang/crates.io-index|8b2a41393f66f16b0823bb79094d54ac5fbd34ab292ddafb9a0456ac9f87d201
critical-section|1.2.0|registry+https://github.com/rust-lang/crates.io-index|790eea4361631c5e7d22598ecd5723ff611904e3344ce8720784c93e3d83d40b
crossbeam-channel|0.5.16|registry+https://github.com/rust-lang/crates.io-index|d85363c37faeca707aef026efa9f3b34d077bce547e48f770770625c6013679e
crossbeam-epoch|0.9.20|registry+https://github.com/rust-lang/crates.io-index|2d6914041f254d6e9176c01941b21115dcfb7089e55135a35411081bd106ef3f
crossbeam-utils|0.8.22|registry+https://github.com/rust-lang/crates.io-index|61803da095bee82a81bb1a452ecc25d3b2f1416d1897eb86430c6159ef717c17
crypto-common|0.2.2|registry+https://github.com/rust-lang/crates.io-index|ce6e4c961d6cd6c9a86db418387425e8bdeaf05b3c8bc1411e6dca4c252f1453
ctr|0.10.1|registry+https://github.com/rust-lang/crates.io-index|baaca1c4b237092596f64d571e9db6ce4109c4ef9742e27590f1709594461f21
ctutils|0.4.2|registry+https://github.com/rust-lang/crates.io-index|7d5515a3834141de9eafb9717ad39eea8247b5674e6066c404e8c4b365d2a29e
data-encoding|2.11.1|registry+https://github.com/rust-lang/crates.io-index|4583a4551df46e2792f82ceeac45e850d2e2d5debba0b91f102385cda5b11f06
deranged|0.5.8|registry+https://github.com/rust-lang/crates.io-index|7cd812cc2bc1d69d4764bd80df88b4317eaef9e773c75226407d9bc0876b211c
displaydoc|0.2.7|registry+https://github.com/rust-lang/crates.io-index|c6232dd377dcc64799954cbd3a9bb882e9cdc1308ccd87b1c098f1fb2eaf82a8
dtoa|1.0.11|registry+https://github.com/rust-lang/crates.io-index|4c3cf4824e2d5f025c7b531afcb2325364084a16806f6d47fbc1f5fbd9960590
either|1.17.0|registry+https://github.com/rust-lang/crates.io-index|9e5e8f6c15a24b9a3ee5efec809ccd006d3b30e8b3bb63c39af737c7f87daa1d
equivalent|1.0.2|registry+https://github.com/rust-lang/crates.io-index|877a4ace8713b0bcf2a4e7eec82529c029f1d0619886d18145fea96c3ffe5c0f
errno|0.3.14|registry+https://github.com/rust-lang/crates.io-index|39cab71617ae0d63f51a36d69f866391735b51691dbda63cf6f96d042b63efeb
fastrand|2.5.0|registry+https://github.com/rust-lang/crates.io-index|da7c62ceae207dd37ea5b845da6a0696c799f85e97da1ab5b7910be3c1c80223
ferrum2-client|0.1.0||
ferrum2-config|0.1.0||
ferrum2-core|0.1.0||
ferrum2-crypto|0.1.0||
ferrum2-dns|0.1.0||
ferrum2-m0-harness|0.1.0||
ferrum2-m4-qualification|0.1.0||
ferrum2-observability|0.1.0||
ferrum2-runtime|0.1.0||
ferrum2-server|0.1.0||
ferrum2-shadowsocks|0.1.0||
ferrum2-sniff|0.1.0||
ferrum2-socks5|0.1.0||
find-msvc-tools|0.1.9|registry+https://github.com/rust-lang/crates.io-index|5baebc0774151f905a1a2cc41989300b1e6fbb29aff0ceffa1064fdd3088d582
fnv|1.0.7|registry+https://github.com/rust-lang/crates.io-index|3f9eec918d3f24069decb9af1554cad7c880e2da24a9afd88aca000531ab82c1
form_urlencoded|1.2.2|registry+https://github.com/rust-lang/crates.io-index|cb4cb245038516f5f85277875cdaa4f7d2c9a0fa0468de06ed190163b1581fcf
futures-channel|0.3.33|registry+https://github.com/rust-lang/crates.io-index|262590f4fe6afeb0bc83be1daa64e52657fe185690a958af7f3ad0e92085c5ae
futures-core|0.3.33|registry+https://github.com/rust-lang/crates.io-index|2cd50c473c80f6d7c3670a752354b8e569b1a7cbfdc0419ec88e5edad85e0dc7
futures-io|0.3.33|registry+https://github.com/rust-lang/crates.io-index|4577ecaa3c4f96589d473f679a71b596316f6641bc350038b962a5daf0085d7a
futures-macro|0.3.33|registry+https://github.com/rust-lang/crates.io-index|2d6d3cde68c518367be28956066ddfef33813991b77a55005a69dae04bf3b10b
futures-sink|0.3.33|registry+https://github.com/rust-lang/crates.io-index|e34418ac499d6305c2fb5ad0ed2f6ac998c5f8ca209b4510f7f94242c647e307
futures-task|0.3.33|registry+https://github.com/rust-lang/crates.io-index|b231ed28831efb4a61a08580c4bc233ec56bc009f4cd8f52da2c3cb97df0c109
futures-util|0.3.33|registry+https://github.com/rust-lang/crates.io-index|a77a90a256fce34da66415271e30f94ee91c57b04b8a2c042d9cf3220179deaa
getrandom|0.2.17|registry+https://github.com/rust-lang/crates.io-index|ff2abc00be7fca6ebc474524697ae276ad847ad0a6b3faa4bcb027e9a4614ad0
getrandom|0.4.3|registry+https://github.com/rust-lang/crates.io-index|300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099
ghash|0.6.0|registry+https://github.com/rust-lang/crates.io-index|2eecf2d5dc9b66b732b97707a0210906b1d30523eb773193ab777c0c84b3e8d5
h2|0.4.15|registry+https://github.com/rust-lang/crates.io-index|6cb093c84e8bd9b188d4c4a8cb6579fc016968d14c99882163cd3ff402a4f155
hashbrown|0.17.1|registry+https://github.com/rust-lang/crates.io-index|ed5909b6e89a2db4456e54cd5f673791d7eca6732202bbf2a9cc504fe2f9b84a
heck|0.5.0|registry+https://github.com/rust-lang/crates.io-index|2304e00983f87ffb38b55b444b5e3b60a884b5d30c0fca7d82fe33449bbe55ea
hex|0.4.3|registry+https://github.com/rust-lang/crates.io-index|7f24254aa9a54b5c858eaee2f5bccdb46aaf0e486a595ed5fd8f86ba55232a70
hickory-net|0.26.1|registry+https://github.com/rust-lang/crates.io-index|e2295ed2f9c31e471e1428a8f88a3f0e1f4b27c15049592138d1eebe9c35b183
hickory-proto|0.26.1|registry+https://github.com/rust-lang/crates.io-index|0bab31817bfb44672a252e97fe81cd0c18d1b2cf892108922f6818820df8c643
hickory-resolver|0.26.1|registry+https://github.com/rust-lang/crates.io-index|f0d58d28879ceecde6607729660c2667a081ccdc082e082675042793960f178c
hickory-server|0.26.1|registry+https://github.com/rust-lang/crates.io-index|130236ba6abba90da6a7acf7a87b27d862b592c3145dc74bc47bf86d8ff198ec
http|1.5.0|registry+https://github.com/rust-lang/crates.io-index|918d3568bebf352712bc2ef3d46a8bcf1a75b373be6539de198e9105cbbf9ce0
httparse|1.10.1|registry+https://github.com/rust-lang/crates.io-index|6dbf3de79e51f3d586ab4cb9d5c3e2c14aa28ed23d180cf89b4df0454a69cc87
hybrid-array|0.4.13|registry+https://github.com/rust-lang/crates.io-index|818356c5132c1fede50f837ca96afbe78ff42413047f4abb886217845e1b6c8c
icu_collections|2.2.0|registry+https://github.com/rust-lang/crates.io-index|2984d1cd16c883d7935b9e07e44071dca8d917fd52ecc02c04d5fa0b5a3f191c
icu_locale_core|2.2.0|registry+https://github.com/rust-lang/crates.io-index|92219b62b3e2b4d88ac5119f8904c10f8f61bf7e95b640d25ba3075e6cac2c29
icu_normalizer|2.2.0|registry+https://github.com/rust-lang/crates.io-index|c56e5ee99d6e3d33bd91c5d85458b6005a22140021cc324cea84dd0e72cff3b4
icu_normalizer_data|2.2.0|registry+https://github.com/rust-lang/crates.io-index|da3be0ae77ea334f4da67c12f149704f19f81d1adf7c51cf482943e84a2bad38
icu_properties|2.2.0|registry+https://github.com/rust-lang/crates.io-index|bee3b67d0ea5c2cca5003417989af8996f8604e34fb9ddf96208a033901e70de
icu_properties_data|2.2.0|registry+https://github.com/rust-lang/crates.io-index|8e2bbb201e0c04f7b4b3e14382af113e17ba4f63e2c9d2ee626b720cbce54a14
icu_provider|2.2.0|registry+https://github.com/rust-lang/crates.io-index|139c4cf31c8b5f33d7e199446eff9c1e02decfc2f0eec2c8d71f65befa45b421
idna|1.1.0|registry+https://github.com/rust-lang/crates.io-index|3b0875f23caa03898994f6ddc501886a45c7d3d62d04d2d90788d47be1b1e4de
idna_adapter|1.2.2|registry+https://github.com/rust-lang/crates.io-index|cb68373c0d6620ef8105e855e7745e18b0d00d3bdb07fb532e434244cdb9a714
indexmap|2.14.0|registry+https://github.com/rust-lang/crates.io-index|d466e9454f08e4a911e14806c24e16fba1b4c121d1ea474396f396069cf949d9
inout|0.2.2|registry+https://github.com/rust-lang/crates.io-index|4250ce6452e92010fdf7268ccc5d14faa80bb12fc741938534c58f16804e03c7
ipnet|2.12.1|registry+https://github.com/rust-lang/crates.io-index|6a756c3fac73139e83f14c2d742155dd2b78d3ee56597b419a0579b7bdd6dd78
itoa|1.0.18|registry+https://github.com/rust-lang/crates.io-index|8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682
jni|0.22.4|registry+https://github.com/rust-lang/crates.io-index|5efd9a482cf3a427f00d6b35f14332adc7902ce91efb778580e180ff90fa3498
jni-macros|0.22.4|registry+https://github.com/rust-lang/crates.io-index|a00109accc170f0bdb141fed3e393c565b6f5e072365c3bd58f5b062591560a3
jni-sys|0.4.1|registry+https://github.com/rust-lang/crates.io-index|c6377a88cb3910bee9b0fa88d4f42e1d2da8e79915598f65fb0c7ee14c878af2
jni-sys-macros|0.4.1|registry+https://github.com/rust-lang/crates.io-index|38c0b942f458fe50cdac086d2f946512305e5631e720728f2a61aabcd47a6264
js-sys|0.3.103|registry+https://github.com/rust-lang/crates.io-index|53b44bfcdb3f8d5837a46dae1ca9660a837176eee74a28b229bc626816589102
lazy_static|1.5.0|registry+https://github.com/rust-lang/crates.io-index|bbd2bcb4c963f2ddae06a2efc7e9f3591312473c50c6685e1f298068316e66fe
libc|0.2.189|registry+https://github.com/rust-lang/crates.io-index|3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2
linux-raw-sys|0.12.1|registry+https://github.com/rust-lang/crates.io-index|32a66949e030da00e8c7d4434b251670a91556f4144941d37452769c25d58a53
litemap|0.8.2|registry+https://github.com/rust-lang/crates.io-index|92daf443525c4cce67b150400bc2316076100ce0b3686209eb8cf3c31612e6f0
lock_api|0.4.14|registry+https://github.com/rust-lang/crates.io-index|224399e74b87b5f3557511d98dff8b14089b3dadafcab6bb93eab67d3aace965
log|0.4.33|registry+https://github.com/rust-lang/crates.io-index|0ceec5bc11778974d1bcb055b18002eba7f4b3518b6a0081b3af5f21666da9ad
matchers|0.2.0|registry+https://github.com/rust-lang/crates.io-index|d1525a2a28c7f4fa0fc98bb91ae755d1e2d1505079e05539e35bc876b5d65ae9
memchr|2.8.3|registry+https://github.com/rust-lang/crates.io-index|cf8baf1c55e62ffcace7a9f06f4bd9cd3f0c4beb022d3b367256b91b87513d98
mio|1.2.2|registry+https://github.com/rust-lang/crates.io-index|30d65c71f1ce40ab09135ce117d742b9f8a19ff91a41a8b57ed50bc2de59c427
moka|0.12.15|registry+https://github.com/rust-lang/crates.io-index|957228ad12042ee839f93c8f257b62b4c0ab5eaae1d4fa60de53b27c9d7c5046
num-conv|0.2.2|registry+https://github.com/rust-lang/crates.io-index|521739c6d2bac4aa25192232afe6841231376b2b26d4d9fae5ecf8ca5772e441
num-traits|0.2.19|registry+https://github.com/rust-lang/crates.io-index|071dfc062690e90b734c0b2273ce72ad0ffa95f0c74596bc250dcfd960262841
once_cell|1.21.4|registry+https://github.com/rust-lang/crates.io-index|9f7c3e4beb33f85d45ae3e3a1792185706c8e16d043238c593331cc7cd313b50
parking_lot|0.12.5|registry+https://github.com/rust-lang/crates.io-index|93857453250e3077bd71ff98b6a65ea6621a19bb0f559a85248955ac12c45a1a
parking_lot_core|0.9.12|registry+https://github.com/rust-lang/crates.io-index|2621685985a2ebf1c516881c026032ac7deafcda1a2c9b7850dc81e3dfcb64c1
percent-encoding|2.3.2|registry+https://github.com/rust-lang/crates.io-index|9b4f627cb1b25917193a259e49bdad08f671f8d9708acfd5fe0a8c1455d87220
pin-project-lite|0.2.17|registry+https://github.com/rust-lang/crates.io-index|a89322df9ebe1c1578d689c92318e070967d1042b512afbe49518723f4e6d5cd
poly1305|0.9.1|registry+https://github.com/rust-lang/crates.io-index|6e2d0073b297041425c7c3df6eb4792d598a15323fe63346852b092eca02904c
polyval|0.7.3|registry+https://github.com/rust-lang/crates.io-index|f0fa31d631f2b2cb2a544d0aa321ce847a94764d701ca2becc411138b93d49cd
portable-atomic|1.14.0|registry+https://github.com/rust-lang/crates.io-index|3d20d5497ef88037a52ff98267d066e7f11fcc5e99bbfbd58a42336193aacec3
potential_utf|0.1.5|registry+https://github.com/rust-lang/crates.io-index|0103b1cef7ec0cf76490e969665504990193874ea05c85ff9bab8b911d0a0564
powerfmt|0.2.0|registry+https://github.com/rust-lang/crates.io-index|439ee305def115ba05938db6eb1644ff94165c5ab5e9420d1c1bcedbba909391
prefix-trie|0.8.4|registry+https://github.com/rust-lang/crates.io-index|4cf6e3177f0684016a5c209b00882e15f8bdd3f3bb48f0491df10cd102d0c6e7
proc-macro2|1.0.107|registry+https://github.com/rust-lang/crates.io-index|985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9
prometheus-client|0.25.0|registry+https://github.com/rust-lang/crates.io-index|ba70bf887030e45213b4a95c9b08d5a450b157f87c1d63661ed0847a12fa2aad
prometheus-client-derive-encode|0.5.0|registry+https://github.com/rust-lang/crates.io-index|9adf1691c04c0a5ff46ff8f262b58beb07b0dbb61f96f9f54f6cbd82106ed87f
quote|1.0.47|registry+https://github.com/rust-lang/crates.io-index|1fbf4db142a473a8d80c26bbf18454ed458bf8d26c8219c331daecfdbd079001
r-efi|6.0.0|registry+https://github.com/rust-lang/crates.io-index|f8dcc9c7d52a811697d2151c701e0d08956f92b0e24136cf4cf27b57a6a0d9bf
rand|0.10.2|registry+https://github.com/rust-lang/crates.io-index|c7f5fa3a058cd35567ef9bfa5e75732bee0f9e4c55fa90477bef2dfcdbc4be80
rand_core|0.10.1|registry+https://github.com/rust-lang/crates.io-index|63b8176103e19a2643978565ca18b50549f6101881c443590420e4dc998a3c69
redox_syscall|0.5.18|registry+https://github.com/rust-lang/crates.io-index|ed2bf2547551a7053d6fdfafda3f938979645c44812fbfcda098faae3f1a362d
regex-automata|0.4.16|registry+https://github.com/rust-lang/crates.io-index|8fcfdb36bda0c880c5931cdc7a2bcdc8ba4556847b9d912bca70bc94708711ad
regex-syntax|0.8.11|registry+https://github.com/rust-lang/crates.io-index|d6f6ff9a378485b298a5286656da665ba74413d36db0979633275d2e708145d4
ring|0.17.14|registry+https://github.com/rust-lang/crates.io-index|a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7
rustc_version|0.4.1|registry+https://github.com/rust-lang/crates.io-index|cfcb3a22ef46e85b45de6ee7e79d063319ebb6594faafcf1c225ea92ab6e9b92
rustix|1.1.4|registry+https://github.com/rust-lang/crates.io-index|b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190
rustls|0.23.43|registry+https://github.com/rust-lang/crates.io-index|0283386ce02abc0151e1761d08802dfe86c173b0b494af5cbc086574e453da06
rustls-pki-types|1.15.1|registry+https://github.com/rust-lang/crates.io-index|2f4925028c7eb5d1fcdaf196971378ed9d2c1c4efc7dc5d011256f76c99c0a96
rustls-webpki|0.103.13|registry+https://github.com/rust-lang/crates.io-index|61c429a8649f110dddef65e2a5ad240f747e85f7758a6bccc7e5777bd33f756e
rustversion|1.0.23|registry+https://github.com/rust-lang/crates.io-index|cf54715a573b99ac80df0bc206da022bcd442c974952c7b9720069370852e21f
same-file|1.0.6|registry+https://github.com/rust-lang/crates.io-index|93fc1dc3aaa9bfed95e02e6eadabb4baf7e3078b0bd1b4d7b6b0b68378900502
scopeguard|1.2.0|registry+https://github.com/rust-lang/crates.io-index|94143f37725109f92c262ed2cf5e59bce7498c01bcc1502d7b9afe439a4e9f49
semver|1.0.28|registry+https://github.com/rust-lang/crates.io-index|8a7852d02fc848982e0c167ef163aaff9cd91dc640ba85e263cb1ce46fae51cd
serde|1.0.229|registry+https://github.com/rust-lang/crates.io-index|4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba
serde_core|1.0.229|registry+https://github.com/rust-lang/crates.io-index|67dca2c9c51e58a4791a4b1ed58308b39c64224d349a935ab5039aa360942a48
serde_derive|1.0.229|registry+https://github.com/rust-lang/crates.io-index|e7a5d71263a5a7d47b41f6b3f06ba276f10cc18b0931f1799f710578e2309348
serde_json|1.0.151|registry+https://github.com/rust-lang/crates.io-index|c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14
serde_spanned|1.1.1|registry+https://github.com/rust-lang/crates.io-index|6662b5879511e06e8999a8a235d848113e942c9124f211511b16466ee2995f26
shadowsocks-crypto|0.7.0||
sharded-slab|0.1.7|registry+https://github.com/rust-lang/crates.io-index|f40ca3c46823713e0d4209592e8d6e826aa57e928f09752619fc696c499637f6
shlex|2.0.1|registry+https://github.com/rust-lang/crates.io-index|f8fadd59c855ef2080decdef8ff161eb6661b86933c9d82e5ba29dc602a55aba
signal-hook-registry|1.4.8|registry+https://github.com/rust-lang/crates.io-index|c4db69cba1110affc0e9f7bcd48bbf87b3f4fc7c61fc9155afd4c469eb3d6c1b
simd_cesu8|1.2.0|registry+https://github.com/rust-lang/crates.io-index|11031e251abf8611c80f460e19dbdeb54a66db918e49c65a7065b46ac7aec520
simdutf8|0.1.5|registry+https://github.com/rust-lang/crates.io-index|e3a9fe34e3e7a50316060351f37187a3f546bce95496156754b601a5fa71b76e
slab|0.4.12|registry+https://github.com/rust-lang/crates.io-index|0c790de23124f9ab44544d7ac05d60440adc586479ce501c1d6d7da3cd8c9cf5
smallvec|1.15.2|registry+https://github.com/rust-lang/crates.io-index|8ed6a63f02c8539c91a8685a86f4099661ba3da017932f6ebbea6de3f0fa7c90
socket2|0.6.5|registry+https://github.com/rust-lang/crates.io-index|c3d1e2c7f27f8d4cb10542a02c49005dbd6e93095799d6f3be745fae9f8fedd4
stable_deref_trait|1.2.1|registry+https://github.com/rust-lang/crates.io-index|6ce2be8dc25455e1f91df71bfa12ad37d7af1092ae736f3a6cd0e37bc7810596
subtle|2.6.1|registry+https://github.com/rust-lang/crates.io-index|13c2bddecc57b384dee18652358fb23172facb8a2c51ccc10d74c157bdea3292
syn|2.0.119|registry+https://github.com/rust-lang/crates.io-index|872831b642d1a07999a962a351ed35b955ea2cfc8f3862091e2a240a84f17297
syn|3.0.3|registry+https://github.com/rust-lang/crates.io-index|53e9bae58849f64dfa4f5d5ae372c8341f7305f82a3868709269343628b659a3
synstructure|0.13.2|registry+https://github.com/rust-lang/crates.io-index|728a70f3dbaf5bab7f0c4b1ac8d7ae5ea60a4b5549c8a5914361c99147a709d2
tagptr|0.2.0|registry+https://github.com/rust-lang/crates.io-index|7b2093cf4c8eb1e67749a6762251bc9cd836b6fc171623bd0a9d324d37af2417
tempfile|3.27.0|registry+https://github.com/rust-lang/crates.io-index|32497e9a4c7b38532efcdebeef879707aa9f794296a4f0244f6f69e9bc8574bd
thiserror|2.0.19|registry+https://github.com/rust-lang/crates.io-index|09a43598840e33d5b0331f38c5e30d13bb11c11210a4b58f0d9b18a5a5eefcd9
thiserror-impl|2.0.19|registry+https://github.com/rust-lang/crates.io-index|43cbfe0cf76104d42a574802844187e84a305e531ed54455f11fbde0f10541cd
thread_local|1.1.10|registry+https://github.com/rust-lang/crates.io-index|1ad99c4c6d32803332c548b1af0540b357b3f5fc0be8f6c6bfe8b2e6ae784070
time|0.3.55|registry+https://github.com/rust-lang/crates.io-index|cdb87b95ec50ddfa440816d227a17b2ccbdda963a316a727fda0fc4334f7d134
time-core|0.1.9|registry+https://github.com/rust-lang/crates.io-index|9e1c906769ad99c88eaa54e728060edef082f8e358ff32030cb7c7d315e81109
tinystr|0.8.3|registry+https://github.com/rust-lang/crates.io-index|c8323304221c2a851516f22236c5722a72eaa19749016521d6dff0824447d96d
tinyvec|1.12.0|registry+https://github.com/rust-lang/crates.io-index|bb4ebadaa0af04fab11ae01eb5f9fdb5f9c5b875506e210e71c07873528baa7f
tinyvec_macros|0.1.1|registry+https://github.com/rust-lang/crates.io-index|1f3ccbac311fea05f86f61904b462b55fb3df8837a366dfc601a0161d0532f20
tokio|1.53.1|registry+https://github.com/rust-lang/crates.io-index|202caea871b69668250d242070849eb495be178ed697a3e98aebce5bc81a0bed
tokio-macros|2.7.1|registry+https://github.com/rust-lang/crates.io-index|6328af13490e73a9b4694030fafd93f8c8c6a9dede33e821c3fc63eddf8042ba
tokio-rustls|0.26.4|registry+https://github.com/rust-lang/crates.io-index|1729aa945f29d91ba541258c8df89027d5792d85a8841fb65e8bf0f4ede4ef61
tokio-util|0.7.19|registry+https://github.com/rust-lang/crates.io-index|494815d09bf52b5548659851081238f0ca39ff638363907596da739561c62c52
toml|1.1.3+spec-1.1.0|registry+https://github.com/rust-lang/crates.io-index|53c96ecdfa941c8fc4fcaed14f99ada8ebed502eef533015095a07e3301d4c3c
toml_datetime|1.1.1+spec-1.1.0|registry+https://github.com/rust-lang/crates.io-index|3165f65f62e28e0115a00b2ebdd37eb6f3b641855f9d636d3cd4103767159ad7
toml_parser|1.1.2+spec-1.1.0|registry+https://github.com/rust-lang/crates.io-index|a2abe9b86193656635d2411dc43050282ca48aa31c2451210f4202550afb7526
toml_writer|1.1.2+spec-1.1.0|registry+https://github.com/rust-lang/crates.io-index|7d56353a2a665ad0f41a421187180aab746c8c325620617ad883a99a1cbe66d2
tracing|0.1.44|registry+https://github.com/rust-lang/crates.io-index|63e71662fa4b2a2c3a26f570f037eb95bb1f85397f3cd8076caed2f026a6d100
tracing-core|0.1.36|registry+https://github.com/rust-lang/crates.io-index|db97caf9d906fbde555dd62fa95ddba9eecfd14cb388e4f491a66d74cd5fb79a
tracing-serde|0.2.0|registry+https://github.com/rust-lang/crates.io-index|704b1aeb7be0d0a84fc9828cae51dab5970fee5088f83d1dd7ee6f6246fc6ff1
tracing-subscriber|0.3.23|registry+https://github.com/rust-lang/crates.io-index|cb7f578e5945fb242538965c2d0b04418d38ec25c79d160cd279bf0731c8d319
typenum|1.20.1|registry+https://github.com/rust-lang/crates.io-index|b6f5e870be6c3b371b77fe0ee0bafb859fa4964b4404c27de1d380043c4dda20
unicode-ident|1.0.24|registry+https://github.com/rust-lang/crates.io-index|e6e4313cd5fcd3dad5cafa179702e2b244f760991f45397d14d4ebf38247da75
universal-hash|0.6.1|registry+https://github.com/rust-lang/crates.io-index|f4987bdc12753382e0bec4a65c50738ffaabc998b9cdd1f952fb5f39b0048a96
untrusted|0.9.0|registry+https://github.com/rust-lang/crates.io-index|8ecb6da28b8a351d773b68d5825ac39017e680750f980f3a1a85cd8dd28a47c1
url|2.5.8|registry+https://github.com/rust-lang/crates.io-index|ff67a8a4397373c3ef660812acab3268222035010ab8680ec4215f38ba3d0eed
utf8_iter|1.0.4|registry+https://github.com/rust-lang/crates.io-index|b6c140620e7ffbb22c2dee59cafe6084a59b5ffc27a8859a5f0d494b5d52b6be
uuid|1.24.0|registry+https://github.com/rust-lang/crates.io-index|bf3923a6f5c4c6382e0b653c4117f48d631ea17f38ed86e2a828e6f7412f5239
valuable|0.1.1|registry+https://github.com/rust-lang/crates.io-index|ba73ea9cf16a25df0c8caa16c51acb937d5712a8429db78a3ee29d5dcacd3a65
walkdir|2.5.0|registry+https://github.com/rust-lang/crates.io-index|29790946404f91d9c5d06f9874efddea1dc06c5efe94541a7d6863108e3a5e4b
wasi|0.11.1+wasi-snapshot-preview1|registry+https://github.com/rust-lang/crates.io-index|ccf3ec651a847eb01de73ccad15eb7d99f80485de043efb2f370cd654f4ea44b
wasm-bindgen|0.2.126|registry+https://github.com/rust-lang/crates.io-index|4b067c0c11094aef6b7a801c1e34a26affafdf3d051dba08456b868789aaf9a4
wasm-bindgen-macro|0.2.126|registry+https://github.com/rust-lang/crates.io-index|167ce5e579f6bcf889c4f7175a8a5a585de84e8ff93976ce393efa5f2837aab1
wasm-bindgen-macro-support|0.2.126|registry+https://github.com/rust-lang/crates.io-index|f3997c7839262f4ef12cf90b818d6340c18e80f263f1a94bf157d0ec4420380e
wasm-bindgen-shared|0.2.126|registry+https://github.com/rust-lang/crates.io-index|dc1b4cb0cc549fcf58d7dfc081778139b3d283a081644e833e84682ad71cea24
webpki-roots|1.0.9|registry+https://github.com/rust-lang/crates.io-index|7dcd9d09a39985f5344844e66b0c530a33843579125f23e21e9f0f220850f22a
winapi-util|0.1.11|registry+https://github.com/rust-lang/crates.io-index|c2a7b1c03c876122aa43f3020e6c3c3ee5c05081c9a00739faf7503aeba10d22
windows-link|0.2.1|registry+https://github.com/rust-lang/crates.io-index|f0805222e57f7521d6a62e36fa9163bc891acd422f971defe97d64e70d0a4fe5
windows-sys|0.52.0|registry+https://github.com/rust-lang/crates.io-index|282be5f36a8ce781fad8c8ae18fa3f9beff57ec1b52cb3de0789201425d9a33d
windows-sys|0.61.2|registry+https://github.com/rust-lang/crates.io-index|ae137229bcbd6cdf0f7b80a31df61766145077ddf49416a728b02cb3921ff3fc
windows-targets|0.52.6|registry+https://github.com/rust-lang/crates.io-index|9b724f72796e036ab90c1021d4780d4d3d648aca59e491e6b98e725b84e99973
windows_aarch64_gnullvm|0.52.6|registry+https://github.com/rust-lang/crates.io-index|32a4622180e7a0ec044bb555404c800bc9fd9ec262ec147edd5989ccd0c02cd3
windows_aarch64_msvc|0.52.6|registry+https://github.com/rust-lang/crates.io-index|09ec2a7bb152e2252b53fa7803150007879548bc709c039df7627cabbd05d469
windows_i686_gnu|0.52.6|registry+https://github.com/rust-lang/crates.io-index|8e9b5ad5ab802e97eb8e295ac6720e509ee4c243f69d781394014ebfe8bbfa0b
windows_i686_gnullvm|0.52.6|registry+https://github.com/rust-lang/crates.io-index|0eee52d38c090b3caa76c563b86c3a4bd71ef1a819287c19d586d7334ae8ed66
windows_i686_msvc|0.52.6|registry+https://github.com/rust-lang/crates.io-index|240948bc05c5e7c6dabba28bf89d89ffce3e303022809e73deaefe4f6ec56c66
windows_x86_64_gnu|0.52.6|registry+https://github.com/rust-lang/crates.io-index|147a5c80aabfbf0c7d901cb5895d1de30ef2907eb21fbbab29ca94c5b08b1a78
windows_x86_64_gnullvm|0.52.6|registry+https://github.com/rust-lang/crates.io-index|24d5b23dc417412679681396f2b49f3de8c1473deb516bd34410872eff51ed0d
windows_x86_64_msvc|0.52.6|registry+https://github.com/rust-lang/crates.io-index|589f6da84c646204747d1270a2a5661ea66ed1cced2631d546fdfb155959f9ec
winnow|1.0.4|registry+https://github.com/rust-lang/crates.io-index|23b97319f7b8343df12cc98938e5c3eb436064524c8d2b4e30a1d3a36eecdf81
writeable|0.6.3|registry+https://github.com/rust-lang/crates.io-index|1ffae5123b2d3fc086436f8834ae3ab053a283cfac8fe0a0b8eaae044768a4c4
yoke|0.8.3|registry+https://github.com/rust-lang/crates.io-index|709fe23a0424b6a435d82152b1bd3fdfb0833487d5fa90d05d42762a9891fef5
yoke-derive|0.8.2|registry+https://github.com/rust-lang/crates.io-index|de844c262c8848816172cef550288e7dc6c7b7814b4ee56b3e1553f275f1858e
zerofrom|0.1.8|registry+https://github.com/rust-lang/crates.io-index|0ec05a11813ea801ff6d75110ad09cd0824ddba17dfe17128ea0d5f68e6c5272
zerofrom-derive|0.1.7|registry+https://github.com/rust-lang/crates.io-index|11532158c46691caf0f2593ea8358fed6bbf68a0315e80aae9bd41fbade684a1
zeroize|1.9.0|registry+https://github.com/rust-lang/crates.io-index|e13c156562582aa81c60cb29407084cdb54c4164760106ab78e6c5b0858cf64e
zeroize_derive|1.5.0|registry+https://github.com/rust-lang/crates.io-index|3c50655cbb0fe3fc43170059e702f1ce5e19b84cec58dc87b037a09935c2f328
zerotrie|0.2.4|registry+https://github.com/rust-lang/crates.io-index|0f9152d31db0792fa83f70fb2f83148effb5c1f5b8c7686c3459e361d9bc20bf
zerovec|0.11.6|registry+https://github.com/rust-lang/crates.io-index|90f911cbc359ab6af17377d242225f4d75119aec87ea711a880987b18cd7b239
zerovec-derive|0.11.3|registry+https://github.com/rust-lang/crates.io-index|625dc425cab0dca6dc3c3319506e6593dcb08a9f387ea3b284dbd52a92c40555
zmij|1.0.23|registry+https://github.com/rust-lang/crates.io-index|29666d0abbfad1e3dc4dcf6144730dd3a3ab225bbbdac83319345b1b44ccfc1b
"#;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LockIdentity {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

fn normalize_line_endings(source: &str) -> Result<String, String> {
    let normalized = source.replace("\r\n", "\n");
    if normalized.contains('\r') {
        return Err("bare carriage return is forbidden".to_owned());
    }
    Ok(normalized)
}

fn dependency_table(
    manifest: &str,
    table_header: &str,
) -> Result<BTreeMap<String, String>, String> {
    let normalized = normalize_line_endings(manifest)?;
    let mut in_table = false;
    let mut declarations = BTreeMap::new();

    for line in normalized.lines() {
        let line = line.trim();
        if line == table_header {
            in_table = true;
            continue;
        }
        if in_table && line.starts_with('[') {
            break;
        }
        if !in_table || line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (name, value) = line
            .split_once(" = ")
            .ok_or_else(|| format!("invalid dependency declaration: {line}"))?;
        if name.is_empty() || value.is_empty() {
            return Err(format!("invalid dependency declaration: {line}"));
        }
        if declarations
            .insert(name.to_owned(), value.to_owned())
            .is_some()
        {
            return Err(format!("duplicate dependency declaration: {name}"));
        }
    }

    if !in_table {
        return Err(format!("missing dependency table: {table_header}"));
    }
    Ok(declarations)
}

fn quoted_lock_field(block: &str, field: &str) -> Result<Option<String>, String> {
    let prefix = format!("{field} = ");
    let mut values = block.lines().filter_map(|line| {
        line.trim()
            .strip_prefix(&prefix)
            .map(str::trim)
            .map(str::to_owned)
    });
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(format!("duplicate lock field: {field}"));
    }
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| format!("lock field is not a quoted string: {field}"))?;
    Ok(Some(value.to_owned()))
}

fn lock_identities(lock: &str) -> Result<Vec<LockIdentity>, String> {
    let normalized = normalize_line_endings(lock)?;
    let mut identities = Vec::new();

    for block in normalized.split("[[package]]").skip(1) {
        identities.push(LockIdentity {
            name: quoted_lock_field(block, "name")?
                .ok_or_else(|| "lock package missing name".to_owned())?,
            version: quoted_lock_field(block, "version")?
                .ok_or_else(|| "lock package missing version".to_owned())?,
            source: quoted_lock_field(block, "source")?,
            checksum: quoted_lock_field(block, "checksum")?,
        });
    }

    identities.sort();
    Ok(identities)
}

fn lock_package_dependencies(lock: &str, package_name: &str) -> Result<BTreeSet<String>, String> {
    let normalized = normalize_line_endings(lock)?;
    let mut matches = normalized.split("[[package]]").skip(1).filter(|block| {
        quoted_lock_field(block, "name").is_ok_and(|name| name.as_deref() == Some(package_name))
    });
    let block = matches
        .next()
        .ok_or_else(|| format!("lock package not found: {package_name}"))?;
    if matches.next().is_some() {
        return Err(format!("duplicate lock package: {package_name}"));
    }
    let mut in_dependencies = false;
    let mut dependencies = BTreeSet::new();
    for line in block.lines() {
        let line = line.trim();
        if line == "dependencies = [" {
            if in_dependencies {
                return Err("duplicate dependencies array".to_owned());
            }
            in_dependencies = true;
            continue;
        }
        if !in_dependencies {
            continue;
        }
        if line == "]" {
            return Ok(dependencies);
        }
        let dependency = line
            .strip_suffix(',')
            .and_then(|line| line.strip_prefix('"'))
            .and_then(|line| line.strip_suffix('"'))
            .ok_or_else(|| format!("invalid lock dependency entry: {line}"))?;
        if !dependencies.insert(dependency.to_owned()) {
            return Err(format!("duplicate lock dependency: {dependency}"));
        }
    }
    Err(format!("missing lock dependencies array: {package_name}"))
}

fn approved_lock_identities() -> Vec<LockIdentity> {
    let identities: Vec<_> = APPROVED_LOCK_IDENTITIES
        .lines()
        .map(|line| {
            let fields: Vec<_> = line.split('|').collect();
            assert_eq!(fields.len(), 4, "invalid embedded lock identity: {line}");
            LockIdentity {
                name: fields[0].to_owned(),
                version: fields[1].to_owned(),
                source: (!fields[2].is_empty()).then(|| fields[2].to_owned()),
                checksum: (!fields[3].is_empty()).then(|| fields[3].to_owned()),
            }
        })
        .collect();
    assert_eq!(
        identities.len(),
        224,
        "the approved workspace baseline must contain 224 identities"
    );
    let mut sorted = identities.clone();
    sorted.sort();
    if identities != sorted {
        let index = identities
            .iter()
            .zip(&sorted)
            .position(|(embedded, sorted)| embedded != sorted)
            .expect("different vectors must have a mismatched entry");
        panic!(
            "the embedded lock identity baseline must be sorted at index {index}: embedded={:?}, sorted={:?}",
            identities[index], sorted[index]
        );
    }
    identities
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("harness must be two levels below the workspace root")
        .to_path_buf()
}

fn metadata() -> Value {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--locked", "--format-version", "1"])
        .current_dir(workspace_root())
        .output()
        .expect("cargo metadata must start");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata JSON")
}

fn unique_registry_package_id(metadata: &Value, name: &str, version: &str) -> String {
    let packages: Vec<_> = metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .filter(|package| {
            package["name"] == name
                && package["version"] == version
                && package["source"] == "registry+https://github.com/rust-lang/crates.io-index"
        })
        .collect();
    assert_eq!(
        packages.len(),
        1,
        "{name} {version} must have exactly one registry package instance"
    );
    packages[0]["id"].as_str().expect("package ID").to_owned()
}

fn resolve_node<'a>(metadata: &'a Value, package_id: &str) -> &'a Value {
    let nodes: Vec<_> = metadata["resolve"]["nodes"]
        .as_array()
        .expect("resolve nodes")
        .iter()
        .filter(|node| node["id"] == package_id)
        .collect();
    assert_eq!(
        nodes.len(),
        1,
        "{package_id} must have exactly one resolve node"
    );
    nodes[0]
}

fn contains_manifest_policy(manifest: &str, policy: &str) -> bool {
    normalize_line_endings(manifest).is_ok_and(|manifest| manifest.contains(policy))
}

const ROOT_TOKIO_DECLARATION: &str = "tokio = { version = \"=1.53.1\", default-features = false, features = [\"rt-multi-thread\", \"macros\", \"net\", \"io-util\", \"sync\", \"time\", \"signal\"] }";
const BINARY_TOKIO_NORMAL_DECLARATION: &str = "tokio.workspace = true";
const BINARY_TOKIO_DEV_DECLARATION: &str =
    "tokio = { workspace = true, features = [\"test-util\"] }";

fn exact_binary_tokio_boundary(
    root_manifest: &str,
    client_manifest: &str,
    server_manifest: &str,
) -> Result<(), String> {
    let root = normalize_line_endings(root_manifest)?;
    if root
        .lines()
        .filter(|line| line.trim() == "[workspace.dependencies]")
        .count()
        != 1
    {
        return Err("workspace dependency table must be unique".to_owned());
    }
    let root_dependencies = dependency_table(&root, "[workspace.dependencies]")?;
    if root_dependencies.get("tokio").map(String::as_str)
        != ROOT_TOKIO_DECLARATION.strip_prefix("tokio = ")
    {
        return Err("root Tokio declaration changed".to_owned());
    }
    let root_tokio_lines: Vec<_> = root
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("tokio = "))
        .collect();
    if root_tokio_lines != [ROOT_TOKIO_DECLARATION] {
        return Err("root contains an extra or moved Tokio declaration".to_owned());
    }

    for (role, manifest) in [("client", client_manifest), ("server", server_manifest)] {
        let manifest = normalize_line_endings(manifest)?;
        for header in ["[dependencies]", "[dev-dependencies]"] {
            if manifest
                .lines()
                .filter(|line| line.trim() == header)
                .count()
                != 1
            {
                return Err(format!("{role} {header} must be unique"));
            }
        }
        let normal = dependency_table(&manifest, "[dependencies]")?;
        if normal.get("tokio.workspace").map(String::as_str) != Some("true")
            || normal.contains_key("tokio")
        {
            return Err(format!("{role} normal Tokio declaration changed"));
        }
        let dev = dependency_table(&manifest, "[dev-dependencies]")?;
        let mut expected_dev = BTreeMap::from([(
            "tokio".to_owned(),
            BINARY_TOKIO_DEV_DECLARATION
                .strip_prefix("tokio = ")
                .expect("dev declaration prefix")
                .to_owned(),
        )]);
        expected_dev.insert("hickory-proto.workspace".to_owned(), "true".to_owned());
        if dev != expected_dev {
            return Err(format!("{role} dev dependencies changed"));
        }
        let tokio_lines: Vec<_> = manifest
            .lines()
            .map(str::trim)
            .filter(|line| line.contains("tokio"))
            .collect();
        if tokio_lines
            != [
                BINARY_TOKIO_NORMAL_DECLARATION,
                BINARY_TOKIO_DEV_DECLARATION,
            ]
        {
            return Err(format!("{role} contains an extra or moved Tokio edge"));
        }
    }
    Ok(())
}

fn cargo_tree_for_tokio(package: &str, edges: &str) -> String {
    let output = Command::new(env!("CARGO"))
        .args([
            "tree", "-p", package, "--locked", "-e", edges, "-i", "tokio",
        ])
        .current_dir(workspace_root())
        .output()
        .expect("cargo tree must start");
    assert!(
        output.status.success(),
        "cargo tree failed for {package} {edges}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("cargo tree output must be UTF-8")
}

#[test]
fn toolchain_and_msrv_are_pinned() {
    let root = workspace_root();
    let toolchain = fs::read_to_string(root.join("rust-toolchain.toml")).expect("toolchain file");
    for required in [
        "channel = \"1.97.1\"",
        "profile = \"minimal\"",
        "components = [\"rustfmt\", \"clippy\"]",
        "\"x86_64-pc-windows-msvc\"",
        "\"x86_64-unknown-linux-gnu\"",
        "\"x86_64-unknown-linux-musl\"",
    ] {
        assert!(
            toolchain.contains(required),
            "missing toolchain policy: {required}"
        );
    }

    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("root manifest");
    assert!(manifest.contains("edition = \"2024\""));
    assert!(manifest.contains("rust-version = \"1.88.0\""));
    assert!(manifest.contains("resolver = \"3\""));

    let cargo_config =
        fs::read_to_string(root.join(".cargo/config.toml")).expect("Cargo configuration");
    assert!(cargo_config.contains("incompatible-rust-versions = \"fallback\""));

    let workflow = fs::read_to_string(root.join(".github/workflows/m0.yml")).expect("workflow");
    for required in [
        "rustup toolchain install 1.88.0 --profile minimal",
        "rustc +1.88.0 -Vv",
        "cargo +1.88.0 -V",
        "cargo +1.88.0 check --workspace --all-targets --locked",
        "cargo +1.88.0 build --workspace --bins --locked",
        "cargo +1.88.0 test --workspace --locked",
    ] {
        assert!(workflow.contains(required), "missing MSRV gate: {required}");
    }
    assert!(!workflow.contains("1.85.0"));
}

#[test]
fn direct_dependency_versions_and_features_match_the_approved_baseline() {
    let manifest = fs::read_to_string(workspace_root().join("Cargo.toml")).expect("root manifest");
    let required = [
        "aes = { version = \"=0.9.1\", default-features = false, features = [\"zeroize\"] }",
        "tokio = { version = \"=1.53.1\", default-features = false, features = [\"rt-multi-thread\", \"macros\", \"net\", \"io-util\", \"sync\", \"time\", \"signal\"] }",
        "bytes = \"=1.12.1\"",
        "socket2 = \"=0.6.5\"",
        "serde = { version = \"=1.0.229\", default-features = false, features = [\"std\", \"derive\"] }",
        "toml = { version = \"=1.1.3\", default-features = false, features = [\"std\", \"serde\", \"parse\"] }",
        "tracing = { version = \"=0.1.44\", default-features = false, features = [\"std\"] }",
        "tracing-subscriber = { version = \"=0.3.23\", default-features = false, features = [\"fmt\", \"json\", \"env-filter\"] }",
        "prometheus-client = { version = \"=0.25.0\", default-features = false }",
        "shadowsocks-crypto = { version = \"=0.7.0\", default-features = false, features = [\"v2\"] }",
        "hickory-resolver = { version = \"=0.26.1\", default-features = false, features = [\"tokio\", \"tls-ring\", \"https-ring\", \"webpki-roots\"] }",
        "hickory-proto = { version = \"=0.26.1\", default-features = false, features = [\"std\"] }",
        "hickory-server = { version = \"=0.26.1\", default-features = false }",
        "ipnet = { version = \"=2.12.1\", default-features = false }",
        "h2 = { version = \"=0.4.15\", default-features = false, features = [\"stream\"] }",
        "futures-util = { version = \"=0.3.33\", default-features = false, features = [\"std\"] }",
        "rustls = { version = \"=0.23.43\", default-features = false, features = [\"ring\", \"std\", \"tls12\"] }",
        "tokio-rustls = { version = \"=0.26.4\", default-features = false, features = [\"ring\"] }",
        "httparse = { version = \"=1.10.1\", default-features = false }",
        "aes-gcm = { version = \"=0.11.0\", default-features = false, features = [\"aes\", \"bytes\", \"zeroize\"] }",
        "chacha20poly1305 = { version = \"=0.11.0\", default-features = false, features = [\"bytes\", \"zeroize\"] }",
        "blake3 = { version = \"=1.8.5\", default-features = false, features = [\"std\", \"zeroize\"] }",
        "base64 = { version = \"=0.23.0\", default-features = false, features = [\"std\"] }",
        "zeroize = { version = \"=1.9.0\", default-features = false, features = [\"alloc\", \"derive\"] }",
        "getrandom = { version = \"=0.4.3\", default-features = false, features = [\"std\"] }",
        "clap = { version = \"=4.6.4\", default-features = false, features = [\"std\", \"derive\", \"help\", \"usage\", \"error-context\"] }",
        "thiserror = \"=2.0.19\"",
        "hex = \"=0.4.3\"",
        "serde_json = \"=1.0.151\"",
        "tempfile = \"=3.27.0\"",
    ];

    for dependency in required {
        assert!(
            manifest.contains(dependency),
            "missing exact dependency contract: {dependency}"
        );
    }

    let dependency_table =
        dependency_table(&manifest, "[workspace.dependencies]").expect("workspace dependencies");
    assert_eq!(
        dependency_table.get("aes").map(String::as_str),
        Some(r#"{ version = "=0.9.1", default-features = false, features = ["zeroize"] }"#)
    );
    let actual_names: BTreeSet<_> = dependency_table.keys().map(String::as_str).collect();
    let expected_names = BTreeSet::from([
        "aes",
        "aes-gcm",
        "base64",
        "blake3",
        "bytes",
        "chacha20poly1305",
        "clap",
        "ferrum2-config",
        "ferrum2-core",
        "ferrum2-crypto",
        "ferrum2-dns",
        "ferrum2-observability",
        "ferrum2-runtime",
        "ferrum2-shadowsocks",
        "ferrum2-sniff",
        "ferrum2-socks5",
        "futures-util",
        "getrandom",
        "h2",
        "hex",
        "hickory-proto",
        "hickory-resolver",
        "hickory-server",
        "httparse",
        "ipnet",
        "prometheus-client",
        "rustls",
        "serde",
        "serde_json",
        "shadowsocks-crypto",
        "socket2",
        "tempfile",
        "thiserror",
        "tokio",
        "tokio-rustls",
        "toml",
        "tracing",
        "tracing-subscriber",
        "zeroize",
    ]);
    assert_eq!(
        actual_names, expected_names,
        "workspace dependencies must be exactly the approved baseline"
    );

    for forbidden in [
        "features = [\"full\"]",
        "async-trait",
        "openssl",
        "io-uring",
        "secrecy",
        "subtle =",
        "rand =",
        "reduced-round",
        "xchacha",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "forbidden dependency or feature: {forbidden}"
        );
    }
}

#[test]
fn core_ipnet_edge_is_exact_no_default_and_adds_no_identity() {
    let root = workspace_root();
    let manifest =
        fs::read_to_string(root.join("crates/ferrum2-core/Cargo.toml")).expect("core manifest");
    assert_eq!(
        dependency_table(&manifest, "[dependencies]").expect("core dependencies"),
        BTreeMap::from([
            ("bytes.workspace".to_owned(), "true".to_owned()),
            ("ipnet.workspace".to_owned(), "true".to_owned()),
        ])
    );

    let metadata = metadata();
    let core = metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|package| package["name"] == "ferrum2-core")
        .expect("core package");
    let ipnet = core["dependencies"]
        .as_array()
        .expect("core dependencies")
        .iter()
        .find(|dependency| dependency["name"] == "ipnet")
        .expect("core ipnet dependency");
    assert_eq!(ipnet["req"], "=2.12.1");
    assert_eq!(ipnet["kind"], Value::Null);
    assert_eq!(ipnet["uses_default_features"], false);
    assert_eq!(ipnet["features"], serde_json::json!([]));

    let package_id = unique_registry_package_id(&metadata, "ipnet", "2.12.1");
    assert_eq!(
        resolve_node(&metadata, &package_id)["features"],
        serde_json::json!(["default", "serde", "std"]),
        "the no-default core edge must not expand ipnet's existing Hickory feature set"
    );
    let lock = fs::read_to_string(root.join("Cargo.lock")).expect("Cargo.lock");
    assert_eq!(
        lock_package_dependencies(&lock, "ferrum2-core").expect("core lock dependencies"),
        BTreeSet::from(["bytes".to_owned(), "ipnet".to_owned()])
    );
}

#[test]
fn sniff_parser_edges_and_resolved_features_are_exact() {
    let root = workspace_root();
    let manifest =
        fs::read_to_string(root.join("crates/ferrum2-sniff/Cargo.toml")).expect("sniff manifest");
    assert_eq!(
        dependency_table(&manifest, "[dependencies]").expect("sniff dependencies"),
        BTreeMap::from([
            ("hickory-proto.workspace".to_owned(), "true".to_owned()),
            ("httparse.workspace".to_owned(), "true".to_owned()),
            ("rustls.workspace".to_owned(), "true".to_owned()),
        ])
    );

    let metadata = metadata();
    let packages = metadata["packages"].as_array().expect("packages");
    let sniff = packages
        .iter()
        .find(|package| package["name"] == "ferrum2-sniff")
        .expect("sniff package");
    assert_eq!(sniff["features"], serde_json::json!({}));
    for (name, version, features) in [
        ("hickory-proto", "=0.26.1", &["std"][..]),
        ("httparse", "=1.10.1", &[][..]),
        ("rustls", "=0.23.43", &["ring", "std", "tls12"][..]),
    ] {
        let edge = sniff["dependencies"]
            .as_array()
            .expect("sniff dependencies")
            .iter()
            .find(|dependency| dependency["name"] == name)
            .unwrap_or_else(|| panic!("missing sniff dependency {name}"));
        assert_eq!(edge["req"], version);
        assert_eq!(edge["kind"], Value::Null);
        assert_eq!(edge["uses_default_features"], false);
        assert_eq!(edge["features"], serde_json::json!(features));
    }

    let httparse_id = unique_registry_package_id(&metadata, "httparse", "1.10.1");
    let httparse = packages
        .iter()
        .find(|package| package["id"] == httparse_id)
        .expect("httparse package");
    assert_eq!(
        httparse["source"],
        "registry+https://github.com/rust-lang/crates.io-index"
    );
    assert_eq!(httparse["license"], "MIT OR Apache-2.0");
    assert_eq!(httparse["rust_version"], Value::Null);
    assert_eq!(
        resolve_node(&metadata, &httparse_id)["features"],
        serde_json::json!([]),
        "the no-default sniff edge must not enable httparse's std feature"
    );
    assert!(
        httparse["dependencies"]
            .as_array()
            .expect("httparse dependencies")
            .iter()
            .all(|dependency| dependency["kind"] == "dev"),
        "httparse must have no normal or build dependency"
    );

    let lock = fs::read_to_string(root.join("Cargo.lock")).expect("Cargo.lock");
    assert_eq!(
        lock_package_dependencies(&lock, "ferrum2-sniff").expect("sniff lock dependencies"),
        BTreeSet::from([
            "hickory-proto".to_owned(),
            "httparse".to_owned(),
            "rustls".to_owned(),
        ])
    );
}

#[test]
fn crypto_manifest_has_one_normal_backend_and_dev_only_oracles() {
    let manifest = fs::read_to_string(
        workspace_root()
            .join("crates")
            .join("ferrum2-crypto")
            .join("Cargo.toml"),
    )
    .expect("crypto manifest");
    assert_eq!(
        dependency_table(&manifest, "[dependencies]").expect("crypto dependencies"),
        BTreeMap::from([
            ("bytes.workspace".to_owned(), "true".to_owned()),
            ("getrandom.workspace".to_owned(), "true".to_owned()),
            ("shadowsocks-crypto.workspace".to_owned(), "true".to_owned()),
            ("zeroize.workspace".to_owned(), "true".to_owned()),
        ])
    );
    assert_eq!(
        dependency_table(&manifest, "[dev-dependencies]").expect("crypto dev dependencies"),
        BTreeMap::from([
            ("aes.workspace".to_owned(), "true".to_owned()),
            ("aes-gcm.workspace".to_owned(), "true".to_owned()),
            ("blake3.workspace".to_owned(), "true".to_owned()),
            ("chacha20poly1305.workspace".to_owned(), "true".to_owned()),
            ("hex.workspace".to_owned(), "true".to_owned()),
            ("serde_json.workspace".to_owned(), "true".to_owned()),
        ])
    );
    assert!(
        !manifest.contains("[features]"),
        "crypto backend selection features are forbidden"
    );
}

#[test]
fn hickory_graph_and_features_match_the_approved_dns_policy() {
    let root = workspace_root();
    let manifest =
        fs::read_to_string(root.join("crates/ferrum2-dns/Cargo.toml")).expect("DNS manifest");
    assert_eq!(
        dependency_table(&manifest, "[dependencies]").expect("DNS dependencies"),
        BTreeMap::from([
            ("ferrum2-core.workspace".to_owned(), "true".to_owned()),
            ("futures-util.workspace".to_owned(), "true".to_owned()),
            ("hickory-proto.workspace".to_owned(), "true".to_owned()),
            ("hickory-resolver.workspace".to_owned(), "true".to_owned()),
            ("hickory-server.workspace".to_owned(), "true".to_owned()),
            (
                "rustls".to_owned(),
                "{ workspace = true, optional = true }".to_owned(),
            ),
            ("tokio.workspace".to_owned(), "true".to_owned()),
        ])
    );
    assert_eq!(
        dependency_table(&manifest, "[dev-dependencies]").expect("DNS dev dependencies"),
        BTreeMap::from([
            ("h2.workspace".to_owned(), "true".to_owned()),
            (
                "hickory-server".to_owned(),
                r#"{ workspace = true, features = ["__https"] }"#.to_owned(),
            ),
            ("rustls.workspace".to_owned(), "true".to_owned()),
            (
                "tokio".to_owned(),
                r#"{ workspace = true, features = ["test-util"] }"#.to_owned(),
            ),
            ("tokio-rustls.workspace".to_owned(), "true".to_owned()),
        ])
    );
    assert!(
        manifest.contains("[features]\ndefault = []\n__interop-test-root = [\"dep:rustls\"]\n")
    );
    let resolver = fs::read_to_string(root.join("crates/ferrum2-dns/src/resolver.rs"))
        .expect("DNS resolver source");
    for required in [
        "#[cfg(feature = \"__interop-test-root\")]",
        "include_bytes!(\"../tests/fixtures/m12-test-ca.der\")",
        "with_root_certificates(roots)",
        "DefaultTimeProvider",
    ] {
        assert!(
            resolver.contains(required),
            "missing test-root bound: {required}"
        );
    }
    for forbidden in ["insecure_skip_verify", "std::env", "var_os(", "dangerous()"] {
        assert!(
            !resolver.contains(forbidden),
            "qualification trust must not expose {forbidden}"
        );
    }

    let metadata = metadata();
    let packages = metadata["packages"].as_array().expect("packages");
    let dns = packages
        .iter()
        .find(|package| package["name"] == "ferrum2-dns")
        .expect("DNS package");
    assert_eq!(
        dns["features"],
        serde_json::json!({
            "__interop-test-root": ["dep:rustls"],
            "default": []
        })
    );
    let futures = dns["dependencies"]
        .as_array()
        .expect("DNS dependencies")
        .iter()
        .find(|dependency| dependency["name"] == "futures-util")
        .expect("DNS Hickory stream trait edge");
    assert_eq!(futures["req"], "=0.3.33");
    assert_eq!(futures["kind"], Value::Null);
    assert_eq!(futures["uses_default_features"], false);
    assert_eq!(futures["features"], serde_json::json!(["std"]));
    let futures_id = unique_registry_package_id(&metadata, "futures-util", "0.3.33");
    let futures_node = resolve_node(&metadata, &futures_id);
    assert_eq!(
        futures_node["features"],
        serde_json::json!([
            "alloc",
            "async-await",
            "async-await-macro",
            "futures-macro",
            "slab",
            "std"
        ]),
        "the direct StreamExt edge must not expand the resolved feature set"
    );
    let hickory: BTreeSet<_> = packages
        .iter()
        .filter_map(|package| {
            let name = package["name"].as_str().expect("package name");
            name.starts_with("hickory-")
                .then(|| (name, package["version"].as_str().expect("package version")))
        })
        .collect();
    assert_eq!(
        hickory,
        BTreeSet::from([
            ("hickory-net", "0.26.1"),
            ("hickory-proto", "0.26.1"),
            ("hickory-resolver", "0.26.1"),
            ("hickory-server", "0.26.1"),
        ])
    );

    for (name, expected_features) in [
        (
            "hickory-net",
            &[
                "__https",
                "__tls",
                "https-ring",
                "tls-ring",
                "tokio",
                "webpki-roots",
            ][..],
        ),
        ("hickory-proto", &["access-control", "serde", "std"][..]),
        (
            "hickory-resolver",
            &[
                "__https",
                "__tls",
                "https-ring",
                "tls-ring",
                "tokio",
                "webpki-roots",
            ][..],
        ),
        ("hickory-server", &["__https", "__tls"][..]),
    ] {
        let package_id = unique_registry_package_id(&metadata, name, "0.26.1");
        let package = packages
            .iter()
            .find(|package| package["id"] == package_id)
            .expect("Hickory package");
        assert_eq!(
            package["source"],
            "registry+https://github.com/rust-lang/crates.io-index"
        );
        assert_eq!(package["rust_version"], "1.88");
        assert_eq!(package["license"], "MIT OR Apache-2.0");

        let node = resolve_node(&metadata, &package_id);
        let actual: BTreeSet<_> = node["features"]
            .as_array()
            .expect("resolved Hickory features")
            .iter()
            .map(|feature| feature.as_str().expect("feature name"))
            .collect();
        assert_eq!(actual, expected_features.iter().copied().collect());
    }

    let package_names: BTreeSet<_> = packages
        .iter()
        .map(|package| package["name"].as_str().expect("package name"))
        .collect();
    for forbidden in [
        "aws-lc-rs",
        "aws-lc-sys",
        "h3",
        "h3-quinn",
        "ipconfig",
        "quinn",
        "resolv-conf",
        "system-configuration",
    ] {
        assert!(
            !package_names.contains(forbidden),
            "forbidden DNS dependency: {forbidden}"
        );
    }
    assert_eq!(
        packages
            .iter()
            .filter(|package| package["name"] == "ring")
            .count(),
        1,
        "the DNS TLS graph must resolve one ring provider"
    );
    assert_eq!(
        packages
            .iter()
            .filter(|package| package["name"] == "socket2")
            .map(|package| package["version"].as_str().expect("socket2 version"))
            .collect::<Vec<_>>(),
        ["0.6.5"]
    );

    let server_id = unique_registry_package_id(&metadata, "hickory-server", "0.26.1");
    let server_node = resolve_node(&metadata, &server_id);
    assert!(
        server_node["deps"]
            .as_array()
            .expect("hickory-server dependencies")
            .iter()
            .all(|dependency| dependency["name"] != "hickory_resolver"),
        "the server-only HTTPS fixture gate must not activate hickory-resolver"
    );

    for (name, version, expected_features) in [
        ("h2", "0.4.15", &["stream"][..]),
        (
            "rustls",
            "0.23.43",
            &["log", "logging", "ring", "std", "tls12"][..],
        ),
        ("tokio-rustls", "0.26.4", &["early-data", "ring"][..]),
    ] {
        let package_id = unique_registry_package_id(&metadata, name, version);
        let node = resolve_node(&metadata, &package_id);
        let actual: BTreeSet<_> = node["features"]
            .as_array()
            .expect("resolved TLS test feature set")
            .iter()
            .map(|feature| feature.as_str().expect("feature name"))
            .collect();
        assert_eq!(actual, expected_features.iter().copied().collect());
    }
}

#[test]
fn controlled_shadowsocks_crypto_source_and_v2_graph_are_exact() {
    let root = workspace_root();
    let root_manifest = normalize_line_endings(
        &fs::read_to_string(root.join("Cargo.toml")).expect("root manifest"),
    )
    .expect("root manifest line endings");
    assert!(root_manifest.contains("exclude = [\"vendor/shadowsocks-crypto\"]"));
    assert!(root_manifest.contains(
        "shadowsocks-crypto = { version = \"=0.7.0\", default-features = false, features = [\"v2\"] }"
    ));
    assert!(root_manifest.contains(
        "[patch.crates-io]\nshadowsocks-crypto = { path = \"vendor/shadowsocks-crypto\" }"
    ));

    let crypto_manifest =
        fs::read_to_string(root.join("crates/ferrum2-crypto/Cargo.toml")).expect("crypto manifest");
    assert!(crypto_manifest.contains("shadowsocks-crypto.workspace = true"));

    let vendor = root.join("vendor/shadowsocks-crypto");
    let provenance = fs::read_to_string(vendor.join("FERRUM_PATCH.md")).expect("provenance");
    for exact in [
        "shadowsocks-crypto 0.7.0",
        "9339588f8aee0810546fd7e4dcc219fc4bda2cfd0066dd277b7104d5113fd0c0",
        "2affa6c39b30f7626137a1792c533610cf133ade",
        "Upstream license: MIT",
    ] {
        assert!(provenance.contains(exact), "missing provenance: {exact}");
    }
    let vcs = fs::read_to_string(vendor.join(".cargo_vcs_info.json")).expect("VCS info");
    assert!(vcs.contains("2affa6c39b30f7626137a1792c533610cf133ade"));
    let license = fs::read_to_string(vendor.join("LICENSE")).expect("vendor LICENSE");
    assert!(license.starts_with("MIT License"));

    let mut directories = vec![vendor.join("src")];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory).expect("vendor source directory") {
            let path = entry.expect("vendor source entry").path();
            if path.is_dir() {
                directories.push(path);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                let source = fs::read_to_string(&path).expect("vendor Rust source");
                assert!(
                    !source.contains("unsafe"),
                    "selected vendor source must remain safe: {}",
                    path.display()
                );
            }
        }
    }

    let metadata = metadata();
    let packages = metadata["packages"].as_array().expect("packages");
    let package = packages
        .iter()
        .find(|package| package["name"] == "shadowsocks-crypto")
        .expect("patched package");
    assert_eq!(package["version"], "0.7.0");
    assert!(package["source"].is_null());
    assert_eq!(package["license"], "MIT");
    assert_eq!(package["rust_version"], "1.71");
    assert!(
        package["manifest_path"]
            .as_str()
            .expect("vendor manifest path")
            .replace('\\', "/")
            .ends_with("vendor/shadowsocks-crypto/Cargo.toml")
    );

    let crypto = packages
        .iter()
        .find(|package| package["name"] == "ferrum2-crypto")
        .expect("crypto package");
    let edge = crypto["dependencies"]
        .as_array()
        .expect("crypto dependencies")
        .iter()
        .find(|dependency| dependency["name"] == "shadowsocks-crypto")
        .expect("controlled dependency edge");
    assert_eq!(
        edge["source"],
        "registry+https://github.com/rust-lang/crates.io-index"
    );
    assert_eq!(edge["req"], "=0.7.0");
    assert!(edge["kind"].is_null());
    assert_eq!(edge["uses_default_features"], false);
    assert_eq!(edge["features"], serde_json::json!(["v2"]));

    let node = resolve_node(
        &metadata,
        package["id"].as_str().expect("patched package ID"),
    );
    assert_eq!(node["features"], serde_json::json!(["v2"]));
    let dependencies: BTreeSet<_> = node["deps"]
        .as_array()
        .expect("patched package dependencies")
        .iter()
        .map(|dependency| dependency["name"].as_str().expect("dependency name"))
        .collect();
    assert_eq!(
        dependencies,
        BTreeSet::from([
            "aes_gcm_v2",
            "aes_v2",
            "blake3_v2",
            "chacha20poly1305_v2",
            "ghash_v2",
            "zeroize",
        ])
    );
}

#[test]
fn manifest_dependency_helpers_accept_line_endings_and_reject_mutations() {
    let root_lf = "[workspace.dependencies]\naes = { version = \"=0.9.1\", default-features = false, features = [\"zeroize\"] }\nghash = { version = \"=0.6.0\", default-features = false, features = [\"zeroize\"] }\n\n[workspace.lints.rust]\nunsafe_code = \"forbid\"\n";
    let member_lf =
        "[dependencies]\naes.workspace = true\nghash.workspace = true\n\n[dev-dependencies]\n";

    for root in [root_lf.to_owned(), root_lf.replace('\n', "\r\n")] {
        let dependencies =
            dependency_table(&root, "[workspace.dependencies]").expect("root fixture");
        assert_eq!(
            dependencies,
            BTreeMap::from([
                (
                    "aes".to_owned(),
                    r#"{ version = "=0.9.1", default-features = false, features = ["zeroize"] }"#
                        .to_owned()
                ),
                (
                    "ghash".to_owned(),
                    r#"{ version = "=0.6.0", default-features = false, features = ["zeroize"] }"#
                        .to_owned()
                ),
            ])
        );
    }

    for member in [member_lf.to_owned(), member_lf.replace('\n', "\r\n")] {
        assert_eq!(
            dependency_table(&member, "[dependencies]").expect("member fixture"),
            BTreeMap::from([
                ("aes.workspace".to_owned(), "true".to_owned()),
                ("ghash.workspace".to_owned(), "true".to_owned()),
            ])
        );
    }

    for mutation in [
        root_lf.replace("=0.9.1", "=0.9.2"),
        root_lf.replace("default-features = false", "default-features = true"),
        root_lf.replace("[\"zeroize\"]", "[\"hazmat\", \"zeroize\"]"),
        root_lf.replace("ghash = ", "renamed-ghash = "),
        format!(
            "{}extra = \"=1.0.0\"\n",
            root_lf.replace("\n\n[workspace.lints.rust]", "\n")
        ),
    ] {
        for fixture in [mutation.clone(), mutation.replace('\n', "\r\n")] {
            let dependencies =
                dependency_table(&fixture, "[workspace.dependencies]").expect("root mutation");
            assert_ne!(
                dependencies,
                dependency_table(root_lf, "[workspace.dependencies]").expect("root baseline"),
                "a dependency policy mutation must change the parsed contract"
            );
        }
    }

    for mutation in [
        member_lf.replace("aes.workspace = true\n", ""),
        member_lf.replace("ghash.workspace = true", "ghash.workspace = false"),
        member_lf.replace("aes.workspace = true", "aes = { workspace = true }"),
    ] {
        for fixture in [mutation.clone(), mutation.replace('\n', "\r\n")] {
            assert_ne!(
                dependency_table(&fixture, "[dependencies]").expect("member mutation"),
                dependency_table(member_lf, "[dependencies]").expect("member baseline"),
                "a member anchor mutation must change the parsed contract"
            );
        }
    }

    assert!(dependency_table("[dependencies]\naes.workspace=true\n", "[dependencies]").is_err());
    assert!(
        dependency_table("[dependencies]\raes.workspace = true\r", "[dependencies]").is_err(),
        "bare carriage returns must not bypass dependency policy"
    );
}

#[test]
fn binary_tokio_manifests_match_the_exact_test_only_boundary_and_reject_mutations() {
    let root = workspace_root();
    let root_manifest = fs::read_to_string(root.join("Cargo.toml")).expect("root manifest");
    let client_manifest =
        fs::read_to_string(root.join("bins/ferrum2-client/Cargo.toml")).expect("client manifest");
    let server_manifest =
        fs::read_to_string(root.join("bins/ferrum2-server/Cargo.toml")).expect("server manifest");
    let root_lf = normalize_line_endings(&root_manifest).expect("root line endings");
    let client_lf = normalize_line_endings(&client_manifest).expect("client line endings");
    let server_lf = normalize_line_endings(&server_manifest).expect("server line endings");

    for crlf in [false, true] {
        let convert = |source: &str| {
            if crlf {
                source.replace('\n', "\r\n")
            } else {
                source.to_owned()
            }
        };
        exact_binary_tokio_boundary(
            &convert(&root_lf),
            &convert(&client_lf),
            &convert(&server_lf),
        )
        .expect("approved LF/CRLF Tokio boundary");
    }

    let mut mutations = Vec::new();
    mutations.push((
        root_lf.clone(),
        client_lf.replace(&format!("{BINARY_TOKIO_DEV_DECLARATION}\n"), ""),
        server_lf.clone(),
    ));
    mutations.push((
        root_lf.clone(),
        client_lf.clone(),
        server_lf.replace(&format!("{BINARY_TOKIO_DEV_DECLARATION}\n"), ""),
    ));
    mutations.push((
        root_lf.clone(),
        client_lf.replace("[\"test-util\"]", "[\"test-util\", \"rt\"]"),
        server_lf.clone(),
    ));
    mutations.push((
        root_lf.clone(),
        client_lf.replace("features = [\"test-util\"]", "features = []"),
        server_lf.clone(),
    ));
    mutations.push((
        root_lf.clone(),
        client_lf.replace(&format!("{BINARY_TOKIO_NORMAL_DECLARATION}\n"), ""),
        server_lf.clone(),
    ));
    mutations.push((
        root_lf.replace(
            "features = [\"rt-multi-thread\", \"macros\", \"net\", \"io-util\", \"sync\", \"time\", \"signal\"]",
            "features = [\"rt-multi-thread\", \"macros\", \"net\", \"io-util\", \"sync\", \"time\", \"signal\", \"test-util\"]",
        ),
        client_lf.replace(&format!("{BINARY_TOKIO_DEV_DECLARATION}\n"), ""),
        server_lf.replace(&format!("{BINARY_TOKIO_DEV_DECLARATION}\n"), ""),
    ));
    for replacement in [
        "tokio = { workspace = true, features = [\"full\"] }",
        "tokio = { version = \"=1.53.1\", features = [\"test-util\"] }",
        "tokio = { workspace = true, default-features = true, features = [\"test-util\"] }",
        "tokio = { workspace = true, source = \"registry\", features = [\"test-util\"] }",
        "tokio = { workspace = true, path = \"../../tokio\", features = [\"test-util\"] }",
        "tokio = { workspace = true, git = \"https://example.invalid/tokio\", features = [\"test-util\"] }",
        "runtime = { workspace = true, package = \"tokio\", features = [\"test-util\"] }",
        "tokio = { workspace = true, optional = true, features = [\"test-util\"] }",
    ] {
        mutations.push((
            root_lf.clone(),
            client_lf.replace(BINARY_TOKIO_DEV_DECLARATION, replacement),
            server_lf.clone(),
        ));
    }
    mutations.push((
        root_lf.clone(),
        client_lf.replace(
            "[dev-dependencies]",
            "[target.'cfg(windows)'.dev-dependencies]",
        ),
        server_lf.clone(),
    ));
    mutations.push((
        root_lf.clone(),
        format!("{client_lf}\n[dev-dependencies]\n{BINARY_TOKIO_DEV_DECLARATION}\n"),
        server_lf.clone(),
    ));
    mutations.push((
        root_lf.clone(),
        client_lf.replace(
            BINARY_TOKIO_DEV_DECLARATION,
            &format!("{BINARY_TOKIO_DEV_DECLARATION}\n{BINARY_TOKIO_DEV_DECLARATION}"),
        ),
        server_lf.clone(),
    ));

    for (root_mutation, client_mutation, server_mutation) in mutations {
        for crlf in [false, true] {
            let convert = |source: &str| {
                if crlf {
                    source.replace('\n', "\r\n")
                } else {
                    source.to_owned()
                }
            };
            assert!(
                exact_binary_tokio_boundary(
                    &convert(&root_mutation),
                    &convert(&client_mutation),
                    &convert(&server_mutation),
                )
                .is_err(),
                "Tokio boundary mutation must fail for LF and CRLF"
            );
        }
    }
    assert!(
        exact_binary_tokio_boundary(&root_lf, &client_lf.replace('\n', "\r"), &server_lf).is_err(),
        "bare carriage returns must be rejected"
    );
}

#[test]
fn binary_tokio_metadata_trees_and_lock_edges_prove_dev_only_test_util() {
    let metadata = metadata();
    let tokio_id = unique_registry_package_id(&metadata, "tokio", "1.53.1");
    let normal_features = serde_json::json!([
        "rt-multi-thread",
        "macros",
        "net",
        "io-util",
        "sync",
        "time",
        "signal"
    ]);
    let dev_features = serde_json::json!([
        "rt-multi-thread",
        "macros",
        "net",
        "io-util",
        "sync",
        "time",
        "signal",
        "test-util"
    ]);
    let lock = fs::read_to_string(workspace_root().join("Cargo.lock")).expect("Cargo.lock");

    for (package_name, expected_lock_dependencies) in [
        (
            "ferrum2-client",
            BTreeSet::from([
                "clap".to_owned(),
                "ferrum2-config".to_owned(),
                "ferrum2-core".to_owned(),
                "ferrum2-crypto".to_owned(),
                "ferrum2-dns".to_owned(),
                "ferrum2-observability".to_owned(),
                "ferrum2-runtime".to_owned(),
                "ferrum2-shadowsocks".to_owned(),
                "ferrum2-sniff".to_owned(),
                "ferrum2-socks5".to_owned(),
                "hickory-proto".to_owned(),
                "tokio".to_owned(),
                "tracing".to_owned(),
            ]),
        ),
        (
            "ferrum2-server",
            BTreeSet::from([
                "clap".to_owned(),
                "ferrum2-config".to_owned(),
                "ferrum2-core".to_owned(),
                "ferrum2-crypto".to_owned(),
                "ferrum2-dns".to_owned(),
                "ferrum2-observability".to_owned(),
                "ferrum2-runtime".to_owned(),
                "ferrum2-shadowsocks".to_owned(),
                "ferrum2-sniff".to_owned(),
                "hickory-proto".to_owned(),
                "tokio".to_owned(),
                "tracing".to_owned(),
            ]),
        ),
    ] {
        let package = metadata["packages"]
            .as_array()
            .expect("packages")
            .iter()
            .find(|package| package["name"] == package_name)
            .expect("binary package");
        let hickory = package["dependencies"]
            .as_array()
            .expect("binary dependencies")
            .iter()
            .find(|dependency| dependency["name"] == "hickory-proto");
        let hickory = hickory.expect("binary typed DNS test edge");
        assert_eq!(hickory["req"], "=0.26.1");
        assert_eq!(hickory["kind"], "dev");
        assert_eq!(hickory["uses_default_features"], false);
        assert_eq!(hickory["features"], serde_json::json!(["std"]));
        let sniff = package["dependencies"]
            .as_array()
            .expect("binary dependencies")
            .iter()
            .find(|dependency| dependency["name"] == "ferrum2-sniff");
        assert_eq!(
            sniff.is_some(),
            matches!(package_name, "ferrum2-client" | "ferrum2-server"),
            "M14 composition binaries must own the normal sniff edge"
        );
        let tokio_dependencies: Vec<_> = package["dependencies"]
            .as_array()
            .expect("binary dependencies")
            .iter()
            .filter(|dependency| dependency["name"] == "tokio")
            .collect();
        assert_eq!(
            tokio_dependencies.len(),
            2,
            "{package_name} must have one normal and one dev Tokio edge"
        );
        for (dependency, kind, features) in [
            (tokio_dependencies[0], Value::Null, &normal_features),
            (
                tokio_dependencies[1],
                Value::String("dev".to_owned()),
                &dev_features,
            ),
        ] {
            assert_eq!(
                dependency["source"],
                "registry+https://github.com/rust-lang/crates.io-index"
            );
            assert_eq!(dependency["req"], "=1.53.1");
            assert_eq!(dependency["kind"], kind);
            assert!(dependency["rename"].is_null());
            assert_eq!(dependency["optional"], false);
            assert_eq!(dependency["uses_default_features"], false);
            assert_eq!(&dependency["features"], features);
            assert!(dependency["target"].is_null());
        }

        let node = resolve_node(
            &metadata,
            package["id"].as_str().expect("binary package ID"),
        );
        let resolved_tokio: Vec<_> = node["deps"]
            .as_array()
            .expect("resolved binary dependencies")
            .iter()
            .filter(|dependency| dependency["name"] == "tokio")
            .collect();
        assert_eq!(resolved_tokio.len(), 1);
        assert_eq!(resolved_tokio[0]["pkg"], tokio_id);
        assert_eq!(
            resolved_tokio[0]["dep_kinds"],
            serde_json::json!([
                {"kind": null, "target": null},
                {"kind": "dev", "target": null}
            ])
        );

        let production_tree = cargo_tree_for_tokio(package_name, "normal,build,features");
        assert!(
            !production_tree.contains("tokio feature \"test-util\""),
            "{package_name} production tree must exclude test-util"
        );
        let test_tree = cargo_tree_for_tokio(package_name, "all,features");
        assert!(
            test_tree.contains("tokio feature \"test-util\"")
                && test_tree.contains("[dev-dependencies]"),
            "{package_name} test tree must include the binary-local test-util edge"
        );
        assert_eq!(
            lock_package_dependencies(&lock, package_name).expect("binary lock dependencies"),
            expected_lock_dependencies,
            "dev feature unification must not add a binary lock dependency"
        );
    }
}

#[test]
fn dns_external_provider_pins_and_hosted_completion_are_exact() {
    let root = workspace_root();
    let versions =
        fs::read_to_string(root.join("tests/interop/versions.toml")).expect("interop version pins");
    for required in [
        "[coredns]",
        "version = \"1.14.6\"",
        "source_commit = \"424d125775cd70fa90dfc80bf0e52cc9a9aeb574\"",
        "linux_size = 22574279",
        "linux_sha256 = \"4402578c8f7b95dac1d8258bfd13e7a9d30f70d7a53f396b02a6d6ca78d56152\"",
        "license_review = \"Apache-2.0; execute only as an independent test process; do not redistribute\"",
        "[bind]",
        "version = \"9.20.26\"",
        "source_commit = \"7e228e3ba7c2ca945b1c2a22ed2ef0aa9d7cab10\"",
        "linux_size = 5918032",
        "linux_sha256 = \"55248def0f870c4c46b3de72978ea972615131516663188a4564dca1d20bf350\"",
        "license_review = \"MPL-2.0; execute only as an independent test process; do not redistribute\"",
    ] {
        assert!(
            versions.contains(required),
            "missing provider pin: {required}"
        );
    }

    let workflow =
        fs::read_to_string(root.join(".github/workflows/m0.yml")).expect("hosted workflow");
    for required in [
        "M12_COREDNS_SETUP_STATUS",
        "M12_BIND_SETUP_STATUS",
        "m0-qualification\" --dns-only",
        "qualification transport=dns status=PASS cleanup=PASS",
        "m12_interop_completion status=PASS",
    ] {
        assert!(
            workflow.contains(required),
            "missing DNS hosted gate: {required}"
        );
    }
}

#[test]
fn harness_dependencies_and_lock_edges_match_the_hosted_qualification_seam() {
    let root = workspace_root();
    let manifest =
        fs::read_to_string(root.join("tests/m0-harness/Cargo.toml")).expect("harness manifest");
    let manifest_lf = normalize_line_endings(&manifest).expect("harness line endings");
    let expected_dev = BTreeMap::from([
        ("aes-gcm.workspace".to_owned(), "true".to_owned()),
        ("blake3.workspace".to_owned(), "true".to_owned()),
        ("hex.workspace".to_owned(), "true".to_owned()),
        ("hickory-proto.workspace".to_owned(), "true".to_owned()),
        ("serde_json.workspace".to_owned(), "true".to_owned()),
        ("socket2.workspace".to_owned(), "true".to_owned()),
    ]);
    let expected_normal = BTreeMap::from([("tempfile.workspace".to_owned(), "true".to_owned())]);
    assert_eq!(
        dependency_table(&manifest, "[dev-dependencies]").expect("harness dev dependencies"),
        expected_dev
    );
    assert_eq!(
        dependency_table(&manifest, "[dependencies]").expect("harness normal dependencies"),
        expected_normal
    );

    for fixture in [manifest_lf.clone(), manifest_lf.replace('\n', "\r\n")] {
        assert_eq!(
            dependency_table(&fixture, "[dev-dependencies]").expect("line-ending fixture"),
            expected_dev
        );
        assert_eq!(
            dependency_table(&fixture, "[dependencies]").expect("line-ending fixture"),
            expected_normal
        );
    }
    for mutation in [
        manifest_lf.replace("aes-gcm.workspace = true\n", ""),
        manifest_lf.replace("aes-gcm.workspace = true", "aes-gcm = { workspace = true }"),
        manifest_lf.replace(
            "blake3.workspace = true",
            "blake3 = { workspace = true, features = [\"rayon\"] }",
        ),
        manifest_lf.replace("socket2.workspace = true\n", ""),
        manifest_lf.replace(
            "socket2.workspace = true",
            "socket2 = { workspace = true, features = [\"all\"] }",
        ),
        manifest_lf.replace(
            "tempfile.workspace = true",
            "tempfile.workspace = true\nferrum2-core.workspace = true",
        ),
        manifest_lf.replace("[dependencies]", "[qualification-dependencies]"),
    ] {
        assert!(
            dependency_table(&mutation, "[dev-dependencies]").ok() != Some(expected_dev.clone())
                || dependency_table(&mutation, "[dependencies]").ok()
                    != Some(expected_normal.clone()),
            "manifest mutation must not preserve the approved dependency contract"
        );
    }
    assert!(
        dependency_table(&manifest_lf.replace('\n', "\r"), "[dev-dependencies]").is_err(),
        "bare carriage returns must be rejected"
    );

    let metadata = metadata();
    let harness = metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|package| package["name"] == "ferrum2-m0-harness")
        .expect("harness package");
    let actual_metadata: BTreeSet<_> = harness["dependencies"]
        .as_array()
        .expect("harness dependencies")
        .iter()
        .map(|dependency| {
            let name = dependency["name"].as_str().expect("dependency name");
            if name == "tempfile" {
                assert!(
                    dependency["kind"].is_null(),
                    "qualification runtime dependency must be normal"
                );
            } else {
                assert_eq!(
                    dependency["kind"], "dev",
                    "all other harness edges must remain test-only"
                );
            }
            match name {
                "aes-gcm" => {
                    assert_eq!(dependency["uses_default_features"], false);
                    assert_eq!(
                        dependency["features"],
                        serde_json::json!(["aes", "bytes", "zeroize"])
                    );
                }
                "blake3" => {
                    assert_eq!(dependency["uses_default_features"], false);
                    assert_eq!(
                        dependency["features"],
                        serde_json::json!(["std", "zeroize"])
                    );
                }
                "hex" | "serde_json" | "socket2" | "tempfile" => {
                    assert_eq!(dependency["uses_default_features"], true);
                    assert_eq!(dependency["features"], serde_json::json!([]));
                }
                "hickory-proto" => {
                    assert_eq!(dependency["uses_default_features"], false);
                    assert_eq!(dependency["features"], serde_json::json!(["std"]));
                }
                other => panic!("unexpected harness dependency: {other}"),
            }
            name.to_owned()
        })
        .collect();
    assert_eq!(
        actual_metadata,
        BTreeSet::from([
            "aes-gcm".to_owned(),
            "blake3".to_owned(),
            "hex".to_owned(),
            "hickory-proto".to_owned(),
            "serde_json".to_owned(),
            "socket2".to_owned(),
            "tempfile".to_owned(),
        ])
    );
    assert!(
        actual_metadata
            .iter()
            .all(|dependency| !dependency.starts_with("ferrum2-"))
    );

    let lock = fs::read_to_string(root.join("Cargo.lock")).expect("Cargo.lock");
    let lock_lf = normalize_line_endings(&lock).expect("Cargo.lock line endings");
    let expected_lock = BTreeSet::from([
        "aes-gcm".to_owned(),
        "blake3".to_owned(),
        "hex".to_owned(),
        "hickory-proto".to_owned(),
        "serde_json".to_owned(),
        "socket2".to_owned(),
        "tempfile".to_owned(),
    ]);
    assert_eq!(
        lock_package_dependencies(&lock, "ferrum2-m0-harness").expect("harness lock dependencies"),
        expected_lock
    );
    assert_eq!(
        lock_package_dependencies(&lock_lf.replace('\n', "\r\n"), "ferrum2-m0-harness")
            .expect("CRLF harness lock dependencies"),
        expected_lock
    );
    for mutation in [
        lock_lf.replace(" \"aes-gcm\",\n", ""),
        lock_lf.replace(" \"blake3\",\n", ""),
        lock_lf.replace(" \"socket2\",\n", ""),
        lock_lf.replace(" \"tempfile\",\n", " \"ferrum2-core\",\n \"tempfile\",\n"),
    ] {
        assert_ne!(
            lock_package_dependencies(&mutation, "ferrum2-m0-harness").ok(),
            Some(expected_lock.clone()),
            "lock edge mutation must not preserve the approved contract"
        );
    }
    assert!(lock_package_dependencies(&lock_lf.replace('\n', "\r"), "ferrum2-m0-harness").is_err());
}

#[test]
fn qualification_is_a_cargo_managed_non_test_binary() {
    let metadata = metadata();
    let harness = metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|package| package["name"] == "ferrum2-m0-harness")
        .expect("harness package");
    let targets = harness["targets"].as_array().expect("harness targets");
    let qualification: Vec<_> = targets
        .iter()
        .filter(|target| target["name"] == "m0-qualification")
        .collect();
    assert_eq!(
        qualification.len(),
        1,
        "exactly one Cargo qualification target is required"
    );
    let qualification = qualification[0];
    assert_eq!(qualification["kind"], serde_json::json!(["bin"]));
    assert_eq!(qualification["crate_types"], serde_json::json!(["bin"]));
    assert_eq!(qualification["test"], false);
    assert_eq!(qualification["doctest"], false);
    assert!(
        qualification["src_path"]
            .as_str()
            .expect("qualification source path")
            .replace('\\', "/")
            .ends_with("/tests/m0-harness/src/bin/m0_qualification.rs")
    );
    assert!(
        targets
            .iter()
            .all(|target| target["name"] != "external_interop"),
        "external interoperability must not remain in libtest discovery"
    );

    let root = workspace_root();
    assert!(
        !root
            .join("tests/m0-harness/tests/external_interop.rs")
            .exists(),
        "the old ignored libtest entry must be removed"
    );
    let external = fs::read_to_string(root.join("tests/m0-harness/src/external_support/mod.rs"))
        .expect("hosted external support");
    assert!(
        !external.contains("#[cfg(test)]"),
        "OS/process/socket helper tests must not remain embedded in hosted support"
    );
    let pure_contract = [
        fs::read_to_string(root.join("tests/m0-harness/src/qualification/mod.rs"))
            .expect("qualification state module"),
        fs::read_to_string(root.join("tests/m0-harness/tests/qualification_contract.rs"))
            .expect("qualification contract tests"),
    ]
    .join("\n");
    for forbidden in [
        "std::net",
        "std::process",
        "TcpListener",
        "TcpStream",
        "Command::new",
        "RUNNER_TEMP",
        "versions.toml",
        "curl",
        "reqwest",
    ] {
        assert!(
            !pure_contract.contains(forbidden),
            "local qualification state tests must remain I/O-free: {forbidden}"
        );
    }

    let m4 = metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|package| package["name"] == "ferrum2-m4-qualification")
        .expect("M4 qualification package");
    assert_eq!(
        m4["dependencies"],
        serde_json::json!([
            {
                "name": "hickory-proto",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "req": "=0.26.1",
                "kind": null,
                "rename": null,
                "optional": false,
                "uses_default_features": false,
                "features": ["std"],
                "target": null,
                "registry": null
            },
            {
                "name": "socket2",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "req": "=0.6.5",
                "kind": null,
                "rename": null,
                "optional": false,
                "uses_default_features": true,
                "features": [],
                "target": null,
                "registry": null
            },
            {
                "name": "tempfile",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "req": "=3.27.0",
                "kind": null,
                "rename": null,
                "optional": false,
                "uses_default_features": true,
                "features": [],
                "target": null,
                "registry": null
            }
        ])
    );
    let targets = m4["targets"].as_array().expect("M4 targets");
    assert_eq!(targets.len(), 1);
    let target = &targets[0];
    assert_eq!(target["name"], "m4-qualification");
    assert_eq!(target["kind"], serde_json::json!(["bin"]));
    assert_eq!(target["crate_types"], serde_json::json!(["bin"]));
    assert_eq!(target["test"], false);
    assert_eq!(target["doctest"], false);
    assert!(
        target["src_path"]
            .as_str()
            .expect("M4 source path")
            .replace('\\', "/")
            .ends_with("/tools/ferrum2-m4-qualification/src/main.rs")
    );
    let manifest = fs::read_to_string(root.join("tools/ferrum2-m4-qualification/Cargo.toml"))
        .expect("M4 qualification manifest");
    assert_eq!(
        dependency_table(&manifest, "[dependencies]").expect("M4 dependencies"),
        BTreeMap::from([
            ("hickory-proto.workspace".to_owned(), "true".to_owned()),
            ("socket2.workspace".to_owned(), "true".to_owned()),
            ("tempfile.workspace".to_owned(), "true".to_owned()),
        ])
    );
    let lock = fs::read_to_string(root.join("Cargo.lock")).expect("Cargo.lock");
    assert_eq!(
        lock_package_dependencies(&lock, "ferrum2-m4-qualification").expect("M4 lock dependencies"),
        BTreeSet::from([
            "hickory-proto".to_owned(),
            "socket2".to_owned(),
            "tempfile".to_owned(),
        ])
    );
}

#[test]
fn metadata_and_lock_prove_one_normal_backend_and_dev_only_oracles() {
    let metadata = metadata();
    let packages = metadata["packages"].as_array().expect("packages");
    let crypto = packages
        .iter()
        .find(|package| package["name"] == "ferrum2-crypto")
        .expect("crypto package");
    let crypto_dependencies = crypto["dependencies"]
        .as_array()
        .expect("crypto dependencies");
    assert_eq!(crypto["features"], serde_json::json!({}));
    let declared: BTreeSet<_> = crypto_dependencies
        .iter()
        .map(|dependency| {
            (
                dependency["name"].as_str().expect("dependency name"),
                dependency["kind"].as_str().unwrap_or("normal"),
            )
        })
        .collect();
    assert_eq!(
        declared,
        BTreeSet::from([
            ("aes", "dev"),
            ("aes-gcm", "dev"),
            ("blake3", "dev"),
            ("bytes", "normal"),
            ("chacha20poly1305", "dev"),
            ("getrandom", "normal"),
            ("hex", "dev"),
            ("serde_json", "dev"),
            ("shadowsocks-crypto", "normal"),
            ("zeroize", "normal"),
        ])
    );

    let normal_crypto_backends: Vec<_> = crypto_dependencies
        .iter()
        .filter(|dependency| {
            dependency["kind"].is_null()
                && matches!(
                    dependency["name"].as_str(),
                    Some(
                        "aes"
                            | "aes-gcm"
                            | "blake3"
                            | "chacha20poly1305"
                            | "ghash"
                            | "shadowsocks-crypto"
                    )
                )
        })
        .collect();
    assert_eq!(normal_crypto_backends.len(), 1);
    assert_eq!(normal_crypto_backends[0]["name"], "shadowsocks-crypto");

    let lock = fs::read_to_string(workspace_root().join("Cargo.lock")).expect("Cargo.lock");
    assert_eq!(
        lock_package_dependencies(&lock, "ferrum2-crypto").expect("crypto lock dependencies"),
        BTreeSet::from([
            "aes".to_owned(),
            "aes-gcm".to_owned(),
            "blake3".to_owned(),
            "bytes".to_owned(),
            "chacha20poly1305".to_owned(),
            "getrandom 0.4.3".to_owned(),
            "hex".to_owned(),
            "serde_json".to_owned(),
            "shadowsocks-crypto".to_owned(),
            "zeroize".to_owned(),
        ])
    );
}

#[test]
fn resolved_crypto_feature_sets_are_exact() {
    let metadata = metadata();
    for (name, version, expected_features) in [
        ("aes-gcm", "0.11.0", &["aes", "bytes", "zeroize"][..]),
        ("chacha20poly1305", "0.11.0", &["bytes", "zeroize"][..]),
        (
            "chacha20",
            "0.10.1",
            &["cipher", "rng", "xchacha", "zeroize"][..],
        ),
        ("poly1305", "0.9.1", &[][..]),
        ("aes", "0.9.1", &["zeroize"][..]),
        ("ghash", "0.6.0", &["zeroize"][..]),
        ("polyval", "0.7.3", &["hazmat", "zeroize"][..]),
        (
            "zeroize",
            "1.9.0",
            &["aarch64", "alloc", "default", "derive", "zeroize_derive"][..],
        ),
    ] {
        let package_id = unique_registry_package_id(&metadata, name, version);
        let node = resolve_node(&metadata, &package_id);
        let actual: BTreeSet<_> = node["features"]
            .as_array()
            .expect("resolved features")
            .iter()
            .map(|feature| feature.as_str().expect("feature string"))
            .collect();
        let expected: BTreeSet<_> = expected_features.iter().copied().collect();
        assert_eq!(
            actual, expected,
            "{name} {version} resolved features must exactly match the approved crypto policy"
        );
    }
}

#[test]
fn lock_package_identities_exactly_match_the_approved_workspace_baseline() {
    let lock = fs::read_to_string(workspace_root().join("Cargo.lock")).expect("Cargo.lock");
    let actual = lock_identities(&lock).expect("candidate lock identities");
    let expected = approved_lock_identities();

    assert_eq!(
        actual.len(),
        224,
        "candidate lock must contain 224 packages"
    );
    assert_eq!(
        actual, expected,
        "package name/version/source/checksum identities must not change"
    );
}

#[test]
fn lock_identity_helper_accepts_line_endings_and_rejects_mutations() {
    let fixture_lf = "# generated\nversion = 4\n\n[[package]]\nname = \"demo\"\nversion = \"1.2.3\"\nsource = \"registry+https://example.invalid/index\"\nchecksum = \"abc123\"\n\n[[package]]\nname = \"workspace-member\"\nversion = \"0.1.0\"\n";
    let expected = vec![
        LockIdentity {
            name: "demo".to_owned(),
            version: "1.2.3".to_owned(),
            source: Some("registry+https://example.invalid/index".to_owned()),
            checksum: Some("abc123".to_owned()),
        },
        LockIdentity {
            name: "workspace-member".to_owned(),
            version: "0.1.0".to_owned(),
            source: None,
            checksum: None,
        },
    ];

    assert_eq!(
        lock_identities(fixture_lf).expect("LF lock fixture"),
        expected
    );
    assert_eq!(
        lock_identities(&fixture_lf.replace('\n', "\r\n")).expect("CRLF lock fixture"),
        expected
    );

    for mutation in [
        fixture_lf.replace("1.2.3", "1.2.4"),
        fixture_lf.replace(
            "registry+https://example.invalid/index",
            "git+https://example.invalid",
        ),
        fixture_lf.replace("abc123", "def456"),
        fixture_lf.replace(
            "\n[[package]]\nname = \"workspace-member\"\nversion = \"0.1.0\"\n",
            "",
        ),
        format!("{fixture_lf}\n[[package]]\nname = \"added\"\nversion = \"9.9.9\"\n"),
    ] {
        for fixture in [mutation.clone(), mutation.replace('\n', "\r\n")] {
            assert_ne!(
                lock_identities(&fixture).expect("lock mutation"),
                expected,
                "a lock identity mutation must change the parsed contract"
            );
        }
    }

    assert!(lock_identities("[[package]]\nname = \"missing-version\"\n").is_err());
}

#[test]
fn every_project_package_inherits_repository_policy() {
    let metadata = metadata();
    let root = workspace_root();

    for member_id in metadata["workspace_members"]
        .as_array()
        .expect("workspace members")
    {
        let package = metadata["packages"]
            .as_array()
            .expect("packages")
            .iter()
            .find(|package| package["id"] == *member_id)
            .expect("member package");
        assert_eq!(package["version"], "0.1.0");
        assert_eq!(package["edition"], "2024");
        assert_eq!(package["rust_version"], "1.88.0");
        assert_eq!(package["license"], "GPL-3.0-only");
        assert_eq!(
            package["publish"],
            serde_json::json!([]),
            "publish=false is represented by an empty registry allowlist"
        );

        let manifest_path =
            PathBuf::from(package["manifest_path"].as_str().expect("manifest path"));
        let manifest = fs::read_to_string(&manifest_path).expect("member manifest");
        assert!(
            contains_manifest_policy(&manifest, "[lints]\nworkspace = true"),
            "{} must inherit workspace lints",
            manifest_path
                .strip_prefix(&root)
                .unwrap_or(&manifest_path)
                .display()
        );
    }

    let root_manifest = fs::read_to_string(root.join("Cargo.toml")).expect("root manifest");
    assert!(contains_manifest_policy(
        &root_manifest,
        "[workspace.lints.rust]\nunsafe_code = \"forbid\""
    ));
}

#[test]
fn lint_policy_matching_accepts_crlf() {
    let member_manifest = "[lints]\r\nworkspace = true\r\n";
    let root_manifest = "[workspace.lints.rust]\r\nunsafe_code = \"forbid\"\r\n";

    assert!(contains_manifest_policy(
        member_manifest,
        "[lints]\nworkspace = true"
    ));
    assert!(contains_manifest_policy(
        root_manifest,
        "[workspace.lints.rust]\nunsafe_code = \"forbid\""
    ));
}

#[test]
fn config_predeclares_zeroizing_storage_dependency() {
    let metadata = metadata();
    let config = metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|package| package["name"] == "ferrum2-config")
        .expect("config package");
    let zeroize = config["dependencies"]
        .as_array()
        .expect("config dependencies")
        .iter()
        .find(|dependency| dependency["name"] == "zeroize")
        .expect("config must predeclare zeroize for raw config and PSK strings");

    assert_eq!(zeroize["req"], "=1.9.0");
    assert_eq!(zeroize["uses_default_features"], false);
    assert_eq!(zeroize["features"], serde_json::json!(["alloc", "derive"]));
}

#[test]
fn lockfile_and_gplv3_license_are_committed_policy_inputs() {
    let root = workspace_root();
    let lock = root.join("Cargo.lock");
    assert!(lock.is_file(), "Cargo.lock must exist");

    let output = Command::new("git")
        .args(["ls-files", "--error-unmatch", "Cargo.lock"])
        .current_dir(&root)
        .output()
        .expect("git ls-files must start");
    assert!(
        output.status.success(),
        "Cargo.lock must be tracked: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let license = fs::read_to_string(root.join("LICENSE")).expect("LICENSE");
    assert!(license.contains("GNU GENERAL PUBLIC LICENSE"));
    assert!(license.contains("Version 3, 29 June 2007"));
}

#[test]
fn harness_has_no_concrete_ferrum2_cargo_dependency() {
    let manifest = fs::read_to_string(workspace_root().join("tests/m0-harness/Cargo.toml"))
        .expect("harness manifest");
    let dependency_section = manifest
        .split("[dev-dependencies]")
        .nth(1)
        .expect("dev dependencies");
    assert!(
        !dependency_section.contains("ferrum2-"),
        "the black-box harness must not link a concrete ferrum2 package"
    );
}

#[test]
fn performance_is_manual_and_decoupled_from_qualification() {
    let workflow =
        fs::read_to_string(workspace_root().join(".github/workflows/m0.yml")).expect("workflow");
    let workflow = normalize_line_endings(&workflow).expect("workflow line endings");
    assert!(workflow.contains(
        "  performance:\n    name: performance\n    if: ${{ github.event_name == 'workflow_dispatch' }}\n"
    ));
    assert!(workflow.contains("test \"$GITHUB_EVENT_NAME\" = \"workflow_dispatch\""));
    assert!(workflow.contains(
        "    needs:\n      - quality\n      - budget\n      - msrv\n      - platform\n      - interop\n"
    ));
    for forbidden in [
        "      - performance\n",
        "PERFORMANCE_RESULT",
        "m4_qualification_completion",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "workflow must not contain {forbidden}"
        );
    }
}

#[test]
fn m4_thp_profile_is_applied_and_restored_around_resource_qualification() {
    let workflow =
        fs::read_to_string(workspace_root().join(".github/workflows/m0.yml")).expect("M4 workflow");
    let workflow = normalize_line_endings(&workflow).expect("M4 workflow line endings");
    let main_start = workflow
        .find("      - name: Run M4 throughput and resource qualification\n")
        .expect("M4 performance main step");
    let cleanup_start = workflow[main_start..]
        .find("      - name: Reap M4 processes and delete generated evidence\n")
        .map(|offset| main_start + offset)
        .expect("M4 performance cleanup step");
    let cleanup_end = workflow[cleanup_start..]
        .find("\n  qualification:\n")
        .map(|offset| cleanup_start + offset)
        .expect("M4 qualification job");
    let main = &workflow[main_start..cleanup_start];
    let cleanup = &workflow[cleanup_start..cleanup_end];

    let mut offset = 0;
    for marker in [
        "grep -Eq '^-?[0-9]+\\.[0-9]{9}$' <<<\"$signed_difference\"",
        "thp_knob=/sys/kernel/mm/transparent_hugepage/khugepaged/max_ptes_none",
        "thp_original_file=\"$work/thp-max-ptes-none.original\"",
        "restore_thp() {",
        "finish_thp() {",
        "thp_original=\"$(cat \"$thp_knob\")\"",
        "grep -Eq '^(0|[1-9][0-9]*)$' <<<\"$thp_original\"",
        "printf '%s\\n' \"$thp_original\" >\"$thp_original_file\"",
        "trap 'finish_thp \"$?\"' EXIT",
        "trap 'finish_thp 143' TERM",
        "printf '0\\n' | sudo -n tee \"$thp_knob\" >/dev/null",
        "test \"$(cat \"$thp_knob\")\" = 0",
        "printf '%s\\n' 'm4_thp_profile status=APPLIED max_ptes_none=0'",
        "resource_output=\"$(target/release/m4-qualification resource \\",
        "test \"$resource_output\" = \"$expected_resource\"",
        "dns_resource_output=\"$(target/release/m4-qualification dns-resource \\",
        "test \"$(grep -c '^' <<<\"$dns_resource_output\")\" -eq 1",
        "grep -Eq \"^m12_dns_resource_completion status=PASS ",
        "restore_thp",
        "trap - EXIT TERM",
        "printf '%s\\n' 'm4_thp_profile status=RESTORED readback=PASS'",
        "printf 'm4_performance_completion status=PASS ",
        "printf 'm12_performance_completion status=PASS ",
    ] {
        let relative = main[offset..]
            .find(marker)
            .unwrap_or_else(|| panic!("M4 main step missing ordered marker: {marker}"));
        offset += relative + marker.len();
    }
    let restore_start = main.find("restore_thp() {").expect("M4 restore function");
    let finish_start = main.find("finish_thp() {").expect("M4 finish function");
    let original_start = main
        .find("thp_original=\"$(cat \"$thp_knob\")\"")
        .expect("M4 original profile read");
    let restore = &main[restore_start..finish_start];
    assert_eq!(
        restore.lines().nth(1).map(str::trim),
        Some("trap - EXIT TERM"),
        "M4 restoration must disarm EXIT and TERM before any fallible action"
    );
    let mut offset = 0;
    for marker in [
        "printf '%s\\n' \"$thp_original\" | sudo -n tee \"$thp_knob\" >/dev/null",
        "test \"$(cat \"$thp_knob\")\" = \"$thp_original\"",
    ] {
        let relative = restore[offset..]
            .find(marker)
            .unwrap_or_else(|| panic!("M4 restore function missing ordered marker: {marker}"));
        offset += relative + marker.len();
    }
    let finish = &main[finish_start..original_start];
    let mut offset = 0;
    for marker in [
        "primary=\"$1\"",
        "restore_status=0",
        "restore_thp || restore_status=$?",
        "if [ \"$primary\" -ne 0 ]; then",
        "exit \"$primary\"",
        "fi",
        "exit \"$restore_status\"",
    ] {
        let relative = finish[offset..]
            .find(marker)
            .unwrap_or_else(|| panic!("M4 finish function missing ordered marker: {marker}"));
        offset += relative + marker.len();
    }

    let mut offset = 0;
    for marker in [
        "if: ${{ always() }}",
        "set -u",
        "pkill \"-$signal\" -x \"$process\" 2>/dev/null || signal_status=$?",
        "thp_knob=/sys/kernel/mm/transparent_hugepage/khugepaged/max_ptes_none",
        "thp_original_file=\"$RUNNER_TEMP/m4/thp-max-ptes-none.original\"",
        "thp_original=\"$(cat \"$thp_original_file\")\"",
        "grep -Eq '^(0|[1-9][0-9]*)$' <<<\"$thp_original\"",
        "printf '%s\\n' \"$thp_original\" | sudo -n tee \"$thp_knob\" >/dev/null || cleanup_status=1",
        "test \"$(cat \"$thp_knob\")\" = \"$thp_original\" || cleanup_status=1",
        "rm -rf -- \"$RUNNER_TEMP/m4\" || cleanup_status=1",
        "test \"$cleanup_status\" -eq 0",
    ] {
        let relative = cleanup[offset..]
            .find(marker)
            .unwrap_or_else(|| panic!("M4 cleanup step missing ordered marker: {marker}"));
        offset += relative + marker.len();
    }
    for line in main
        .lines()
        .filter(|line| line.contains("m4_thp_profile status="))
    {
        assert!(
            !line.contains("$thp_original") && !line.contains("original="),
            "M4 THP status evidence must not emit the observed original value"
        );
    }
}
