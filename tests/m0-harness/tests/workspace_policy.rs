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
base64|0.23.0|registry+https://github.com/rust-lang/crates.io-index|b25655df2c3cdd83c5e5b293b88acd880332b2ddadd7c30ac43144fdc0033da9
bitflags|2.13.1|registry+https://github.com/rust-lang/crates.io-index|b588b76d00fde79687d7646a9b5bdf3cc0f655e0bbd080335a95d7e96f3587da
blake3|1.8.5|registry+https://github.com/rust-lang/crates.io-index|0aa83c34e62843d924f905e0f5c866eb1dd6545fc4d719e803d9ba6030371fce
block-buffer|0.12.1|registry+https://github.com/rust-lang/crates.io-index|d2f6c7dbe95a6ed67ad9f18e57daf93a2f034c524b99fd2b76d18fdfeb6660aa
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
constant_time_eq|0.4.2|registry+https://github.com/rust-lang/crates.io-index|3d52eff69cd5e647efe296129160853a42795992097e8af39800e1060caeea9b
cpubits|0.1.1|registry+https://github.com/rust-lang/crates.io-index|15b85f9c39137c3a891689859392b1bd49812121d0d61c9caf00d46ed5ce06ae
cpufeatures|0.3.0|registry+https://github.com/rust-lang/crates.io-index|8b2a41393f66f16b0823bb79094d54ac5fbd34ab292ddafb9a0456ac9f87d201
crypto-common|0.2.2|registry+https://github.com/rust-lang/crates.io-index|ce6e4c961d6cd6c9a86db418387425e8bdeaf05b3c8bc1411e6dca4c252f1453
ctr|0.10.1|registry+https://github.com/rust-lang/crates.io-index|baaca1c4b237092596f64d571e9db6ce4109c4ef9742e27590f1709594461f21
ctutils|0.4.2|registry+https://github.com/rust-lang/crates.io-index|7d5515a3834141de9eafb9717ad39eea8247b5674e6066c404e8c4b365d2a29e
dtoa|1.0.11|registry+https://github.com/rust-lang/crates.io-index|4c3cf4824e2d5f025c7b531afcb2325364084a16806f6d47fbc1f5fbd9960590
equivalent|1.0.2|registry+https://github.com/rust-lang/crates.io-index|877a4ace8713b0bcf2a4e7eec82529c029f1d0619886d18145fea96c3ffe5c0f
errno|0.3.14|registry+https://github.com/rust-lang/crates.io-index|39cab71617ae0d63f51a36d69f866391735b51691dbda63cf6f96d042b63efeb
fastrand|2.5.0|registry+https://github.com/rust-lang/crates.io-index|da7c62ceae207dd37ea5b845da6a0696c799f85e97da1ab5b7910be3c1c80223
ferrum2-client|0.1.0||
ferrum2-config|0.1.0||
ferrum2-core|0.1.0||
ferrum2-crypto|0.1.0||
ferrum2-m0-harness|0.1.0||
ferrum2-m4-qualification|0.1.0||
ferrum2-observability|0.1.0||
ferrum2-runtime|0.1.0||
ferrum2-server|0.1.0||
ferrum2-shadowsocks|0.1.0||
ferrum2-socks5|0.1.0||
find-msvc-tools|0.1.9|registry+https://github.com/rust-lang/crates.io-index|5baebc0774151f905a1a2cc41989300b1e6fbb29aff0ceffa1064fdd3088d582
getrandom|0.4.3|registry+https://github.com/rust-lang/crates.io-index|300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099
ghash|0.6.0|registry+https://github.com/rust-lang/crates.io-index|2eecf2d5dc9b66b732b97707a0210906b1d30523eb773193ab777c0c84b3e8d5
hashbrown|0.17.1|registry+https://github.com/rust-lang/crates.io-index|ed5909b6e89a2db4456e54cd5f673791d7eca6732202bbf2a9cc504fe2f9b84a
heck|0.5.0|registry+https://github.com/rust-lang/crates.io-index|2304e00983f87ffb38b55b444b5e3b60a884b5d30c0fca7d82fe33449bbe55ea
hex|0.4.3|registry+https://github.com/rust-lang/crates.io-index|7f24254aa9a54b5c858eaee2f5bccdb46aaf0e486a595ed5fd8f86ba55232a70
hybrid-array|0.4.13|registry+https://github.com/rust-lang/crates.io-index|818356c5132c1fede50f837ca96afbe78ff42413047f4abb886217845e1b6c8c
indexmap|2.14.0|registry+https://github.com/rust-lang/crates.io-index|d466e9454f08e4a911e14806c24e16fba1b4c121d1ea474396f396069cf949d9
inout|0.2.2|registry+https://github.com/rust-lang/crates.io-index|4250ce6452e92010fdf7268ccc5d14faa80bb12fc741938534c58f16804e03c7
itoa|1.0.18|registry+https://github.com/rust-lang/crates.io-index|8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682
lazy_static|1.5.0|registry+https://github.com/rust-lang/crates.io-index|bbd2bcb4c963f2ddae06a2efc7e9f3591312473c50c6685e1f298068316e66fe
libc|0.2.189|registry+https://github.com/rust-lang/crates.io-index|3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2
linux-raw-sys|0.12.1|registry+https://github.com/rust-lang/crates.io-index|32a66949e030da00e8c7d4434b251670a91556f4144941d37452769c25d58a53
lock_api|0.4.14|registry+https://github.com/rust-lang/crates.io-index|224399e74b87b5f3557511d98dff8b14089b3dadafcab6bb93eab67d3aace965
matchers|0.2.0|registry+https://github.com/rust-lang/crates.io-index|d1525a2a28c7f4fa0fc98bb91ae755d1e2d1505079e05539e35bc876b5d65ae9
memchr|2.8.3|registry+https://github.com/rust-lang/crates.io-index|cf8baf1c55e62ffcace7a9f06f4bd9cd3f0c4beb022d3b367256b91b87513d98
mio|1.2.2|registry+https://github.com/rust-lang/crates.io-index|30d65c71f1ce40ab09135ce117d742b9f8a19ff91a41a8b57ed50bc2de59c427
once_cell|1.21.4|registry+https://github.com/rust-lang/crates.io-index|9f7c3e4beb33f85d45ae3e3a1792185706c8e16d043238c593331cc7cd313b50
parking_lot|0.12.5|registry+https://github.com/rust-lang/crates.io-index|93857453250e3077bd71ff98b6a65ea6621a19bb0f559a85248955ac12c45a1a
parking_lot_core|0.9.12|registry+https://github.com/rust-lang/crates.io-index|2621685985a2ebf1c516881c026032ac7deafcda1a2c9b7850dc81e3dfcb64c1
pin-project-lite|0.2.17|registry+https://github.com/rust-lang/crates.io-index|a89322df9ebe1c1578d689c92318e070967d1042b512afbe49518723f4e6d5cd
poly1305|0.9.1|registry+https://github.com/rust-lang/crates.io-index|6e2d0073b297041425c7c3df6eb4792d598a15323fe63346852b092eca02904c
polyval|0.7.3|registry+https://github.com/rust-lang/crates.io-index|f0fa31d631f2b2cb2a544d0aa321ce847a94764d701ca2becc411138b93d49cd
proc-macro2|1.0.107|registry+https://github.com/rust-lang/crates.io-index|985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9
prometheus-client|0.25.0|registry+https://github.com/rust-lang/crates.io-index|ba70bf887030e45213b4a95c9b08d5a450b157f87c1d63661ed0847a12fa2aad
prometheus-client-derive-encode|0.5.0|registry+https://github.com/rust-lang/crates.io-index|9adf1691c04c0a5ff46ff8f262b58beb07b0dbb61f96f9f54f6cbd82106ed87f
quote|1.0.47|registry+https://github.com/rust-lang/crates.io-index|1fbf4db142a473a8d80c26bbf18454ed458bf8d26c8219c331daecfdbd079001
r-efi|6.0.0|registry+https://github.com/rust-lang/crates.io-index|f8dcc9c7d52a811697d2151c701e0d08956f92b0e24136cf4cf27b57a6a0d9bf
redox_syscall|0.5.18|registry+https://github.com/rust-lang/crates.io-index|ed2bf2547551a7053d6fdfafda3f938979645c44812fbfcda098faae3f1a362d
regex-automata|0.4.16|registry+https://github.com/rust-lang/crates.io-index|8fcfdb36bda0c880c5931cdc7a2bcdc8ba4556847b9d912bca70bc94708711ad
regex-syntax|0.8.11|registry+https://github.com/rust-lang/crates.io-index|d6f6ff9a378485b298a5286656da665ba74413d36db0979633275d2e708145d4
rustix|1.1.4|registry+https://github.com/rust-lang/crates.io-index|b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190
scopeguard|1.2.0|registry+https://github.com/rust-lang/crates.io-index|94143f37725109f92c262ed2cf5e59bce7498c01bcc1502d7b9afe439a4e9f49
serde|1.0.229|registry+https://github.com/rust-lang/crates.io-index|4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba
serde_core|1.0.229|registry+https://github.com/rust-lang/crates.io-index|67dca2c9c51e58a4791a4b1ed58308b39c64224d349a935ab5039aa360942a48
serde_derive|1.0.229|registry+https://github.com/rust-lang/crates.io-index|e7a5d71263a5a7d47b41f6b3f06ba276f10cc18b0931f1799f710578e2309348
serde_json|1.0.151|registry+https://github.com/rust-lang/crates.io-index|c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14
serde_spanned|1.1.1|registry+https://github.com/rust-lang/crates.io-index|6662b5879511e06e8999a8a235d848113e942c9124f211511b16466ee2995f26
shadowsocks-crypto|0.7.0||
sharded-slab|0.1.7|registry+https://github.com/rust-lang/crates.io-index|f40ca3c46823713e0d4209592e8d6e826aa57e928f09752619fc696c499637f6
shlex|2.0.1|registry+https://github.com/rust-lang/crates.io-index|f8fadd59c855ef2080decdef8ff161eb6661b86933c9d82e5ba29dc602a55aba
signal-hook-registry|1.4.8|registry+https://github.com/rust-lang/crates.io-index|c4db69cba1110affc0e9f7bcd48bbf87b3f4fc7c61fc9155afd4c469eb3d6c1b
smallvec|1.15.2|registry+https://github.com/rust-lang/crates.io-index|8ed6a63f02c8539c91a8685a86f4099661ba3da017932f6ebbea6de3f0fa7c90
socket2|0.6.5|registry+https://github.com/rust-lang/crates.io-index|c3d1e2c7f27f8d4cb10542a02c49005dbd6e93095799d6f3be745fae9f8fedd4
subtle|2.6.1|registry+https://github.com/rust-lang/crates.io-index|13c2bddecc57b384dee18652358fb23172facb8a2c51ccc10d74c157bdea3292
syn|2.0.119|registry+https://github.com/rust-lang/crates.io-index|872831b642d1a07999a962a351ed35b955ea2cfc8f3862091e2a240a84f17297
syn|3.0.3|registry+https://github.com/rust-lang/crates.io-index|53e9bae58849f64dfa4f5d5ae372c8341f7305f82a3868709269343628b659a3
tempfile|3.27.0|registry+https://github.com/rust-lang/crates.io-index|32497e9a4c7b38532efcdebeef879707aa9f794296a4f0244f6f69e9bc8574bd
thiserror|2.0.19|registry+https://github.com/rust-lang/crates.io-index|09a43598840e33d5b0331f38c5e30d13bb11c11210a4b58f0d9b18a5a5eefcd9
thiserror-impl|2.0.19|registry+https://github.com/rust-lang/crates.io-index|43cbfe0cf76104d42a574802844187e84a305e531ed54455f11fbde0f10541cd
thread_local|1.1.10|registry+https://github.com/rust-lang/crates.io-index|1ad99c4c6d32803332c548b1af0540b357b3f5fc0be8f6c6bfe8b2e6ae784070
tokio|1.53.1|registry+https://github.com/rust-lang/crates.io-index|202caea871b69668250d242070849eb495be178ed697a3e98aebce5bc81a0bed
tokio-macros|2.7.1|registry+https://github.com/rust-lang/crates.io-index|6328af13490e73a9b4694030fafd93f8c8c6a9dede33e821c3fc63eddf8042ba
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
valuable|0.1.1|registry+https://github.com/rust-lang/crates.io-index|ba73ea9cf16a25df0c8caa16c51acb937d5712a8429db78a3ee29d5dcacd3a65
wasi|0.11.1+wasi-snapshot-preview1|registry+https://github.com/rust-lang/crates.io-index|ccf3ec651a847eb01de73ccad15eb7d99f80485de043efb2f370cd654f4ea44b
windows-link|0.2.1|registry+https://github.com/rust-lang/crates.io-index|f0805222e57f7521d6a62e36fa9163bc891acd422f971defe97d64e70d0a4fe5
windows-sys|0.61.2|registry+https://github.com/rust-lang/crates.io-index|ae137229bcbd6cdf0f7b80a31df61766145077ddf49416a728b02cb3921ff3fc
winnow|1.0.4|registry+https://github.com/rust-lang/crates.io-index|23b97319f7b8343df12cc98938e5c3eb436064524c8d2b4e30a1d3a36eecdf81
zeroize|1.9.0|registry+https://github.com/rust-lang/crates.io-index|e13c156562582aa81c60cb29407084cdb54c4164760106ab78e6c5b0858cf64e
zeroize_derive|1.5.0|registry+https://github.com/rust-lang/crates.io-index|3c50655cbb0fe3fc43170059e702f1ce5e19b84cec58dc87b037a09935c2f328
zmij|1.0.23|registry+https://github.com/rust-lang/crates.io-index|29666d0abbfad1e3dc4dcf6144730dd3a3ab225bbbdac83319345b1b44ccfc1b"#;

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
        115,
        "the approved workspace baseline must contain 115 identities"
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
        .filter(|line| line.contains("tokio"))
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
        if dev
            != BTreeMap::from([(
                "tokio".to_owned(),
                BINARY_TOKIO_DEV_DECLARATION
                    .strip_prefix("tokio = ")
                    .expect("dev declaration prefix")
                    .to_owned(),
            )])
        {
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
    assert!(manifest.contains("rust-version = \"1.85.0\""));
    assert!(manifest.contains("resolver = \"3\""));

    let cargo_config =
        fs::read_to_string(root.join(".cargo/config.toml")).expect("Cargo configuration");
    assert!(cargo_config.contains("incompatible-rust-versions = \"fallback\""));
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
        "aes-gcm = { version = \"=0.11.0\", default-features = false, features = [\"aes\", \"bytes\", \"zeroize\"] }",
        "chacha20poly1305 = { version = \"=0.11.0\", default-features = false, features = [\"bytes\", \"zeroize\"] }",
        "ghash = { version = \"=0.6.0\", default-features = false, features = [\"zeroize\"] }",
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
    assert_eq!(
        dependency_table.get("ghash").map(String::as_str),
        Some(r#"{ version = "=0.6.0", default-features = false, features = ["zeroize"] }"#)
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
        "ferrum2-observability",
        "ferrum2-runtime",
        "ferrum2-shadowsocks",
        "ferrum2-socks5",
        "getrandom",
        "ghash",
        "hex",
        "prometheus-client",
        "serde",
        "serde_json",
        "shadowsocks-crypto",
        "socket2",
        "tempfile",
        "thiserror",
        "tokio",
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
fn crypto_manifest_declares_exact_primitive_edges_and_zeroize_anchors() {
    let manifest = fs::read_to_string(
        workspace_root()
            .join("crates")
            .join("ferrum2-crypto")
            .join("Cargo.toml"),
    )
    .expect("crypto manifest");
    let dependencies = dependency_table(&manifest, "[dependencies]").expect("crypto dependencies");

    assert_eq!(
        dependencies.get("aes.workspace").map(String::as_str),
        Some("true"),
        "aes must be inherited from the workspace without member overrides"
    );
    assert_eq!(
        dependencies.get("ghash.workspace").map(String::as_str),
        Some("true"),
        "ghash must be inherited from the workspace without member overrides"
    );
    assert_eq!(
        dependencies
            .get("chacha20poly1305.workspace")
            .map(String::as_str),
        Some("true"),
        "ChaCha20-Poly1305 must be inherited without a member feature override"
    );
    assert!(
        !dependencies.contains_key("aes"),
        "aes must use the exact dotted workspace declaration"
    );
    assert!(
        !dependencies.contains_key("ghash"),
        "ghash must use the exact dotted workspace declaration"
    );
    assert!(
        !dependencies.contains_key("chacha20poly1305"),
        "ChaCha20-Poly1305 must use the exact dotted workspace declaration"
    );
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
                "ferrum2-observability".to_owned(),
                "ferrum2-runtime".to_owned(),
                "ferrum2-shadowsocks".to_owned(),
                "ferrum2-socks5".to_owned(),
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
                "ferrum2-observability".to_owned(),
                "ferrum2-runtime".to_owned(),
                "ferrum2-shadowsocks".to_owned(),
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
fn harness_dependencies_and_lock_edges_match_the_hosted_qualification_seam() {
    let root = workspace_root();
    let manifest =
        fs::read_to_string(root.join("tests/m0-harness/Cargo.toml")).expect("harness manifest");
    let manifest_lf = normalize_line_endings(&manifest).expect("harness line endings");
    let expected_dev = BTreeMap::from([
        ("aes-gcm.workspace".to_owned(), "true".to_owned()),
        ("blake3.workspace".to_owned(), "true".to_owned()),
        ("hex.workspace".to_owned(), "true".to_owned()),
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
            ("socket2.workspace".to_owned(), "true".to_owned()),
            ("tempfile.workspace".to_owned(), "true".to_owned()),
        ])
    );
    let lock = fs::read_to_string(root.join("Cargo.lock")).expect("Cargo.lock");
    assert_eq!(
        lock_package_dependencies(&lock, "ferrum2-m4-qualification").expect("M4 lock dependencies"),
        BTreeSet::from(["socket2".to_owned(), "tempfile".to_owned()])
    );
}

#[test]
fn metadata_proves_exact_zeroize_feature_anchor_edges() {
    let metadata = metadata();
    let packages = metadata["packages"].as_array().expect("packages");
    let crypto = packages
        .iter()
        .find(|package| package["name"] == "ferrum2-crypto")
        .expect("crypto package");
    let crypto_dependencies = crypto["dependencies"]
        .as_array()
        .expect("crypto dependencies");

    for (name, version) in [("aes", "0.9.1"), ("ghash", "0.6.0")] {
        let dependencies: Vec<_> = crypto_dependencies
            .iter()
            .filter(|dependency| dependency["name"] == name)
            .collect();
        assert_eq!(
            dependencies.len(),
            1,
            "crypto must have one direct {name} feature anchor"
        );
        let dependency = dependencies[0];
        assert_eq!(
            dependency["source"],
            "registry+https://github.com/rust-lang/crates.io-index"
        );
        assert_eq!(dependency["req"], format!("={version}"));
        assert!(dependency["kind"].is_null(), "{name} must be normal");
        assert!(dependency["rename"].is_null(), "{name} must be unrenamed");
        assert_eq!(dependency["optional"], false);
        assert_eq!(dependency["uses_default_features"], false);
        assert_eq!(dependency["features"], serde_json::json!(["zeroize"]));
        assert!(
            dependency["target"].is_null(),
            "{name} must be unconditional"
        );
    }

    let crypto_node = resolve_node(&metadata, crypto["id"].as_str().expect("crypto package ID"));
    let chacha_dependencies: Vec<_> = crypto_dependencies
        .iter()
        .filter(|dependency| dependency["name"] == "chacha20poly1305")
        .collect();
    assert_eq!(
        chacha_dependencies.len(),
        1,
        "crypto must have one direct ChaCha20-Poly1305 edge"
    );
    let chacha_dependency = chacha_dependencies[0];
    assert_eq!(
        chacha_dependency["source"],
        "registry+https://github.com/rust-lang/crates.io-index"
    );
    assert_eq!(chacha_dependency["req"], "=0.11.0");
    assert!(chacha_dependency["kind"].is_null());
    assert!(chacha_dependency["rename"].is_null());
    assert_eq!(chacha_dependency["optional"], false);
    assert_eq!(chacha_dependency["uses_default_features"], false);
    assert_eq!(
        chacha_dependency["features"],
        serde_json::json!(["bytes", "zeroize"])
    );
    assert!(chacha_dependency["target"].is_null());
    let chacha_id = unique_registry_package_id(&metadata, "chacha20poly1305", "0.11.0");
    let chacha_package = packages
        .iter()
        .find(|package| package["id"].as_str() == Some(chacha_id.as_str()))
        .expect("resolved ChaCha20-Poly1305 package");
    assert_eq!(chacha_package["rust_version"], "1.85");
    assert_eq!(chacha_package["license"], "Apache-2.0 OR MIT");
    let chacha_edge = crypto_node["deps"]
        .as_array()
        .expect("crypto resolve dependencies")
        .iter()
        .find(|dependency| dependency["name"] == "chacha20poly1305")
        .expect("direct ChaCha20-Poly1305 edge");
    assert_eq!(chacha_edge["pkg"], chacha_id);
    assert_eq!(
        chacha_edge["dep_kinds"],
        serde_json::json!([{"kind": null, "target": null}])
    );

    let aes_gcm_id = unique_registry_package_id(&metadata, "aes-gcm", "0.11.0");
    let aes_gcm_node = resolve_node(&metadata, &aes_gcm_id);

    for (name, version) in [("aes", "0.9.1"), ("ghash", "0.6.0")] {
        let package_id = unique_registry_package_id(&metadata, name, version);
        let direct_edge = crypto_node["deps"]
            .as_array()
            .expect("crypto resolve dependencies")
            .iter()
            .find(|dependency| dependency["name"] == name)
            .expect("direct feature anchor edge");
        let transitive_edge = aes_gcm_node["deps"]
            .as_array()
            .expect("aes-gcm resolve dependencies")
            .iter()
            .find(|dependency| dependency["name"] == name)
            .expect("aes-gcm transitive edge");

        assert_eq!(direct_edge["pkg"], package_id);
        assert_eq!(transitive_edge["pkg"], package_id);
        assert_eq!(
            direct_edge["dep_kinds"],
            serde_json::json!([{"kind": null, "target": null}]),
            "{name} direct resolve edge must be normal and unconditional"
        );
    }
}

#[test]
fn resolved_crypto_feature_sets_are_exact() {
    let metadata = metadata();
    for (name, version, expected_features) in [
        ("aes-gcm", "0.11.0", &["aes", "bytes", "zeroize"][..]),
        ("chacha20poly1305", "0.11.0", &["bytes", "zeroize"][..]),
        ("chacha20", "0.10.1", &["cipher", "xchacha", "zeroize"][..]),
        ("poly1305", "0.9.1", &[][..]),
        ("aes", "0.9.1", &["zeroize"][..]),
        ("ghash", "0.6.0", &["zeroize"][..]),
        ("polyval", "0.7.3", &["hazmat", "zeroize"][..]),
        (
            "zeroize",
            "1.9.0",
            &["aarch64", "alloc", "derive", "zeroize_derive"][..],
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
        115,
        "candidate lock must contain 115 packages"
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
        assert_eq!(package["rust_version"], "1.85.0");
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
        "restore_thp",
        "trap - EXIT TERM",
        "printf '%s\\n' 'm4_thp_profile status=RESTORED readback=PASS'",
        "printf 'm4_performance_completion status=PASS ",
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
