//! Common utilities

/// Generate random bytes into `iv_or_salt`
pub fn random_iv_or_salt(iv_or_salt: &mut [u8]) {
    use rand::RngExt;

    // Gen IV or Gen Salt by KEY-LEN
    if iv_or_salt.is_empty() {
        return;
    }

    let mut rng = rand::rng();
    loop {
        rng.fill(iv_or_salt);

        let is_zeros = iv_or_salt.iter().all(|&byte| byte == 0);

        if !is_zeros {
            break;
        }
    }
}
