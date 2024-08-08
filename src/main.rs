use ring::{digest, hmac};

pub fn hexdump(bytes: &[u8]) {
    for (i, byte) in bytes.iter().enumerate() {
        if i % 16 == 0 {
            print!("{i:03X}: ");
        }
        print!("{byte:02X} ");
        if i % 16 == 15 {
            println!();
        }
    }
    // End of data new-line if bytes.len() isn't aligned to 16
    if bytes.len() % 16 != 0 {
        println!();
    }
    println!();
}

pub fn evp(passphrase: &[u8], salt: Option<&[u8]>, dk_len: usize) -> Vec<u8> {
    let mut v = Vec::new();
    let mut hash = Vec::new();

    loop {
        v.clear();
        v.extend_from_slice(&hash);
        v.extend_from_slice(passphrase);
        if let Some(salt) = salt {
            v.extend_from_slice(salt);
        }
        println!("Source of hash:");
        hexdump(&v);

        hash.extend_from_slice(&digest::digest(&digest::SHA256, &v).as_ref());
        println!("Hash:");
        hexdump(&hash);

        if hash.len() >= dk_len {
            break;
        }
    }

    hash.drain(dk_len..);
    hash
}

pub fn pbkdf2(passphrase: &[u8], salt: Option<&[u8]>, iterations: u32, dk_len: usize) -> Vec<u8> {
    let salt = if let Some(salt) = salt { salt } else { &[] };

    let prf = hmac::Key::new(hmac::HMAC_SHA256, passphrase);
    let mut output = vec![0u8; dk_len];
    let mut block_num = 1u32;

    let mut remaining = dk_len;
    let mut offset = 0;

    while remaining > 0 {
        let mut block = [0u8; 32];
        let mut u = vec![0u8; 32];

        // Salt || INT_32_BE(block_num)
        let mut salt_block = Vec::with_capacity(salt.len() + 4);
        salt_block.extend_from_slice(salt);
        salt_block.extend_from_slice(&block_num.to_be_bytes());

        // U1 = PRF(Password, Salt || INT_32_BE(block_num))
        hmac::sign(&prf, &salt_block).as_ref().clone_into(&mut u);
        block.clone_from_slice(&u);

        for _ in 1..iterations {
            // Uj = PRF(Password, U_{j-1})
            hmac::sign(&prf, &u).as_ref().clone_into(&mut u);
            for i in 0..block.len() {
                block[i] ^= u[i];
            }
        }

        println!("Block {block_num}:");
        hexdump(&block);

        let block_len = remaining.min(block.len());
        output[offset..offset + block_len].copy_from_slice(&block[..block_len]);

        offset += block_len;
        remaining -= block_len;
        block_num += 1;
    }

    output
}

fn main() {}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use openssl::{hash::MessageDigest, pkcs5::pbkdf2_hmac};

    const PASSPHRASE: &[u8] = b"drjom(&)(&)MOJRD";

    #[test]
    fn test_openssl_pbkdf2_hmac() {
        // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -salt -iter 10000
        // salt=0526EC6BCCE0E971
        // key=9332AE8FAEAD6BA8B94DEAE0526A96267F7588611FCC5A9A30DC9CA8480E9B55
        // iv =5E4E0250801A7C68FA185133729D7798

        let mut derived_key = vec![0; 48];
        pbkdf2_hmac(
            PASSPHRASE,
            &hex!("0526EC6BCCE0E971"),
            10000,
            MessageDigest::sha256(),
            &mut derived_key,
        )
        .unwrap();

        assert_eq!(
            &derived_key[..32],
            &hex!("9332AE8FAEAD6BA8B94DEAE0526A96267F7588611FCC5A9A30DC9CA8480E9B55")
        );
        assert_eq!(
            &derived_key[32..],
            &hex!("5E4E0250801A7C68FA185133729D7798")
        );
    }

    #[test]
    fn test_evp() {
        // evp + nosalt
        // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -nosalt
        // key=53A8968B0F53CAA2D21F2694B19EDD0676AF034D4D570651B3689C7827EC84C2
        // iv =ED889267E14BA02167ED96E226153158
        let derived_key = evp(PASSPHRASE, None, 48);
        assert_eq!(
            hex!("53A8968B0F53CAA2D21F2694B19EDD0676AF034D4D570651B3689C7827EC84C2"),
            &derived_key[..32]
        );
        assert_eq!(hex!("ED889267E14BA02167ED96E226153158"), &derived_key[32..]);

        // evp + salt
        // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -salt
        // salt=DB42A96B2AA5CECE
        // key=CD10B0CBE8CFF451CDF082F00DA4A3E6351BFD5996D7EF0E4ACEBE13B1382BF7
        // iv =115776C3DFD6EFEDA0076617A35B3438
        let derived_key = evp(PASSPHRASE, Some(&hex!("DB42A96B2AA5CECE")), 48);
        assert_eq!(
            hex!("CD10B0CBE8CFF451CDF082F00DA4A3E6351BFD5996D7EF0E4ACEBE13B1382BF7"),
            &derived_key[..32]
        );
        assert_eq!(hex!("115776C3DFD6EFEDA0076617A35B3438"), &derived_key[32..]);
    }

    #[test]
    fn test_pbkdf2() {
        // pbkdf2 + salt + iter 10000
        // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -salt -iter 10000
        // salt=0526EC6BCCE0E971
        // key=9332AE8FAEAD6BA8B94DEAE0526A96267F7588611FCC5A9A30DC9CA8480E9B55
        // iv =5E4E0250801A7C68FA185133729D7798
        let derived_key = pbkdf2(PASSPHRASE, Some(&hex!("0526EC6BCCE0E971")), 10000, 48);
        assert_eq!(
            &derived_key[..32],
            &hex!("9332AE8FAEAD6BA8B94DEAE0526A96267F7588611FCC5A9A30DC9CA8480E9B55")
        );
        assert_eq!(
            &derived_key[32..],
            &hex!("5E4E0250801A7C68FA185133729D7798")
        );

        // pbkdf2 + salt + iter 1
        // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -salt -iter 1
        // salt=ED0B59AB61394DAF
        // key=7BE0978302CDEA9A5C2DADC931BCC2559C7FA7FC3E378EC9D6276066D8026CFC
        // iv =3862EB4C5400259794232D09277C279E
        let derived_key = pbkdf2(PASSPHRASE, Some(&hex!("ED0B59AB61394DAF")), 1, 48);
        assert_eq!(
            &derived_key[..32],
            &hex!("7BE0978302CDEA9A5C2DADC931BCC2559C7FA7FC3E378EC9D6276066D8026CFC")
        );
        assert_eq!(
            &derived_key[32..],
            &hex!("3862EB4C5400259794232D09277C279E")
        );

        // pbkdf2 + nosalt (+ iter 10000 by default)
        // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -nosalt -pbkdf2
        // key=2BA47DBFEF693184578563073278A83E3DE33A1F2DE6E64BDBD9DFC32946CE0B
        // iv =3C03BCBBAE2BD72F44366159358F3843
        let derived_key = pbkdf2(PASSPHRASE, None, 10000, 48);
        assert_eq!(
            &derived_key[..32],
            &hex!("2BA47DBFEF693184578563073278A83E3DE33A1F2DE6E64BDBD9DFC32946CE0B")
        );
        assert_eq!(
            &derived_key[32..],
            &hex!("3C03BCBBAE2BD72F44366159358F3843")
        );

        // pbkdf2 + nosalt + iter 1
        // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -nosalt -pbkdf2 -iter 1
        // key=B0BC445D2D47544327D147982B25B86BBDE6A745338D0B9D681DDD61E3AE523F
        // iv =6EAD332E24753C990A6031E3C9D12B3B
        let derived_key = pbkdf2(PASSPHRASE, None, 1, 48);
        assert_eq!(
            &derived_key[..32],
            &hex!("B0BC445D2D47544327D147982B25B86BBDE6A745338D0B9D681DDD61E3AE523F")
        );
        assert_eq!(
            &derived_key[32..],
            &hex!("6EAD332E24753C990A6031E3C9D12B3B")
        );
    }
}
