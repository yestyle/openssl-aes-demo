use hex_literal::hex;
use openssl::{hash::MessageDigest, pkcs5::pbkdf2_hmac, sha::sha256};
use ring::hmac;

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

// key_size in bits, e.g.: 128, 256, etc.
fn evp(passphrase: &[u8], salt: Option<&[u8]>, key_size: u32) -> (Vec<u8>, Vec<u8>) {
    let mut v = Vec::new();
    let mut hash = Vec::new();

    let expected_key_bytes = (key_size / 8) as usize;
    // Expected IV is always 16 bytes
    let expected_iv_bytes = 16;
    loop {
        v.clear();
        v.extend_from_slice(&hash);
        v.extend_from_slice(passphrase);
        if let Some(salt) = salt {
            v.extend_from_slice(salt);
        }
        println!("Source of hash:");
        hexdump(&v);

        hash.extend_from_slice(&sha256(&v));
        println!("Hash:");
        hexdump(&hash);

        if hash.len() >= expected_key_bytes + expected_iv_bytes {
            break;
        }
    }

    (
        hash[..expected_key_bytes].to_owned(),
        hash[expected_key_bytes..expected_key_bytes + expected_iv_bytes].to_owned(),
    )
}

fn pbkdf2(
    passphrase: &[u8],
    salt: Option<&[u8]>,
    iterations: u32,
    dk_len: usize,
) -> (Vec<u8>, Vec<u8>) {
    // Expected IV is always 16 bytes
    let expected_iv_bytes = 16;
    let salt = if let Some(salt) = salt { salt } else { &[] };

    let prf = hmac::Key::new(hmac::HMAC_SHA256, passphrase);
    let mut key = vec![0u8; dk_len];
    let mut iv = vec![0u8; expected_iv_bytes];
    let mut block_num = 1u32;

    let mut remaining_key = dk_len;
    let mut remaining_iv = expected_iv_bytes;
    let mut offset_key = 0;
    let mut offset_iv = 0;

    while remaining_key > 0 || remaining_iv > 0 {
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

        let mut offset_in_block = 0;
        if remaining_key > 0 {
            let used = remaining_key.min(block.len());
            key[offset_key..offset_key + used].copy_from_slice(&block[..used]);

            offset_key += used;
            remaining_key -= used;
            offset_in_block += used;
        }

        if remaining_iv > 0 {
            let used = remaining_iv.min(block.len() - offset_in_block);
            iv[offset_iv..offset_iv + used]
                .copy_from_slice(&block[offset_in_block..offset_in_block + used]);

            offset_iv += used;
            remaining_iv -= used;
        }
        block_num += 1;
    }

    (key, iv)
}

fn main() {
    let passphrase = "drjom(&)(&)MOJRD";

    // evp + nosalt
    // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -nosalt
    // key=53A8968B0F53CAA2D21F2694B19EDD0676AF034D4D570651B3689C7827EC84C2
    // iv =ED889267E14BA02167ED96E226153158
    let (key, iv) = evp(passphrase.as_bytes(), None, 256);
    assert_eq!(
        hex!("53A8968B0F53CAA2D21F2694B19EDD0676AF034D4D570651B3689C7827EC84C2"),
        key.as_slice()
    );
    assert_eq!(hex!("ED889267E14BA02167ED96E226153158"), iv.as_slice());

    // evp + salt
    // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -salt
    // salt=DB42A96B2AA5CECE
    // key=CD10B0CBE8CFF451CDF082F00DA4A3E6351BFD5996D7EF0E4ACEBE13B1382BF7
    // iv =115776C3DFD6EFEDA0076617A35B3438
    let (key, iv) = evp(passphrase.as_bytes(), Some(&hex!("DB42A96B2AA5CECE")), 256);
    assert_eq!(
        hex!("CD10B0CBE8CFF451CDF082F00DA4A3E6351BFD5996D7EF0E4ACEBE13B1382BF7"),
        key.as_slice()
    );
    assert_eq!(hex!("115776C3DFD6EFEDA0076617A35B3438"), iv.as_slice());

    // pbkdf2 + salt + iter 10000
    // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -salt -iter 10000
    // salt=0526EC6BCCE0E971
    // key=9332AE8FAEAD6BA8B94DEAE0526A96267F7588611FCC5A9A30DC9CA8480E9B55
    // iv =5E4E0250801A7C68FA185133729D7798

    // Using pbkdf2_hmac() from openssl crate
    let mut derived_key = vec![0; 48];
    pbkdf2_hmac(
        passphrase.as_bytes(),
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

    // Using my own implementation
    let (key, iv) = pbkdf2(
        passphrase.as_bytes(),
        Some(&hex!("0526EC6BCCE0E971")),
        10000,
        32,
    );
    assert_eq!(
        &key,
        &hex!("9332AE8FAEAD6BA8B94DEAE0526A96267F7588611FCC5A9A30DC9CA8480E9B55")
    );
    assert_eq!(&iv, &hex!("5E4E0250801A7C68FA185133729D7798"));

    // pbkdf2 + salt + iter 1
    // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -salt -iter 1
    // salt=ED0B59AB61394DAF
    // key=7BE0978302CDEA9A5C2DADC931BCC2559C7FA7FC3E378EC9D6276066D8026CFC
    // iv =3862EB4C5400259794232D09277C279E
    let (key, iv) = pbkdf2(
        passphrase.as_bytes(),
        Some(&hex!("ED0B59AB61394DAF")),
        1,
        32,
    );
    assert_eq!(
        &key,
        &hex!("7BE0978302CDEA9A5C2DADC931BCC2559C7FA7FC3E378EC9D6276066D8026CFC")
    );
    assert_eq!(&iv, &hex!("3862EB4C5400259794232D09277C279E"));

    // pbkdf2 + nosalt (+ iter 10000 by default)
    // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -nosalt -pbkdf2
    // key=2BA47DBFEF693184578563073278A83E3DE33A1F2DE6E64BDBD9DFC32946CE0B
    // iv =3C03BCBBAE2BD72F44366159358F3843
    let (key, iv) = pbkdf2(passphrase.as_bytes(), None, 10000, 32);
    assert_eq!(
        &key,
        &hex!("2BA47DBFEF693184578563073278A83E3DE33A1F2DE6E64BDBD9DFC32946CE0B")
    );
    assert_eq!(&iv, &hex!("3C03BCBBAE2BD72F44366159358F3843"));

    // pbkdf2 + nosalt + iter 1
    // openssl enc -aes-256-cbc -k "drjom(&)(&)MOJRD" -md sha256 -P -nosalt -pbkdf2 -iter 1
    // key=B0BC445D2D47544327D147982B25B86BBDE6A745338D0B9D681DDD61E3AE523F
    // iv =6EAD332E24753C990A6031E3C9D12B3B
    let (key, iv) = pbkdf2(passphrase.as_bytes(), None, 1, 32);
    assert_eq!(
        &key,
        &hex!("B0BC445D2D47544327D147982B25B86BBDE6A745338D0B9D681DDD61E3AE523F")
    );
    assert_eq!(&iv, &hex!("6EAD332E24753C990A6031E3C9D12B3B"));
}
