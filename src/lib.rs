use std::{
    collections::HashMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use base64ct::Encoding;
use ecdsa::SigningKey;
use elliptic_curve::{rand_core::OsRng, JwkEcKey};
use p521::ecdsa;
use serde::Serialize;
use sha2::Digest;

#[derive(Debug)]
pub struct TangyLib {
    keys: std::collections::HashMap<String, MyJwkEcKey>,
    signing_keys: Vec<MyJwkEcKey>,
}

#[derive(PartialEq)]
pub enum KeySource<'a> {
    LocalDir(&'a Path),
    Vector(&'a Vec<&'a str>),
}

impl TangyLib {
    pub fn init(source: KeySource) -> Result<Self, std::io::Error> {
        let mut loaded_keys = match source {
            KeySource::LocalDir(dir) => load_keys_from_dir(dir)?,
            KeySource::Vector(keys) => load_keys_from_vec(keys)?,
        };

        let ecmr_exists = loaded_keys
            .iter()
            .any(|(_, v)| v.alg.is_some() && v.alg.as_ref().unwrap() == "ECMR");
        let es512_exists = loaded_keys
            .iter()
            .any(|(_, v)| v.alg.is_some() && v.alg.as_ref().unwrap() == "ES512");

        if (!ecmr_exists && es512_exists) || (ecmr_exists && !es512_exists) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Key loading file error",
            ));
        }

        if !ecmr_exists && !es512_exists {
            match source {
                KeySource::LocalDir(dir) => {
                    let keys = create_new_key_set();
                    keys.iter().for_each(|k| {
                        let jwk: MyJwkEcKey = serde_json::from_str(k).unwrap();
                        let thumbprint = jwk.thumbprint();
                        if let Ok(mut file) =
                            std::fs::File::create_new(dir.join(format!("{}.jwk", thumbprint)))
                        {
                            file.write_all(k.as_bytes()).unwrap();
                        }
                        loaded_keys.insert(thumbprint, jwk);
                    });
                }
                KeySource::Vector(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "ES512 and ECMR keys not present in input vector",
                    ));
                }
            }
        }

        // Extract a signing key from the JWK, it shouldn't really be generated using a
        // from_bytes call from the secret key... perhaps the SigningKey From trait is
        // missing for the secret key.
        let signing_keys: Vec<MyJwkEcKey> = loaded_keys
            .iter()
            .filter_map(|(_, v)| {
                if let Some(alg) = v.alg.as_ref() {
                    if alg == "ES512" {
                        return Some(v.clone());
                    }
                }
                None
            })
            .collect();

        if signing_keys.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Signing key not found",
            ));
        }

        Ok(Self {
            keys: loaded_keys,
            signing_keys: signing_keys,
        })
    }

    pub fn adv(&mut self, skid: Option<&str>) -> Result<String, std::io::Error> {
        #[derive(serde::Serialize)]
        struct Siguature {
            protected: String,
            signature: String,
        }
        #[derive(serde::Serialize)]
        struct Advertise {
            payload: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            protected: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            signature: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            signatures: Option<Vec<Siguature>>,
        }

        #[derive(serde::Serialize)]
        struct Payload {
            keys: Vec<MyJwkEcKey>,
        }

        let keys: Vec<&MyJwkEcKey> = self.keys.values().collect();

        let signing_keys = if let Some(kid) = skid {
            let key = self.keys.get(kid);
            if key.is_none() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Requested signing key {} not found", kid),
                ));
            }
            if key.unwrap().key_ops.is_none() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Requested signing key {} cannot be used for signing", kid),
                ));
            }
            if !key
                .as_ref()
                .unwrap()
                .key_ops
                .as_ref()
                .unwrap()
                .contains(&"sign".to_string())
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Requested signing key {} cannot be used for signing", kid),
                ));
            }
            vec![key.unwrap().clone()]
        } else {
            self.signing_keys.iter().map(|v| v.clone()).collect()
        };

        let payload = base64ct::Base64Url::encode_string(
            serde_json::to_string(&Payload {
                keys: keys
                    .iter()
                    .map(|v| {
                        let mut k = v.to_public_key();
                        let mut ops = k.key_ops.take();
                        if let Some(ops) = &mut ops {
                            ops.retain(|v| *v != "sign");
                        }
                        k.key_ops = ops;
                        k
                    })
                    .collect(),
            })
            .unwrap()
            .as_bytes(),
        );

        // As per tang reference implementation
        let protected = base64ct::Base64Url::encode_string(
            r#"{"alg":"ES512","cty":"jwk-set+json"}"#.as_bytes(),
        );

        let mut signing_keys: Vec<SigningKey> = signing_keys
            .iter()
            .map(|k| {
                SigningKey::from_bytes(
                    &k.to_jwk_ec_key(false)
                        .to_secret_key::<p521::NistP521>()
                        .unwrap()
                        .to_bytes(),
                )
                .unwrap()
            })
            .collect();

        // The protected and payload fields are signed, as base64url encoded string
        // joined with a period.
        let to_sign = format!("{}.{}", &protected, &payload);

        let signatures: Vec<_> = signing_keys
            .iter_mut()
            .map(|k| ecdsa::signature::SignerMut::sign(k, to_sign.as_bytes()))
            .collect();

        let mut buf = [0; 1024];

        if signatures.len() == 1 {
            Ok(serde_json::to_string(&Advertise {
                payload,
                protected: Some(protected),
                signature: Some(
                    base64ct::Base64Url::encode(&signatures[0].to_bytes(), &mut buf)
                        .unwrap()
                        .to_string(),
                ),
                signatures: None,
            })
            .unwrap())
        } else {
            Ok(serde_json::to_string(&Advertise {
                payload,
                protected: None,
                signature: None,
                signatures: Some(
                    signatures
                        .iter()
                        .map(|s| Siguature {
                            protected: protected.to_owned(),
                            signature: base64ct::Base64Url::encode(&s.to_bytes(), &mut buf)
                                .unwrap()
                                .to_string(),
                        })
                        .collect(),
                ),
            })
            .unwrap())
        }
    }

    pub fn rec(&self, kid: &str, request: &str) -> Result<String, std::io::Error> {
        let key = self.keys.iter().find_map(|(k, v)| {
            if k == kid {
                return Some(v);
            }
            None
        });

        if key.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Requested key not found".to_string(),
            ));
        }

        let request_key: MyJwkEcKey = serde_json::from_str(request).unwrap();
        let request_key = request_key
            .to_jwk_ec_key(true)
            .to_public_key::<p521::NistP521>()
            .unwrap();

        let p = diffie_hellman_public_key(
            &key.as_ref()
                .unwrap()
                .to_jwk_ec_key(false)
                .to_secret_key::<p521::NistP521>()
                .unwrap()
                .to_nonzero_scalar(),
            request_key.as_affine(),
        );

        Ok(serde_json::to_string(&p).unwrap())
    }
}

pub fn create_new_key_set() -> Vec<String> {
    let es512_jwk = create_new_jwk("ES512", &["sign", "verify"]);
    let ecmr_jwk = create_new_jwk("ECMR", &["deriveKey"]);
    vec![es512_jwk, ecmr_jwk]
}

fn load_keys_from_dir(db_path: &Path) -> Result<HashMap<String, MyJwkEcKey>, std::io::Error> {
    if !db_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "Key database \"{}\" does not exist",
                db_path.to_string_lossy()
            ),
        ));
    }

    if !db_path.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "Key database \"{}\" is not a directory",
                db_path.to_string_lossy()
            ),
        ));
    }

    let jwk_files: Vec<PathBuf> = db_path
        .read_dir()?
        .filter_map(|f| f.ok())
        .map(|e| e.path())
        .filter(|f| f.extension() == Some(std::ffi::OsStr::new("jwk")))
        .collect();

    let keys: Vec<String> = jwk_files
        .iter()
        .filter_map(|j| {
            let mut file_content = String::new();
            match std::fs::File::open(j) {
                Ok(mut f) => {
                    if f.read_to_string(&mut file_content).is_err() {
                        return None;
                    }
                }
                Err(_) => return None,
            };
            Some(file_content)
        })
        .collect();

    load_keys_from_vec(&keys)
}

fn load_keys_from_vec<T: AsRef<str>>(
    keys: &[T],
) -> Result<HashMap<String, MyJwkEcKey>, std::io::Error> {
    Ok(keys
        .iter()
        .filter_map(|key| {
            let jwk: MyJwkEcKey = if let Ok(jwk) = serde_json::from_str(key.as_ref()) {
                jwk
            } else {
                return None;
            };

            let thumbprint = thumprint(&jwk.crv, &jwk.kty, &jwk.x, &jwk.y);

            Some((thumbprint, jwk))
        })
        .collect())
}

fn create_new_jwk(alg: &str, key_ops: &[&str]) -> String {
    let priv_key = elliptic_curve::SecretKey::<p521::NistP521>::random(&mut OsRng);
    let jwk = priv_key.to_jwk();
    let encoded_point = jwk.to_encoded_point::<p521::NistP521>().unwrap();
    let mut buf = [0; 1000];

    let x = base64ct::Base64Url::encode(encoded_point.x().unwrap(), &mut buf)
        .unwrap()
        .to_string();

    let y = base64ct::Base64Url::encode(encoded_point.y().unwrap(), &mut buf)
        .unwrap()
        .to_string();

    serde_json::to_string(&MyJwkEcKey {
        alg: Some(alg.into()),
        kty: "EC".into(),
        crv: jwk.crv().into(),
        x: x.to_owned(),
        y: y.to_owned(),
        d: Some(
            base64ct::Base64Url::encode(priv_key.to_bytes().as_slice(), &mut buf)
                .unwrap()
                .to_string(),
        ),
        key_ops: Some(key_ops.iter().map(|k| k.to_string()).collect()),
        use_: None,
        kid: None,
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
    })
    .unwrap()
}

fn thumprint(crv: &str, kty: &str, x: &str, y: &str) -> String {
    #[derive(Serialize)]
    struct Required {
        crv: String,
        kty: String,
        x: String,
        y: String,
    }

    let required_fields = Required {
        crv: crv.to_owned(),
        kty: kty.to_owned(),
        x: x.to_owned(),
        y: y.to_owned(),
    };

    let mut hasher = sha2::Sha256::new();
    hasher.update(serde_json::to_string(&required_fields).unwrap().as_bytes());
    base64ct::Base64UrlUnpadded::encode_string(&hasher.finalize())
}

fn diffie_hellman_public_key(
    secret_key: &elliptic_curve::NonZeroScalar<p521::NistP521>,
    public_key: &elliptic_curve::AffinePoint<p521::NistP521>,
) -> MyJwkEcKey {
    let public_point = elliptic_curve::ProjectivePoint::<p521::NistP521>::from(*public_key);
    let secret_point = (public_point * secret_key.as_ref()).to_affine();
    let generated_public_key = p521::PublicKey::from_affine(secret_point).unwrap();

    let mut formatted_public_key: MyJwkEcKey =
        serde_json::from_str(generated_public_key.to_jwk_string().as_str()).unwrap();

    formatted_public_key.alg = Some("ECMR".into());
    formatted_public_key.crv = "P-521".into();
    formatted_public_key.kty = "EC".into();
    formatted_public_key.key_ops = Some(vec!["deriveKey".into()]);

    formatted_public_key
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct MyJwkEcKey {
    /// The `crv` parameter which identifies a particular elliptic curve
    /// as defined in RFC 7518 Section 6.2.1.1:
    /// <https://tools.ietf.org/html/rfc7518#section-6.2.1.1>
    pub crv: String,

    /// The x-coordinate of the elliptic curve point which is the public key
    /// value associated with this JWK as defined in RFC 7518 6.2.1.2:
    /// <https://tools.ietf.org/html/rfc7518#section-6.2.1.2>
    pub x: String,

    /// The y-coordinate of the elliptic curve point which is the public key
    /// value associated with this JWK as defined in RFC 7518 6.2.1.3:
    /// <https://tools.ietf.org/html/rfc7518#section-6.2.1.3>
    pub y: String,

    /// The `d` ECC private key parameter as described in RFC 7518 6.2.2.1:
    /// <https://tools.ietf.org/html/rfc7518#section-6.2.2.1>
    ///
    /// Value is optional and if omitted, this JWK represents a private key.
    ///
    /// Inner value is encoded according to the `Integer-to-Octet-String`
    /// conversion as defined in SEC1 section 2.3.7:
    /// <https://www.secg.org/sec1-v2.pdf>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,

    /// Key Type (must be "EC" if present) as described in RFC 7517 4.1:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.1>
    ///
    /// Value is optional.
    ///
    /// For Elliptic-Curve the value must be "EC".
    pub kty: String,

    /// The Public Key Use as described in RFC 7517 4.2:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.2>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none", rename = "use")]
    pub use_: Option<String>,

    /// The Key Operations as described in RFC 7517 4.3:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.3>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,

    /// The Algorithm as described in RFC 7517 4.4:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.4>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// The Key ID as described in RFC 7517 4.5:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.5>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// The X.509 URL as described in RFC 7517 4.6:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.6>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,

    /// The X.509 Certificate Chain as described in RFC 7517 4.7:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.7>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<String>,

    /// The X.509 Certificate SHA-1 Thumbprint as described in RFC 7517 4.8:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.8>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,

    /// The X.509 Certificate SHA-256 as described in RFC 7517 4.9:
    /// <https://datatracker.ietf.org/doc/html/rfc7517#section-4.9>
    ///
    /// Value is optional and not used by this crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
}

impl MyJwkEcKey {
    pub fn to_jwk_ec_key(&self, public: bool) -> JwkEcKey {
        let mut content: HashMap<String, String> = HashMap::new();
        content.insert("crv".into(), self.crv.to_owned());
        content.insert("kty".into(), self.kty.to_owned());
        content.insert("x".into(), self.x.to_owned());
        content.insert("y".into(), self.y.to_owned());
        if self.d.is_some() && !public {
            content.insert("d".into(), self.d.as_ref().unwrap().to_owned());
        }
        JwkEcKey::from_str(&serde_json::to_string(&content).unwrap()).unwrap()
    }

    pub fn to_public_key(&self) -> MyJwkEcKey {
        let mut ret = self.clone();
        ret.d = None;
        ret
    }

    pub fn thumbprint(&self) -> String {
        // For EC type the following fields are required to be
        // present and in lexicographic order
        #[derive(Serialize)]
        struct Required {
            crv: String,
            kty: String,
            x: String,
            y: String,
        }

        let required_fields = Required {
            crv: self.crv.to_owned(),
            kty: self.kty.to_owned(),
            x: self.x.to_owned(),
            y: self.y.to_owned(),
        };

        let mut hasher = sha2::Sha256::new();
        hasher.update(serde_json::to_string(&required_fields).unwrap().as_bytes());
        base64ct::Base64UrlUnpadded::encode_string(&hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    const JWK_ES512: &str = r#"
        {
            "kty": "EC",
            "alg": "ES512",
            "crv": "P-521",
            "x": "AX5mUTAH1qr3YSSwuMV_HV0yupJhMIAqwly710a7qLbXR6up3flnaPsJbaSVATrIF6QcXc9PPyFW1IQHmDOWGSPj",
            "y": "ADT1K8Q-O1Q5lyU3StXnPMQwgnYWS8hnTRGjjcFssitZy_tUWSuhUPFhzaUJKhXRNbcyELeDX-kPCMbBKX1vb8Lq",
            "d": "AbDO5xCtQHUbHld-Fq61sSCvyjr9EpNj3_sklNmo54xmKeYu_cW_s7fzQxm6SsqFwrTmiiFz2OaD1ODsXI-DdoKt",
            "key_ops": ["sign","verify"]
        }
    "#;

    const JWK_ES512_THUMBPRINT: &str = "tpUdnaei02Z6bSS3_rKEU0BDPl8tyZFy16CKCTWNlbA";

    const JWK_ECMR: &str = r#"
        {
            "kty": "EC",
            "alg": "ECMR",
            "crv": "P-521",
            "x": "ASa1DOpfB9-Qe1zkbG6HAZ_DC2FNUBeR6e3kgLgHF8xC8JZM1EsiGjkvTRk0paH_Oat8OSGSRPD0-PsXFAvNuXCd",
            "y": "AaO_WH8pzC__37gCuCJdgtIbO6IK4XLfyjAjuJovvfksoMigvFwpyLKwWhIfE8lQqPR7CMxG2LRLXJIubFjSDMDH",
            "d": "AQTm4JamDPZufHlRCC12Ssjh6xTwu630neCLr7EUtUuZoFHk9zga-kzwaGajH1MQb8ffc3CeV-7InHKmR8HvytTE",
            "key_ops":["deriveKey"]
        }
    "#;

    const JWK_ECMR_THUMBPRINT: &str = "UFgqx9-PLx_h6h4hd6sysNHMC6cDyjBQOYZHFvObLbo";

    #[test]
    fn source_local_dir() {
        let tmp_dir = tempdir::TempDir::new("local_dir_test").unwrap();
        let t = TangyLib::init(KeySource::LocalDir(&tmp_dir.path()));
        assert!(t.is_ok());
    }

    #[test]
    fn source_vector() {
        let v = vec![JWK_ES512, JWK_ECMR];
        let t = TangyLib::init(KeySource::Vector(&v));
        assert!(t.is_ok());
    }

    #[test]
    fn adv() {
        let v = vec![JWK_ES512, JWK_ECMR];
        let mut t = TangyLib::init(KeySource::Vector(&v)).unwrap();
        let advertisment = t.adv(None).unwrap();

        #[derive(Deserialize)]
        struct Adv {
            payload: String,
        }

        #[derive(Deserialize)]
        struct Key {
            kty: String,
            crv: String,
            x: String,
            y: String,
        }

        #[derive(Deserialize)]
        struct Payload {
            keys: Vec<Key>,
        }

        let actual_adv: Adv = serde_json::from_str(&advertisment).unwrap();
        let payload_json = base64ct::Base64Unpadded::decode_vec(&actual_adv.payload).unwrap();
        let payload: Payload = serde_json::from_slice(&payload_json).unwrap();
        assert_eq!(payload.keys.len(), 2);
    }

    #[test]
    fn adv_skid() {
        let v = vec![JWK_ES512, JWK_ECMR];
        let mut t = TangyLib::init(KeySource::Vector(&v)).unwrap();
        let advertisment = t.adv(Some(JWK_ES512_THUMBPRINT.into())).unwrap();

        #[derive(Deserialize)]
        struct Adv {
            payload: String,
        }

        #[derive(Deserialize)]
        struct Key {
            kty: String,
            crv: String,
            x: String,
            y: String,
        }

        #[derive(Deserialize)]
        struct Payload {
            keys: Vec<Key>,
        }

        let actual_adv: Adv = serde_json::from_str(&advertisment).unwrap();
        let payload_json = base64ct::Base64Unpadded::decode_vec(&actual_adv.payload).unwrap();
        let payload: Payload = serde_json::from_slice(&payload_json).unwrap();
        assert_eq!(payload.keys.len(), 2);
    }
}
