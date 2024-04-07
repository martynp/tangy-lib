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
    signing_key: MyJwkEcKey,
}

impl TangyLib {
    pub fn init(db_path: &Path) -> Result<Self, std::io::Error> {
        let mut keys = load_files_from_db(db_path)?;

        let ecmr_exists = keys
            .iter()
            .any(|(_, v)| v.alg.is_some() && v.alg.as_ref().unwrap() == "ECMR");
        let es512_exists = keys
            .iter()
            .any(|(_, v)| v.alg.is_some() && v.alg.as_ref().unwrap() == "ES512");

        if (!ecmr_exists && es512_exists) || (ecmr_exists && !es512_exists) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Key loading file error",
            ));
        }

        if !ecmr_exists && !es512_exists {
            //let es512_jwk = create_new_jwk("ES512", &["sign", "verify"]);
            let es512_jwk = create_new_jwk("ES512", &["sign", "verify"]);
            if let Ok(mut file) = std::fs::File::create_new(db_path.join("es512.jwk")) {
                file.write_all(es512_jwk.as_bytes()).unwrap();
            }

            let ecmr_jwk = create_new_jwk("ECMR", &["deriveKey"]);
            if let Ok(mut file) = std::fs::File::create_new(db_path.join("ecmr.jwk")) {
                file.write_all(ecmr_jwk.as_bytes()).unwrap();
            }

            keys.extend(load_files_from_db(db_path)?);
        }

        // Extract a signing key from the JWK, it shouldn't really be generated using a
        // from_bytes call from the secret key... perhaps the SigningKey From trait is
        // missing for the secret key.
        let signing_key = keys.iter().find_map(|(_, v)| {
            if let Some(alg) = v.alg.as_ref() {
                if alg == "ES512" {
                    return Some(v.clone());
                }
            }
            None
        });

        if signing_key.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Signing key not found",
            ));
        }

        Ok(Self {
            keys,
            signing_key: signing_key.unwrap(),
        })
    }

    pub fn adv(&mut self) -> String {
        #[derive(serde::Serialize)]
        struct Advertise {
            payload: String,
            protected: String,
            signature: String,
        }

        #[derive(serde::Serialize)]
        struct Payload {
            keys: Vec<MyJwkEcKey>,
        }

        let payload = base64ct::Base64Url::encode_string(
            serde_json::to_string(&Payload {
                keys: self.keys.values().map(|v| v.to_public_key()).collect(),
            })
            .unwrap()
            .as_bytes(),
        );

        // As per tang reference implementation
        let protected = base64ct::Base64Url::encode_string(
            r#"{"alg":"ES512","cty":"jwk-set+json"}"#.as_bytes(),
        );

        let mut signing_key = SigningKey::from_bytes(
            &self
                .signing_key
                .to_jwk_ec_key(false)
                .to_secret_key::<p521::NistP521>()
                .unwrap()
                .to_bytes(),
        )
        .unwrap();

        // The protected and payload fields are signed, as base64url encoded string
        // joined with a period.
        let to_sign = format!("{}.{}", &protected, &payload);

        let signature = ecdsa::signature::SignerMut::sign(&mut signing_key, to_sign.as_bytes());

        let mut buf = [0; 1024];
        serde_json::to_string(&Advertise {
            payload,
            protected,
            signature: base64ct::Base64Url::encode(&signature.to_bytes(), &mut buf)
                .unwrap()
                .to_string(),
        })
        .unwrap()
    }

    pub fn rec(&self, kid: &str, request: &str) -> Result<String, String> {
        let key = self.keys.iter().find_map(|(k, v)| {
            if k == kid {
                return Some(v);
            }
            None
        });

        if key.is_none() {
            println!("Key missmatch");
            return Err("".into());
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

        dbg!(&p);

        Ok(serde_json::to_string(&p).unwrap())
    }
}

fn load_files_from_db(db_path: &Path) -> Result<HashMap<String, MyJwkEcKey>, std::io::Error> {
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

    Ok(jwk_files
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

            let jwk: MyJwkEcKey = if let Ok(jwk) = serde_json::from_str(&file_content) {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_dir() {
        let tmp_dir = tempdir::TempDir::new("local_dir_test").unwrap();
        let _t = TangyLib::init(&tmp_dir.path());
    }

    #[test]
    fn adv() {
        let mut t = TangyLib::init(&std::path::Path::new("/var/lib/tang").to_path_buf()).unwrap();
        dbg!(t.adv());
    }
}
