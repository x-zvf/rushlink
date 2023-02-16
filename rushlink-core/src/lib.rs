use aes_gcm_siv::Nonce as AesNonce;
use aes_gcm_siv::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    Aes256GcmSiv,
};

use blake3::Hasher;
use rand_core::{OsRng, RngCore};
use rocksdb::DB;
use serde::{Deserialize, Serialize};

type Hash = [u8; 32];
type Nonce = [u8; 12];
type EncryptionKey = Hash;

#[derive(Debug)]
pub struct LinkStore {
    database: DB,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    AlreadyExists,
    DoesNotExist,
    InvalidPassword,
    EncryptionFailed,
    DecryptionFailed,
    SerializationFailed,
    DeserializationFailed,
    DatabaseReadFailed,
    DatabaseWriteFailed,
}

#[derive(Serialize, Deserialize, Debug)]
struct LinkEntry {
    edit_password_hash: [u8; 32],
    encrypted_destination: Vec<u8>,
    nonce: [u8; 12],
    hit_counter: Option<u64>,
}

impl LinkStore {
    /// Open a Rocksdb dataset located at Path
    pub fn new(db_path: &str) -> Result<Self, String> {
        DB::open_default(db_path)
            .map_err(|e| e.to_string())
            .map(|database| Ok(LinkStore { database }))?
    }

    pub fn add_url(
        &self,
        shortlink: &str,
        resolve_to: &str,
        password: &str,
        should_count_hits: bool,
    ) -> Result<(), Error> {
        let (hasher, key) = hash_shortlink(shortlink);
        self.verify_unique_shortlink(&key)?;

        let (encrypted_destination, nonce) = encrypt_destination(shortlink, resolve_to, hasher)?;

        let edit_password_hash = hash_password(password);

        let entry = LinkEntry {
            nonce: nonce,
            encrypted_destination,
            hit_counter: if should_count_hits { Some(0) } else { None },
            edit_password_hash,
        };

        self.write_to_db(&entry, &key)
    }

    pub fn resolve_url(&self, shortlink: &str) -> Result<Option<(String, Option<u64>)>, Error> {
        let (hasher, key) = hash_shortlink(shortlink);
        self.database
            .get(key)
            .map_err(|_| Error::DatabaseReadFailed)?
            .map(|v| {
                self.resolve_from_entry(shortlink, &key, hasher, v)
                    .map(|(r, e)| (r, e.hit_counter))
            })
            .map_or(Ok(None), |r| r.map(|v| Some(v)))
    }

    pub fn delete_url(&self, shortlink: &str, password: &str) -> Result<(), Error> {
        let (hasher, key) = hash_shortlink(shortlink);
        self.database
            .get(key)
            .map_err(|_| Error::DatabaseReadFailed)?
            .map_or(Err(Error::DoesNotExist), |v| {
                self.resolve_from_entry(shortlink, &key, hasher, v)
                    .and_then(|(_, entry)| {
                        let password_hash = hash_password(password);
                        if password_hash.eq(&entry.edit_password_hash) {
                            self.database
                                .delete(key)
                                .map_err(|_| Error::DatabaseWriteFailed)
                        } else {
                            Err(Error::InvalidPassword)
                        }
                    })
            })
    }

    fn write_to_db(&self, entry: &LinkEntry, key: &Hash) -> Result<(), Error> {
        let encoded = serde_json::to_string(&entry).map_err(|_| Error::SerializationFailed)?;
        self.database
            .put(key, encoded)
            .map_err(|_| Error::DatabaseWriteFailed)
    }

    fn resolve_from_entry(
        &self,
        shortlink: &str,
        key: &Hash,
        hasher: Hasher,
        serialized_entry: Vec<u8>,
    ) -> Result<(String, LinkEntry), Error> {
        let mut entry = std::str::from_utf8(&serialized_entry)
            .map_err(|_| Error::DeserializationFailed)
            .map(|v| {
                serde_json::from_str::<LinkEntry>(v).map_err(|_| Error::DeserializationFailed)
            })??;
        let resolved = decrypt_destination(
            shortlink,
            &entry.encrypted_destination,
            &entry.nonce,
            hasher,
        )?;

        if let Some(counter) = &mut entry.hit_counter {
            *counter += 1;
            self.write_to_db(&entry, key)?;
        }

        Ok((resolved, entry))
    }

    fn verify_unique_shortlink(&self, key: &Hash) -> Result<(), Error> {
        self.database
            .get(key)
            .map_err(|_| Error::AlreadyExists)
            .and_then(|option| option.map_or(Ok(()), |_| Err(Error::AlreadyExists)))
    }
}

fn hash_password(password: &str) -> Hash {
    *blake3::hash(password.as_bytes()).as_bytes()
}

fn hash_shortlink(shortlink: &str) -> (Hasher, Hash) {
    let mut hasher = Hasher::new();
    hasher.update(shortlink.as_bytes());
    let hash = hasher.finalize();
    let key: Hash = *hash.as_bytes();
    (hasher, key)
}

fn encrypt_destination(
    shortlink: &str,
    resolve_to: &str,
    mut hasher: Hasher,
) -> Result<(Vec<u8>, Nonce), Error> {
    hasher.update(shortlink.as_bytes());
    let hash = hasher.finalize();
    let encryption_key: &EncryptionKey = hash.as_bytes();

    let mut nonce_buffer: Nonce = [0; 12]; //96 bits
    OsRng.fill_bytes(&mut nonce_buffer);
    let nonce = AesNonce::from_slice(&nonce_buffer);

    Aes256GcmSiv::new(GenericArray::from_slice(encryption_key))
        .encrypt(GenericArray::from_slice(nonce), resolve_to.as_bytes())
        .map_err(|_| Error::EncryptionFailed)
        .and_then(|v| Ok((v, nonce_buffer)))
}

fn decrypt_destination(
    shortlink: &str,
    ciphertext: &Vec<u8>,
    nonce: &Nonce,
    mut hasher: Hasher,
) -> Result<String, Error> {
    hasher.update(shortlink.as_bytes());
    let hash = hasher.finalize();
    let encryption_key: &EncryptionKey = hash.as_bytes();

    let nonce = AesNonce::from_slice(nonce);

    Aes256GcmSiv::new(GenericArray::from_slice(encryption_key))
        .decrypt(AesNonce::from_slice(nonce), ciphertext.as_ref())
        .map_err(|_| Error::DecryptionFailed)
        .and_then(|v| String::from_utf8(v).map_err(|_| Error::DeserializationFailed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{tempdir, TempDir};

    const SHORTLINK: &str = "link-this";
    const INVALID_SHORT_LINK: &str = "does-not-exist";
    const DESTINATION_URL: &str = "https://example.com/destination";
    const PASSWORD: &str = "Password123";

    fn get_tmp_db() -> (TempDir, LinkStore) {
        let dir = tempdir().unwrap();
        let _file_path = dir.path().join("tempdb");
        let file_path = _file_path.to_str().unwrap();
        let store = LinkStore::new(file_path);
        assert!(store.is_ok());
        (dir, store.unwrap())
    }

    fn rm_temp_db(dir: TempDir) {
        dir.close().unwrap();
    }

    #[test]
    fn open_successful() {
        let (dir, _db) = get_tmp_db();
        rm_temp_db(dir);
    }

    #[test]
    fn open_fail_invalid_path() {
        let s = LinkStore::new("/this/path/does/not/exists/527/foo.db");
        assert!(s.is_err());
    }

    #[test]
    fn create_and_resolve_link() {
        let (dir, store) = get_tmp_db();

        let r = store.add_url(SHORTLINK, DESTINATION_URL, PASSWORD, true);
        assert!(r.is_ok());

        let q = store.resolve_url(SHORTLINK);
        assert!(q.is_ok());
        let queried = q.unwrap();
        assert!(queried.is_some());
        let (link, count) = queried.unwrap();
        assert_eq!(link, DESTINATION_URL);
        assert!(count.is_some());
        assert_eq!(count.unwrap(), 1);

        let delete_result = store.delete_url(SHORTLINK, PASSWORD);
        assert!(delete_result.is_ok());

        let query_deleted_result = store.resolve_url(SHORTLINK);
        assert!(query_deleted_result.is_ok());
        assert!(query_deleted_result.unwrap().is_none());

        rm_temp_db(dir);
    }

    #[test]
    fn invalid_link() {
        let (dir, store) = get_tmp_db();

        let q = store.resolve_url("does-not-exist");
        assert!(q.is_ok());
        let queried = q.unwrap();
        assert!(queried.is_none());

        let q = store.delete_url(INVALID_SHORT_LINK, PASSWORD);
        assert!(q.is_err());
        assert_eq!(q.unwrap_err(), Error::DoesNotExist);

        rm_temp_db(dir);
    }
}
