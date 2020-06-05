extern crate mysqlclient_sys as ffi;
extern crate percent_encoding;
extern crate url;

use self::percent_encoding::percent_decode;
use self::url::{Host, Url};
use std::collections::HashMap;
use std::ffi::{CStr, CString};

use crate::result::{ConnectionError, ConnectionResult};

pub struct ConnectionOptions {
    host: Option<CString>,
    user: CString,
    password: Option<CString>,
    database: Option<CString>,
    port: Option<u16>,
    unix_socket: Option<CString>,
    ssl_mode: Option<ffi::mysql_ssl_mode>,
    ssl_key: Option<CString>,
    ssl_cert: Option<CString>,
    ssl_ca: Option<CString>,
    ssl_capath: Option<CString>,
    ssl_cipher: Option<CString>,
}

impl ConnectionOptions {
    pub fn parse(database_url: &str) -> ConnectionResult<Self> {
        let url = match Url::parse(database_url) {
            Ok(url) => url,
            Err(_) => return Err(connection_url_error()),
        };

        if url.scheme() != "mysql" {
            return Err(connection_url_error());
        }

        if url.path_segments().map(Iterator::count).unwrap_or(0) > 1 {
            return Err(connection_url_error());
        }

        let query_pairs = url.query_pairs().into_owned().collect::<HashMap<_, _>>();
        if query_pairs.get("database").is_some() {
            return Err(connection_url_error());
        }

        let unix_socket = match query_pairs.get("unix_socket") {
            Some(v) => Some(CString::new(v.as_bytes())?),
            _ => None,
        };

        let ssl_key = match query_pairs.get("ssl_key") {
            Some(v) => Some(CString::new(v.as_bytes())?),
            _ => None,
        };

        let ssl_cert = match query_pairs.get("ssl_cert") {
            Some(v) => Some(CString::new(v.as_bytes())?),
            _ => None,
        };

        let ssl_ca = match query_pairs.get("ssl_ca") {
            Some(v) => Some(CString::new(v.as_bytes())?),
            _ => None,
        };

        let ssl_capath = match query_pairs.get("ssl_capath") {
            Some(v) => Some(CString::new(v.as_bytes())?),
            _ => None,
        };

        let ssl_cipher = match query_pairs.get("ssl_cipher") {
            Some(v) => Some(CString::new(v.as_bytes())?),
            _ => None,
        };

        let ssl_mode = match query_pairs.get("ssl_mode") {
            Some(v) => Some(match v.to_lowercase().as_ref() {
                "disabled" => ffi::mysql_ssl_mode::SSL_MODE_DISABLED,
                "preferred" => ffi::mysql_ssl_mode::SSL_MODE_PREFERRED,
                "required" => ffi::mysql_ssl_mode::SSL_MODE_REQUIRED,
                "verify_ca" => ffi::mysql_ssl_mode::SSL_MODE_VERIFY_CA,
                "verify_identity" => ffi::mysql_ssl_mode::SSL_MODE_VERIFY_IDENTITY,
                _ => return Err(connection_url_error()),
            }),
            _ => None,
        };

        let host = match url.host() {
            Some(Host::Ipv6(host)) => Some(CString::new(host.to_string())?),
            Some(host) if host.to_string() == "localhost" && unix_socket != None => None,
            Some(host) => Some(CString::new(host.to_string())?),
            None => None,
        };
        let user = decode_into_cstring(url.username())?;
        let password = match url.password() {
            Some(password) => Some(decode_into_cstring(password)?),
            None => None,
        };

        let database = match url.path_segments().and_then(|mut iter| iter.next()) {
            Some("") | None => None,
            Some(segment) => Some(CString::new(segment.as_bytes())?),
        };

        Ok(ConnectionOptions {
            host,
            user,
            password,
            database,
            port: url.port(),
            unix_socket,
            ssl_mode,
            ssl_key,
            ssl_cert,
            ssl_ca,
            ssl_capath,
            ssl_cipher,
        })
    }

    pub fn host(&self) -> Option<&CStr> {
        self.host.as_ref().map(|x| &**x)
    }

    pub fn user(&self) -> &CStr {
        &self.user
    }

    pub fn password(&self) -> Option<&CStr> {
        self.password.as_ref().map(|x| &**x)
    }

    pub fn database(&self) -> Option<&CStr> {
        self.database.as_ref().map(|x| &**x)
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }

    pub fn unix_socket(&self) -> Option<&CStr> {
        self.unix_socket.as_ref().map(|x| &**x)
    }

    pub fn ssl_mode(&self) -> Option<ffi::mysql_ssl_mode> {
        self.ssl_mode
    }

    pub fn ssl_key(&self) -> Option<&CStr> {
        self.ssl_key.as_ref().map(|x| &**x)
    }

    pub fn ssl_cert(&self) -> Option<&CStr> {
        self.ssl_cert.as_ref().map(|x| &**x)
    }

    pub fn ssl_ca(&self) -> Option<&CStr> {
        self.ssl_ca.as_ref().map(|x| &**x)
    }

    pub fn ssl_capath(&self) -> Option<&CStr> {
        self.ssl_capath.as_ref().map(|x| &**x)
    }

    pub fn ssl_cipher(&self) -> Option<&CStr> {
        self.ssl_cipher.as_ref().map(|x| &**x)
    }
}

fn decode_into_cstring(s: &str) -> ConnectionResult<CString> {
    let decoded = percent_decode(s.as_bytes())
        .decode_utf8()
        .map_err(|_| connection_url_error())?;
    CString::new(decoded.as_bytes()).map_err(Into::into)
}

fn connection_url_error() -> ConnectionError {
    let msg = "MySQL connection URLs must be in the form \
               `mysql://[[user]:[password]@]host[:port][/database][?<query_params>] \
               where query params include `unix_socket=<unix_socket_path>`, `ssl_mode=required`, \
               `ssl_key=<ssl_key_path>`, `ssl_cert=<ssl_cert_path>`, `ssl_ca=<ssl_ca_path>`, \
               `ssl_capath=<ssl_ca_dir_path>` and `ssl_cipher=<ssl_cipher>`";
    ConnectionError::InvalidConnectionUrl(msg.into())
}

#[test]
fn urls_with_schemes_other_than_mysql_are_errors() {
    assert!(ConnectionOptions::parse("postgres://localhost").is_err());
    assert!(ConnectionOptions::parse("http://localhost").is_err());
    assert!(ConnectionOptions::parse("file:///tmp/mysql.sock").is_err());
    assert!(ConnectionOptions::parse("socket:///tmp/mysql.sock").is_err());
    assert!(ConnectionOptions::parse("mysql://localhost?database=somedb").is_err());
    assert!(ConnectionOptions::parse("mysql://localhost").is_ok());
}

#[test]
fn urls_must_have_zero_or_one_path_segments() {
    assert!(ConnectionOptions::parse("mysql://localhost/foo/bar").is_err());
    assert!(ConnectionOptions::parse("mysql://localhost/foo").is_ok());
}

#[test]
fn first_path_segment_is_treated_as_database() {
    let foo_cstr = CString::new("foo").unwrap();
    let bar_cstr = CString::new("bar").unwrap();
    assert_eq!(
        Some(&*foo_cstr),
        ConnectionOptions::parse("mysql://localhost/foo")
            .unwrap()
            .database()
    );
    assert_eq!(
        Some(&*bar_cstr),
        ConnectionOptions::parse("mysql://localhost/bar")
            .unwrap()
            .database()
    );
    assert_eq!(
        None,
        ConnectionOptions::parse("mysql://localhost")
            .unwrap()
            .database()
    );
}

#[test]
fn userinfo_should_be_percent_decode() {
    use self::percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
    const USERINFO_ENCODE_SET: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'<')
        .add(b'>')
        .add(b'`')
        .add(b'#')
        .add(b'?')
        .add(b'{')
        .add(b'}')
        .add(b'/')
        .add(b':')
        .add(b';')
        .add(b'=')
        .add(b'@')
        .add(b'[')
        .add(b'\\')
        .add(b']')
        .add(b'^')
        .add(b'|');

    let username = "x#gfuL?4Zuj{n73m}eeJt0";
    let encoded_username = utf8_percent_encode(username, USERINFO_ENCODE_SET);

    let password = "x/gfuL?4Zuj{n73m}eeJt1";
    let encoded_password = utf8_percent_encode(password, USERINFO_ENCODE_SET);

    let db_url = format!(
        "mysql://{}:{}@localhost/bar",
        encoded_username, encoded_password
    );
    let db_url = Url::parse(&db_url).unwrap();

    let conn_opts = ConnectionOptions::parse(db_url.as_str()).unwrap();
    let username = CString::new(username.as_bytes()).unwrap();
    let password = CString::new(password.as_bytes()).unwrap();
    assert_eq!(username, conn_opts.user);
    assert_eq!(password, conn_opts.password.unwrap());
}

#[test]
fn ipv6_host_not_wrapped_in_brackets() {
    let host1 = CString::new("::1").unwrap();
    let host2 = CString::new("2001:db8:85a3::8a2e:370:7334").unwrap();

    assert_eq!(
        Some(&*host1),
        ConnectionOptions::parse("mysql://[::1]").unwrap().host()
    );
    assert_eq!(
        Some(&*host2),
        ConnectionOptions::parse("mysql://[2001:db8:85a3::8a2e:370:7334]")
            .unwrap()
            .host()
    );
}

#[test]
fn unix_socket_tests() {
    let unix_socket = "/var/run/mysqld.sock";
    let username = "foo";
    let password = "bar";
    let db_url = format!(
        "mysql://{}:{}@localhost?unix_socket={}",
        username, password, unix_socket
    );
    let conn_opts = ConnectionOptions::parse(db_url.as_str()).unwrap();
    let cstring = |s| CString::new(s).unwrap();
    assert_eq!(None, conn_opts.host);
    assert_eq!(None, conn_opts.port);
    assert_eq!(cstring(username), conn_opts.user);
    assert_eq!(cstring(password), conn_opts.password.unwrap());
    assert_eq!(
        CString::new(unix_socket).unwrap(),
        conn_opts.unix_socket.unwrap()
    );
}

#[test]
fn ssl_mode_should_be_required_or_none() {
    let conn_opts = ConnectionOptions::parse("mysql://root@localhost").unwrap();
    assert_eq!(conn_opts.ssl_mode, None);
    let conn_opts = ConnectionOptions::parse("mysql://root@localhost?ssl_mode=disabled").unwrap();
    assert_eq!(
        conn_opts.ssl_mode,
        Some(ffi::mysql_ssl_mode::SSL_MODE_DISABLED)
    );
    let conn_opts = ConnectionOptions::parse("mysql://root@localhost?ssl_mode=preferred").unwrap();
    assert_eq!(
        conn_opts.ssl_mode,
        Some(ffi::mysql_ssl_mode::SSL_MODE_PREFERRED)
    );
    let conn_opts = ConnectionOptions::parse("mysql://root@localhost?ssl_mode=required").unwrap();
    assert_eq!(
        conn_opts.ssl_mode,
        Some(ffi::mysql_ssl_mode::SSL_MODE_REQUIRED)
    );
    let conn_opts = ConnectionOptions::parse("mysql://root@localhost?ssl_mode=verify_ca").unwrap();
    assert_eq!(
        conn_opts.ssl_mode,
        Some(ffi::mysql_ssl_mode::SSL_MODE_VERIFY_CA)
    );
    let conn_opts =
        ConnectionOptions::parse("mysql://root@localhost?ssl_mode=verify_identity").unwrap();
    assert_eq!(
        conn_opts.ssl_mode,
        Some(ffi::mysql_ssl_mode::SSL_MODE_VERIFY_IDENTITY)
    );
    let conn_res = ConnectionOptions::parse("mysql://root@localhost?ssl_mode=invalid");
    assert_eq!(conn_res.err(), Some(connection_url_error()))
}

#[test]
fn ssl_options_should_populate() {
    let ssl_key = "/etc/ssl/client-key.pem";
    let ssl_cert = "/etc/ssl/client-cert.pem";
    let ssl_ca = "/etc/ssl/ca.pem";
    let ssl_capath = "/etc/ssl";
    let ssl_cipher = "TLSv1.2";
    let conn_opts = ConnectionOptions::parse(&format!(
        "mysql://root@localhost?ssl_key={}&ssl_cert={}&ssl_ca={}&ssl_capath={}&ssl_cipher={}",
        ssl_key, ssl_cert, ssl_ca, ssl_capath, ssl_cipher
    ))
    .unwrap();
    let cstring = |s| CString::new(s).unwrap();
    assert_eq!(cstring(ssl_key), conn_opts.ssl_key.unwrap());
    assert_eq!(cstring(ssl_cert), conn_opts.ssl_cert.unwrap());
    assert_eq!(cstring(ssl_ca), conn_opts.ssl_ca.unwrap());
    assert_eq!(cstring(ssl_capath), conn_opts.ssl_capath.unwrap());
    assert_eq!(cstring(ssl_cipher), conn_opts.ssl_cipher.unwrap());
}
