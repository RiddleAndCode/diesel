extern crate mysqlclient_sys as ffi;
use crate::result::{ConnectionError, ConnectionResult};
use std::os::raw as libc;
use std::ptr::NonNull;

#[derive(Copy, Clone, Debug)]
pub enum MysqlSSLMode {
    Disabled,
    Preferred,
    Required,
    VerifyCa,
    VerifyIdentity,
}

fn ssl_mode_conn_err() -> ConnectionError {
    let msg = "Your current MySQL version does not support those SSL Mode options";
    ConnectionError::InvalidConnectionUrl(msg.into())
}

#[mysqlclient_mariadb]
#[mysqlclient_version(">=10.0.0")]
pub fn parse_ssl_mode(ssl_mode: Option<&str>) -> ConnectionResult<Option<MysqlSSLMode>> {
    Ok(match ssl_mode {
        Some(v) => Some(match v.to_lowercase().as_ref() {
            "required" => MysqlSSLMode::Required,
            "verify_ca" => MysqlSSLMode::VerifyCa,
            _ => return Err(ssl_mode_conn_err()),
        }),
        None => None,
    })
}

#[mysqlclient_mariadb]
#[mysqlclient_version(">=10.0.0")]
pub fn set_ssl_mode(
    mysql: NonNull<ffi::MYSQL>,
    ssl_mode: Option<MysqlSSLMode>,
) -> ConnectionResult<()> {
    if let Some(ref ssl_mode) = ssl_mode {
        match ssl_mode {
            MysqlSSLMode::Required | MysqlSSLMode::VerifyCa => unsafe {
                let res = ffi::mysql_options(
                    mysql.as_ptr(),
                    ffi::mysql_option::MYSQL_OPT_SSL_ENFORCE,
                    &true as *const ffi::my_bool as *const libc::c_void,
                );
                assert_eq!(res, 0);
            },
            _ => return Err(ssl_mode_conn_err()),
        };
        match ssl_mode {
            MysqlSSLMode::Required | MysqlSSLMode::VerifyCa => unsafe {
                let res = ffi::mysql_options(
                    mysql.as_ptr(),
                    ffi::mysql_option::MYSQL_OPT_SSL_VERIFY_SERVER_CERT,
                    &true as *const ffi::my_bool as *const libc::c_void,
                );
                assert_eq!(res, 0);
            },
            _ => (),
        };
    }
    Ok(())
}

#[mysqlclient_mysql]
#[mysqlclient_version(">=5.7.11")]
pub fn parse_ssl_mode(ssl_mode: Option<&str>) -> ConnectionResult<Option<MysqlSSLMode>> {
    Ok(match ssl_mode {
        Some(v) => Some(match v.to_lowercase().as_ref() {
            "disabled" => MysqlSSLMode::Disabled,
            "preferred" => MysqlSSLMode::Preferred,
            "required" => MysqlSSLMode::Required,
            "verify_ca" => MysqlSSLMode::VerifyCa,
            "verify_identity" => MysqlSSLMode::VerifyIdentity,
            _ => return Err(ssl_mode_conn_err()),
        }),
        None => None,
    })
}

#[mysqlclient_mysql]
#[mysqlclient_version(">=5.7.11")]
pub fn set_ssl_mode(
    mysql: NonNull<ffi::MYSQL>,
    ssl_mode: Option<MysqlSSLMode>,
) -> ConnectionResult<()> {
    if let Some(ref ssl_mode) = ssl_mode {
        let ssl_mode = match ssl_mode {
            MysqlSSLMode::Disabled => ffi::mysql_ssl_mode::SSL_MODE_DISABLED,
            MysqlSSLMode::Preferred => ffi::mysql_ssl_mode::SSL_MODE_PREFERRED,
            MysqlSSLMode::Required => ffi::mysql_ssl_mode::SSL_MODE_REQUIRED,
            MysqlSSLMode::VerifyCa => ffi::mysql_ssl_mode::SSL_MODE_VERIFY_CA,
            MysqlSSLMode::VerifyIdentity => ffi::mysql_ssl_mode::SSL_MODE_VERIFY_IDENTITY,
        };
        unsafe {
            let res = ffi::mysql_options(
                mysql.as_ptr(),
                ffi::mysql_option::MYSQL_OPT_SSL_MODE,
                &ssl_mode as *const ffi::mysql_ssl_mode as *const libc::c_void,
            );
            assert_eq!(res, 0);
        }
    }
    Ok(())
}

#[mysqlclient_version(">=5.6.36, <5.7.11")]
pub fn parse_ssl_mode(ssl_mode: Option<&str>) -> ConnectionResult<Option<MysqlSSLMode>> {
    Ok(match ssl_mode {
        Some(v) => Some(match v.to_lowercase().as_ref() {
            "required" => MysqlSSLMode::Required,
            _ => return Err(ssl_mode_conn_err()),
        }),
        None => None,
    })
}

#[mysqlclient_version(">=5.6.36, <5.7.11")]
pub fn set_ssl_mode(
    mysql: NonNull<ffi::MYSQL>,
    ssl_mode: Option<MysqlSSLMode>,
) -> ConnectionResult<()> {
    if let Some(ref ssl_mode) = ssl_mode {
        let ssl_mode = match ssl_mode {
            MysqlSSLMode::Required => ffi::mysql_ssl_mode::SSL_MODE_REQUIRED,
            _ => return Err(ssl_mode_conn_err()),
        };
        unsafe {
            let res = ffi::mysql_options(
                mysql.as_ptr(),
                ffi::mysql_option::MYSQL_OPT_SSL_MODE,
                &ssl_mode as *const ffi::mysql_ssl_mode as *const libc::c_void,
            );
            assert_eq!(res, 0);
        }
    }
    Ok(())
}

#[mysqlclient_version("<5.6.36")]
pub fn parse_ssl_mode(ssl_mode: Option<&str>) -> ConnectionResult<Option<MysqlSSLMode>> {
    if ssl_mode.is_some() {
        Err(ssl_mode_conn_err())
    } else {
        Ok(None)
    }
}

#[mysqlclient_version("<5.6.36")]
pub fn set_ssl_mode(
    _: NonNull<ffi::MYSQL>,
    ssl_mode: Option<MysqlSSLMode>,
) -> ConnectionResult<()> {
    if ssl_mode.is_some() {
        Err(ssl_mode_conn_err())
    } else {
        Ok(())
    }
}
