pub mod s0;

pub const STL_MTU: usize = 2048;

pub const STL_V0: u8 = 0x00;

pub const STL_TYPE_NULL: u8 = 0x00;
pub const STL_TYPE_APP_SIMPLE: u8 = 0x01;
pub const STL_TYPE_APP_ENCRYPTED: u8 = 0x02;
pub const STL_TYPE_HS_CLIENT_INITIAL: u8 = 0x81;
pub const STL_TYPE_HS_SERVER_CONTINUE: u8 = 0x82;
pub const STL_TYPE_HS_CLIENT_ACCEPT: u8 = 0x83;
pub const STL_TYPE_HS_SERVER_ACCEPT: u8 = 0x84;

pub const STL_SUITE_S0: u16 = 0x0000;
pub const STL_SUITE_S1: u16 = 0x0001;

pub const STL_SESSION_ID_SZ: usize = 7;

pub const STL_COOKIE_SZ: usize = 8;

pub const STL_NONCE_SZ: usize = 16;

#[derive(Default)]
#[repr(packed)]
pub struct Header {
    pub version_type: u8,
    pub session_id: [u8; STL_SESSION_ID_SZ],
}

impl Header {
    pub fn new(version: u8, type_: u8, session_id: [u8; STL_SESSION_ID_SZ]) -> Header {
        Header {
            version_type: (version << 4) | (type_ & 0x0f),
            session_id,
        }
    }

    #[inline]
    pub fn version(&self) -> u8 {
        self.version_type >> 4
    }

    #[inline]
    pub fn type_(&self) -> u8 {
        self.version_type & 0x0f
    }
}

#[repr(packed)]
pub struct HandshakeHeader {
    pub header: Header,
    pub suite: u16,
    pub cookie: [u8; STL_COOKIE_SZ],
}

#[repr(packed)]
pub struct S1AppHeader {
    pub header: Header,
    pub mac_tag: [u8; 16],
    pub seq_compact: u32,
}

#[inline]
pub fn seq_compress(seq: u64) -> u32 {
    seq as u32
}

#[inline]
pub fn seq_expand(seq_compact: u32, last_seq: u64) -> u64 {
    let diff = seq_compact.wrapping_sub(last_seq as u32);
    last_seq.wrapping_add(diff as i32 as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seq_expand() {
        assert_eq!(seq_expand(0, 0), 0x0);
        assert_eq!(seq_expand(0x7fffffff, 0), 0x7fffffff);
        assert_eq!(seq_expand(0x80000000, 0), 0xffffffff80000000);
        assert_eq!(seq_expand(0xffffffff, 0), 0xffffffffffffffff);
        assert_eq!(seq_expand(0xffffffff, 0x100000000), 0xffffffff);
        assert_eq!(seq_expand(0x00000001, 0x100000000), 0x100000001);
        assert_eq!(seq_expand(0x7fffffff, 0x123400000000), 0x12347fffffff);
    }
}
