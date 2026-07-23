#[derive(Debug, Clone, Copy)]
pub struct CborIndexVal {
    pub k: usize,
    pub v: usize,
}

#[derive(Debug, Clone)]
pub struct CborElement {
    pub value: CborValue,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone)]
pub enum CborValue {
    Integer(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborElement>),
    Map(Vec<(CborElement, CborElement)>),
    Tag(u64, Box<CborElement>),
    Simple(u8),
}

pub struct CborParser<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> CborParser<'a> {
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn read_byte(&mut self) -> Result<u8, String> {
        if self.offset >= self.data.len() {
            return Err("Unexpected EOF".to_string());
        }
        let b = self.data[self.offset];
        self.offset += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], String> {
        if self.offset + len > self.data.len() {
            return Err("Unexpected EOF".to_string());
        }
        let res = &self.data[self.offset..self.offset + len];
        self.offset += len;
        Ok(res)
    }

    pub fn parse_val(&mut self) -> Result<CborElement, String> {
        let start = self.offset;
        let b = self.read_byte()?;
        let major = b >> 5;
        let info = b & 0x1f;

        let val = match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.read_byte()?),
            25 => {
                let bytes = self.read_bytes(2)?;
                u64::from(u16::from_be_bytes([bytes[0], bytes[1]]))
            }
            26 => {
                let bytes = self.read_bytes(4)?;
                u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            }
            27 => {
                let bytes = self.read_bytes(8)?;
                u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ])
            }
            _ => return Err(format!("Unsupported length info: {info}")),
        };

        let value = match major {
            0 => CborValue::Integer(val),
            1 => CborValue::Integer(val),
            2 => {
                let bytes = self.read_bytes(val as usize)?.to_vec();
                CborValue::Bytes(bytes)
            }
            3 => {
                let bytes = self.read_bytes(val as usize)?;
                let s = String::from_utf8(bytes.to_vec()).map_err(|e| e.to_string())?;
                CborValue::Text(s)
            }
            4 => {
                let mut arr = Vec::new();
                for _ in 0..val {
                    arr.push(self.parse_val()?);
                }
                CborValue::Array(arr)
            }
            5 => {
                let mut map = Vec::new();
                for _ in 0..val {
                    let k = self.parse_val()?;
                    let v = self.parse_val()?;
                    map.push((k, v));
                }
                CborValue::Map(map)
            }
            6 => {
                let inner = self.parse_val()?;
                CborValue::Tag(val, Box::new(inner))
            }
            7 => CborValue::Simple(info),
            _ => return Err(format!("Unsupported major type: {major}")),
        };

        let end = self.offset;
        Ok(CborElement { value, start, end })
    }
}

pub fn parse_mso_cbor(data: &[u8]) -> Result<CborElement, String> {
    let mut parser = CborParser::new(data);
    let top = parser.parse_val()?;
    if let CborValue::Bytes(ref payload) = top.value {
        let mut sub_parser = CborParser::new(payload);
        let inner = sub_parser.parse_val()?;
        if let CborValue::Tag(24, ref bstr_el) = inner.value {
            if let CborValue::Bytes(ref map_bytes) = bstr_el.value {
                let mut map_parser = CborParser::new(map_bytes);
                return map_parser.parse_val();
            }
        }
    }
    Err(format!(
        "Invalid MSO structure: expected Bytes containing Tag 24 ByteString Map, got: {:?}",
        top.value
    ))
}

#[must_use]
pub fn find_key_in_map(el: &CborElement, target_key: &str) -> Option<CborIndexVal> {
    match &el.value {
        CborValue::Map(pairs) => {
            for (k, v) in pairs {
                if let CborValue::Text(s) = &k.value {
                    if s == target_key {
                        return Some(CborIndexVal {
                            k: k.start,
                            v: v.start,
                        });
                    }
                }
                if let Some(res) = find_key_in_map(v, target_key) {
                    return Some(res);
                }
            }
        }
        CborValue::Array(arr) => {
            for item in arr {
                if let Some(res) = find_key_in_map(item, target_key) {
                    return Some(res);
                }
            }
        }
        CborValue::Tag(_, inner) => {
            return find_key_in_map(inner, target_key);
        }
        _ => {}
    }
    None
}

#[must_use]
pub fn find_element_by_key(el: &CborElement, target_key: &str) -> Option<CborElement> {
    match &el.value {
        CborValue::Map(pairs) => {
            for (k, v) in pairs {
                if let CborValue::Text(s) = &k.value {
                    if s == target_key {
                        return Some(v.clone());
                    }
                }
                if let Some(res) = find_element_by_key(v, target_key) {
                    return Some(res);
                }
            }
        }
        CborValue::Array(arr) => {
            for item in arr {
                if let Some(res) = find_element_by_key(item, target_key) {
                    return Some(res);
                }
            }
        }
        CborValue::Tag(_, inner) => {
            return find_element_by_key(inner, target_key);
        }
        _ => {}
    }
    None
}

#[must_use]
pub fn find_key_element_by_key(el: &CborElement, target_key: &str) -> Option<CborElement> {
    match &el.value {
        CborValue::Map(pairs) => {
            for (k, v) in pairs {
                if let CborValue::Text(s) = &k.value {
                    if s == target_key {
                        return Some(k.clone());
                    }
                }
                if let Some(res) = find_key_element_by_key(v, target_key) {
                    return Some(res);
                }
            }
        }
        CborValue::Array(arr) => {
            for item in arr {
                if let Some(res) = find_key_element_by_key(item, target_key) {
                    return Some(res);
                }
            }
        }
        CborValue::Tag(_, inner) => {
            return find_key_element_by_key(inner, target_key);
        }
        _ => {}
    }
    None
}

#[must_use]
pub fn find_digest_offset(el: &CborElement, namespace: &str, digest_id: u64) -> Option<usize> {
    let ns_el = find_element_by_key(el, namespace)?;
    if let CborValue::Map(pairs) = &ns_el.value {
        for (k, v) in pairs {
            if let CborValue::Integer(n) = k.value {
                if n == digest_id {
                    return Some(v.start);
                }
            }
        }
    }
    None
}

#[must_use]
pub fn get_array(el: &CborElement) -> Option<&Vec<CborElement>> {
    match &el.value {
        CborValue::Array(arr) => Some(arr),
        CborValue::Tag(_, inner) => get_array(inner),
        _ => None,
    }
}

#[must_use]
pub fn get_bytes(el: &CborElement) -> Option<&Vec<u8>> {
    match &el.value {
        CborValue::Bytes(b) => Some(b),
        CborValue::Tag(_, inner) => get_bytes(inner),
        _ => None,
    }
}

#[must_use]
pub fn find_device_key_coordinate(
    device_key_map: &CborElement,
    mdoc_or_mso: &[u8],
    coordinate_byte: u8,
) -> Option<Vec<u8>> {
    if let CborValue::Map(pairs) = &device_key_map.value {
        for (k, v) in pairs {
            if mdoc_or_mso[k.start] == coordinate_byte {
                if let CborValue::Bytes(b) = &v.value {
                    return Some(b.clone());
                }
            }
        }
    }
    None
}
