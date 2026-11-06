//! RFC 7252 §3 literal encoder and API-1 transactional writer sequence oracle.
use mai_coap::{
    codec::{Code, MessageType, OptionNumber},
    endpoint::{ResponseError, ResponseWriter},
};

#[derive(Clone, Default)]
struct Model {
    options: Vec<(u32, Vec<u8>)>,
    payload: Vec<u8>,
}
fn extension(n: usize) -> Option<(u8, Vec<u8>)> {
    Some(match n {
        0..=12 => (n as u8, vec![]),
        13..=268 => (13, vec![(n - 13) as u8]),
        269..=65_804 => (14, ((n - 269) as u16).to_be_bytes().to_vec()),
        _ => return None,
    })
}
impl Model {
    fn wire(&self, token: &[u8]) -> Option<Vec<u8>> {
        let mut result = vec![0x60 | token.len() as u8, Code::CONTENT.0, 0x12, 0x34];
        result.extend_from_slice(token);
        let mut previous = 0;
        for (number, value) in &self.options {
            let (delta, db) = extension((number - previous) as usize)?;
            let (length, lb) = extension(value.len())?;
            result.push(delta * 16 + length);
            result.extend(db);
            result.extend(lb);
            result.extend(value);
            previous = *number;
        }
        if !self.payload.is_empty() {
            result.push(0xff);
            result.extend(&self.payload);
        }
        Some(result)
    }
}
pub fn check(data: &[u8]) {
    if let Some((&first, data)) = data.split_first() {
        if first & 0x80 == 0 {
            sequence::<128>(first, data);
        } else {
            sequence::<1152>(first, data);
        }
    }
}
fn sequence<const D: usize>(first: u8, mut data: &[u8]) {
    let token = &b"token123"[..usize::from(first % 9)];
    let mut arena = [0; D];
    let mut writer = ResponseWriter::<D>::new(&mut arena, Code::CONTENT, token).unwrap();
    let mut model = Model::default();
    while data.len() >= 3 {
        let operation = data[0] % 3;
        let number = match data[1] {
            0 => 0,
            1 => 4,
            2 => 8,
            3 => 11,
            4 => 12,
            5 => 13,
            6 => 268,
            7 => 269,
            8 => 65_804,
            9 => 65_805,
            10 => u32::MAX,
            n => u32::from(n),
        };
        let length = usize::from(data[2]).min(data.len() - 3);
        let value = &data[3..3 + length];
        data = &data[3 + length..];
        let mut candidate = model.clone();
        if operation == 2 {
            candidate.payload = value.to_vec();
        } else {
            if operation == 1 {
                candidate.options.retain(|(n, _)| *n != number);
            }
            let position = candidate.options.partition_point(|(n, _)| *n <= number);
            candidate.options.insert(position, (number, value.to_vec()));
        }
        // This construction API accepts raw option values; semantic option
        // validation belongs to the receiver. Dot path segments are its exception.
        let dot = operation != 2 && matches!(number, 8 | 11) && matches!(value, b"." | b"..");
        let capacity =
            candidate.options.len() > 16 || candidate.wire(token).is_none_or(|wire| wire.len() > D);
        let expected = if dot {
            Err(ResponseError::InvalidOption)
        } else if capacity {
            Err(ResponseError::Capacity)
        } else {
            Ok(())
        };
        let actual = match operation {
            0 => writer.option(OptionNumber(number), value),
            1 => writer.set_option(OptionNumber(number), value),
            _ => writer.set_payload(value),
        };
        if dot && capacity {
            assert!(matches!(
                actual,
                Err(ResponseError::InvalidOption | ResponseError::Capacity)
            ));
        } else {
            assert_eq!(actual, expected);
        }
        if actual.is_ok() {
            model = candidate;
        }
        // Compare after refusals too: API-1 requires atomic mutations.
        let expected = model.wire(token).unwrap();
        assert_eq!(writer.payload(), model.payload);
        let mut copy = [0; D];
        let length = writer
            .encode(&mut copy, MessageType::Acknowledgement, 0x1234)
            .unwrap();
        assert_eq!(&copy[..length], expected);
        let owned = writer.to_owned().unwrap();
        let length = owned
            .encode(&mut copy, MessageType::Acknowledgement, 0x1234, token)
            .unwrap();
        assert_eq!(&copy[..length], expected);
    }
    assert_eq!(
        writer
            .finish(MessageType::Acknowledgement, 0x1234)
            .unwrap()
            .as_bytes(),
        model.wire(token).unwrap()
    );
}
