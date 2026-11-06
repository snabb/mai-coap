use crate::Error;

pub(crate) fn singleton_bit(name: &str) -> u8 {
    match name {
        "ct" => 1,
        "rt" => 2,
        "if" => 4,
        "sz" => 8,
        _ => 0,
    }
}

pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

pub(crate) fn validate_attributes(attributes: &[(&str, Option<&str>)]) -> Result<(), Error> {
    let mut seen = 0;
    for (name, value) in attributes {
        let bit = singleton_bit(name);
        if !valid_name(name) || seen & bit != 0 || value.is_some_and(|v| v.bytes().any(|b| b < 32))
        {
            return Err(Error::Malformed);
        }
        seen |= bit;
    }
    Ok(())
}
