use aho_corasick::AhoCorasick;

pub fn replace_builtin_rules(grammar: &mut String) -> Result<(), std::io::Error> {
    let patterns = &[
        "ASCII_DIGIT",
        "ASCII_NONZERO_DIGIT",
        "ASCII_BIN_DIGIT",
        "ASCII_OCT_DIGIT",
        "ASCII_HEX_DIGIT",
        "ASCII_ALPHA_LOWER",
        "ASCII_ALPHA_UPPER",
        "ASCII_ALPHANUMERIC",
    ];

    // Parentheses are kept to facilitate things like ASCII_ALPHA{1,5}
    let replace_with = &[
        "('0'..'9')",
        "('1'..'9')",
        "('0'..'1')",
        "('0'..'7')",
        "('0'..'9' | 'a'..'f')",
        "('a'..'z')",
        "('A'..'Z')",
        "('0'..'9' | 'a'..'z' | 'A'..'Z')",
    ];

    // Replace all strings in a single pass
    let mut wtr = vec![];
    let ac = AhoCorasick::new(patterns).unwrap();
    ac.try_stream_replace_all(grammar.as_bytes(), &mut wtr, replace_with)?;

    let mut s = match String::from_utf8(wtr) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };

    // ASCII_ALPHA it is replaced last because it has conflict with ASCII_ALPHA_LOWER/ASCII_ALPHA_UPPER
    s = s.replace("ASCII_ALPHA", "('a'..'z' | 'A'..'Z')");

    *grammar = s;

    Ok(())
}

pub fn unescape(string: &str) -> Option<Vec<u8>> {
    let mut result: Vec<u8> = Vec::new();
    let mut chars = string.chars();

    loop {
        match chars.next() {
            Some('\\') => match chars.next()? {
                '"' => result.push(b'"'),
                '\\' => result.push(b'\\'),
                'r' => result.push(b'\r'),
                'n' => result.push(b'\n'),
                't' => result.push(b'\t'),
                '0' => result.push(b'\0'),
                '\'' => result.push(b'\''),
                'x' => {
                    let string: String = chars.clone().take(2).collect();

                    if string.len() != 2 {
                        return None;
                    }

                    for _ in 0..string.len() {
                        chars.next()?;
                    }

                    let value = u8::from_str_radix(&string, 16).ok()?;

                    result.push(value);
                }
                'u' => {
                    if chars.next()? != '{' {
                        return None;
                    }

                    let string: String = chars.clone().take_while(|c| *c != '}').collect();

                    if string.len() < 2 || 6 < string.len() {
                        return None;
                    }

                    for _ in 0..string.len() + 1 {
                        chars.next()?;
                    }

                    result.append(&mut string.as_bytes().to_vec());
                }
                _ => return None,
            },
            Some(c) => result.push(c as u8),
            None => return Some(result),
        };
    }
}
