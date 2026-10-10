//! Bytewords（BCR-2020-012）：每个字节对应一个 4 字母单词。UR 使用 minimal 风格（首尾两个字母），
//! 末尾附加 4 字节大端 CRC-32。词表来自参考实现，测试中与 third_party/bc-ur/src/bytewords.cpp 比对。

use crate::{crc32, UrError};

/// 256 个单词首尾相接（每个 4 字母）。
pub(crate) const WORDS: &[u8; 1024] = b"ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebodybragbrewbulbbuzzcalmcashcatschefcityclawcodecolacookcostcruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasyechoedgeepicevenexamexiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglowgoodgraygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhopehornhutsicedideaidleinchinkyintoirisironitemjadejazzjoinjoltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamblavalazyleaflegsliarlimplionlistlogoloudloveluaulucklungmainmanymathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnotenumbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolposepuffpumapurrquadquizraceramprealredorichroadrockroofrubyruinrunsrustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoystriptunatwinuglyundouniturgeuservastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebswhatwhenwhizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom";

/// (首字母, 尾字母) → 字节值；-1 表示不存在。
const LOOKUP: [i16; 26 * 26] = build_lookup();

// 编译期求值：越界会成为编译错误而不是运行时 panic
#[allow(clippy::indexing_slicing)]
const fn build_lookup() -> [i16; 26 * 26] {
    let mut t = [-1i16; 26 * 26];
    let mut i = 0;
    while i < 256 {
        let first = (WORDS[i * 4] - b'a') as usize;
        let last = (WORDS[i * 4 + 3] - b'a') as usize;
        t[last * 26 + first] = i as i16;
        i += 1;
    }
    t
}

fn word(b: u8) -> &'static [u8] {
    let i = usize::from(b) * 4;
    WORDS.get(i..i + 4).unwrap_or(b"????")
}

fn lookup(first: u8, last: u8) -> Option<u8> {
    if !first.is_ascii_lowercase() || !last.is_ascii_lowercase() {
        return None;
    }
    let idx = usize::from(last - b'a') * 26 + usize::from(first - b'a');
    LOOKUP.get(idx).and_then(|&v| u8::try_from(v).ok())
}

fn with_crc(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(data.len() + 4);
    v.extend_from_slice(data);
    v.extend_from_slice(&crc32::checksum_be(data));
    v
}

fn strip_crc(mut buf: Vec<u8>) -> Result<Vec<u8>, UrError> {
    if buf.len() < 5 {
        return Err(UrError::Bytewords);
    }
    let body_len = buf.len() - 4;
    let expected = crc32::checksum_be(buf.get(..body_len).ok_or(UrError::Bytewords)?);
    if buf.get(body_len..) != Some(&expected[..]) {
        return Err(UrError::Bytewords);
    }
    buf.truncate(body_len);
    Ok(buf)
}

/// minimal 风格：每字节两个小写字母，无分隔符。
pub fn encode_minimal(data: &[u8]) -> String {
    let mut s = String::with_capacity((data.len() + 4) * 2);
    for b in with_crc(data) {
        let w = word(b);
        s.push(char::from(*w.first().unwrap_or(&b'?')));
        s.push(char::from(*w.get(3).unwrap_or(&b'?')));
    }
    s
}

pub fn decode_minimal(s: &str) -> Result<Vec<u8>, UrError> {
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return Err(UrError::Bytewords);
    }
    let buf = pairs
        .iter()
        .map(|&[f, l]| lookup(f, l).ok_or(UrError::Bytewords))
        .collect::<Result<Vec<u8>, _>>()?;
    strip_crc(buf)
}

/// standard / uri 风格：完整单词，以 `sep` 分隔。
pub fn encode_words(data: &[u8], sep: char) -> String {
    let words: Vec<&str> = with_crc(data)
        .into_iter()
        .map(|b| core::str::from_utf8(word(b)).unwrap_or("????"))
        .collect();
    words.join(&sep.to_string())
}

pub fn decode_words(s: &str, sep: char) -> Result<Vec<u8>, UrError> {
    let buf = s
        .split(sep)
        .map(|w| match w.as_bytes() {
            [a, b, c, d] => {
                let v = lookup(*a, *d).ok_or(UrError::Bytewords)?;
                let full = word(v);
                if full.get(1) == Some(b) && full.get(2) == Some(c) {
                    Ok(v)
                } else {
                    Err(UrError::Bytewords)
                }
            }
            _ => Err(UrError::Bytewords),
        })
        .collect::<Result<Vec<u8>, _>>()?;
    strip_crc(buf)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    /// 词表与参考实现源码中的字面量逐字节一致
    #[test]
    fn wordlist_matches_reference_source() {
        let cpp = include_str!("../../../../third_party/bc-ur/src/bytewords.cpp");
        let start = cpp.find("bytewords = \"").unwrap() + "bytewords = \"".len();
        let end = start + cpp[start..].find('"').unwrap();
        assert_eq!(&cpp.as_bytes()[start..end], &WORDS[..]);
    }

    #[test]
    fn every_byte_roundtrips_and_first_last_letters_are_unique() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode_minimal(&encode_minimal(&all)).unwrap(), all);
        assert!(LOOKUP.iter().filter(|&&v| v >= 0).count() == 256);
    }

    /// bc-ur test.cpp: test_bytewords_1
    #[test]
    fn reference_vector_1() {
        let input = [0u8, 1, 2, 128, 255];
        assert_eq!(
            encode_words(&input, ' '),
            "able acid also lava zoom jade need echo taxi"
        );
        assert_eq!(
            encode_words(&input, '-'),
            "able-acid-also-lava-zoom-jade-need-echo-taxi"
        );
        assert_eq!(encode_minimal(&input), "aeadaolazmjendeoti");
        assert_eq!(
            decode_words("able acid also lava zoom jade need echo taxi", ' ').unwrap(),
            input
        );
        assert_eq!(decode_minimal("aeadaolazmjendeoti").unwrap(), input);
        // 校验和错误
        assert!(decode_words("able acid also lava zero jade need echo wolf", ' ').is_err());
        assert!(decode_minimal("aeadaolazojendeowf").is_err());
        // 太短
        assert!(decode_words("wolf", ' ').is_err());
        assert!(decode_words("", ' ').is_err());
    }

    /// bc-ur test.cpp: test_bytewords_2（期望值从参考源码中解析，避免手抄错误）
    #[test]
    fn reference_vector_2() {
        let t = crate::fountain::refvec::section("test_bytewords_2");
        let input: Vec<u8> = crate::fountain::refvec::ints_after(&t, "ByteVector input = {")
            .into_iter()
            .map(|v| u8::try_from(v).unwrap())
            .collect();
        let encoded = crate::fountain::refvec::joined_strings_after(&t, "string encoded =");
        let minimal = crate::fountain::refvec::joined_strings_after(&t, "string encoded_minimal =");
        assert_eq!(input.len(), 100);
        assert_eq!(encode_words(&input, ' '), encoded);
        assert_eq!(encode_minimal(&input), minimal);
        assert_eq!(decode_minimal(&minimal).unwrap(), input);
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode_minimal("a").is_err());
        assert!(decode_minimal("AE").is_err());
        assert!(decode_minimal("zzzzzzzzzz").is_err());
        assert!(decode_minimal("你好").is_err());
    }
}
