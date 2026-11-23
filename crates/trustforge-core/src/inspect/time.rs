//! RFC 3339 formatting of Unix timestamps, without a date-time dependency.

/// Formats seconds since the Unix epoch as `YYYY-MM-DDThh:mm:ssZ` (UTC).
/// Returns `None` outside the years 0000 through 9999.
pub(crate) fn rfc3339_utc(secs: i64) -> Option<String> {
    let days = secs.div_euclid(86_400);
    let time = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    if !(0..=9999).contains(&year) {
        return None;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time / 3600,
        time % 3600 / 60,
        time % 60
    ))
}

/// Parses exactly the form [`rfc3339_utc`] writes, `YYYY-MM-DDThh:mm:ssZ`,
/// into seconds since the Unix epoch. Anything else, including an impossible
/// date such as February 30, is `None`.
pub(crate) fn parse_rfc3339_utc(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() != 20 {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let digits = bytes.get(range)?;
        digits.iter().try_fold(0i64, |n, &b| {
            b.is_ascii_digit().then(|| n * 10 + i64::from(b - b'0'))
        })
    };
    let separators = [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'Z'),
    ];
    if separators.iter().any(|&(i, c)| bytes.get(i) != Some(&c)) {
        return None;
    }
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let secs = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    // An impossible date normalizes to another day; only an exact round
    // trip is accepted.
    (rfc3339_utc(secs).as_deref() == Some(text)).then_some(secs)
}

/// The day number, counted from 1970-01-01, of a proleptic Gregorian
/// calendar date: the inverse of [`civil_from_days`] (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400; // year of era, 0..=399
    let mp = (month + 9) % 12; // month from March, 0..=11
    let doy = (153 * mp + 2) / 5 + day - 1; // day of year from March 1st
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // day of era
    era * 146_097 + doe - 719_468
}

/// The proleptic Gregorian calendar date of a day number counted from
/// 1970-01-01, after Howard Hinnant's `civil_from_days` algorithm. Valid for
/// every `i64` day number that `rfc3339_utc` can produce.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // day of era, 0..=146096
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // year of era, 0..=399
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year from March 1st, 0..=365
    let mp = (5 * doy + 2) / 153; // month from March, 0..=11
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_instants() {
        let cases = [
            (0, "1970-01-01T00:00:00Z"),
            (-1, "1969-12-31T23:59:59Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (951_868_799, "2000-02-29T23:59:59Z"),
            (1_730_678_400, "2024-11-04T00:00:00Z"),
            (4_107_542_399, "2100-02-28T23:59:59Z"),
            (4_107_542_400, "2100-03-01T00:00:00Z"),
            (-62_167_219_200, "0000-01-01T00:00:00Z"),
            (253_402_300_799, "9999-12-31T23:59:59Z"),
        ];
        for (secs, expected) in cases {
            assert_eq!(rfc3339_utc(secs).as_deref(), Some(expected), "{secs}");
        }
    }

    #[test]
    fn written_instants_parse_back() {
        for secs in [
            0,
            -1,
            951_782_400,
            1_730_678_400,
            4_107_542_400,
            -62_167_219_200,
            253_402_300_799,
        ] {
            let text = rfc3339_utc(secs).unwrap();
            assert_eq!(parse_rfc3339_utc(&text), Some(secs), "{text}");
        }
    }

    #[test]
    fn other_forms_and_impossible_dates_do_not_parse() {
        for text in [
            "2026-02-30T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-11-23T24:00:00Z",
            "2026-11-23T12:00:60Z",
            "2026-11-23T12:00:00+00:00",
            "2026-11-23 12:00:00Z",
            "2026-11-23T12:00:00z",
            "+026-11-23T12:00:00Z",
            "2026-11-23T12:00:00.5Z",
            "",
        ] {
            assert_eq!(parse_rfc3339_utc(text), None, "{text}");
        }
    }

    #[test]
    fn out_of_range_years_are_none() {
        for secs in [-62_167_219_201, 253_402_300_800, i64::MIN, i64::MAX] {
            assert_eq!(rfc3339_utc(secs), None, "{secs}");
        }
    }
}
