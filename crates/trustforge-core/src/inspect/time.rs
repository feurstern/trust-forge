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
    fn out_of_range_years_are_none() {
        for secs in [-62_167_219_201, 253_402_300_800, i64::MIN, i64::MAX] {
            assert_eq!(rfc3339_utc(secs), None, "{secs}");
        }
    }
}
