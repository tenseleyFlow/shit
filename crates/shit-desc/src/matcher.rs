// SPDX-License-Identifier: AGPL-3.0-or-later

//! Argv pattern matcher for descriptor `match.argv` (and `exclude_argv`).
//!
//! Grammar:
//! - `*` matches exactly one argv token (any value).
//! - `**` matches zero or more trailing argv tokens (must be the last
//!   element of the pattern; lint enforces this).
//! - Any other token is a literal — case-sensitive byte equality.
//!
//! Score (used for specificity ranking when multiple descriptors match):
//! - +1.0 for each literal token match.
//! - +0.5 for each `*` token match.
//! - +0.25 for `**` consuming a non-empty tail (zero-token tail still counts as a tiny positive).
//!
//! Higher score = more specific. The dispatcher picks the highest score;
//! ties resolve by authority tier elsewhere.

use super::schema::DescriptorMatch;

/// Outcome of matching one descriptor against an argv. `score` is only
/// meaningful when `matched` is true.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MatchOutcome {
    pub matched: bool,
    pub score: f32,
}

impl MatchOutcome {
    pub const NO: MatchOutcome = MatchOutcome {
        matched: false,
        score: 0.0,
    };

    pub fn yes(score: f32) -> Self {
        Self {
            matched: true,
            score,
        }
    }
}

/// Match a single pattern against an argv. Returns the score (a positive
/// f32) when matched, `MatchOutcome::NO` otherwise.
pub fn match_pattern(pattern: &[String], argv: &[String]) -> MatchOutcome {
    // argv must have at least one token (the binary name); lint ensures
    // pattern[0] is a literal so the binary name check is exact.
    if argv.is_empty() || pattern.is_empty() {
        return MatchOutcome::NO;
    }
    match_inner(pattern, argv)
}

fn match_inner(pattern: &[String], argv: &[String]) -> MatchOutcome {
    let mut p = 0usize;
    let mut a = 0usize;
    let mut score: f32 = 0.0;
    while p < pattern.len() {
        let tok = &pattern[p];
        if tok == "**" {
            // `**` consumes the remainder of argv (zero or more tokens).
            // Lint guarantees this is the last pattern element.
            let consumed = argv.len() - a;
            // Give a small bonus only when something is actually consumed.
            if consumed > 0 {
                score += 0.25 * consumed as f32;
            } else {
                score += 0.01;
            }
            return MatchOutcome::yes(score);
        }
        if a >= argv.len() {
            return MatchOutcome::NO;
        }
        if tok == "*" {
            score += 0.5;
        } else if tok == &argv[a] {
            score += 1.0;
        } else {
            return MatchOutcome::NO;
        }
        p += 1;
        a += 1;
    }
    if a == argv.len() {
        MatchOutcome::yes(score)
    } else {
        // Pattern consumed but argv has leftover tokens; no `**` to soak.
        MatchOutcome::NO
    }
}

/// Match a `DescriptorMatch` block against an argv. Honors `exclude_argv`:
/// returns `MatchOutcome::NO` if any exclude pattern matches, regardless
/// of the main argv match.
pub fn match_descriptor(dm: &DescriptorMatch, argv: &[String]) -> MatchOutcome {
    for excl in &dm.exclude_argv {
        if match_pattern(excl, argv).matched {
            return MatchOutcome::NO;
        }
    }
    match_pattern(&dm.argv, argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    // ------- single-token patterns -------

    #[test]
    fn literal_only_matches_exact() {
        let out = match_pattern(&p(&["hostname"]), &p(&["hostname"]));
        assert!(out.matched);
        assert!((out.score - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn literal_only_rejects_with_trailing_arg() {
        let out = match_pattern(&p(&["hostname"]), &p(&["hostname", "foo"]));
        assert!(!out.matched);
    }

    #[test]
    fn literal_only_rejects_different_binary() {
        let out = match_pattern(&p(&["hostname"]), &p(&["uname"]));
        assert!(!out.matched);
    }

    // ------- single-star -------

    #[test]
    fn single_star_matches_one_token() {
        let out = match_pattern(&p(&["hostname", "*"]), &p(&["hostname", "newhost"]));
        assert!(out.matched);
        // 1.0 (literal) + 0.5 (star) = 1.5
        assert!((out.score - 1.5).abs() < f32::EPSILON);
    }

    #[test]
    fn single_star_rejects_empty_tail() {
        let out = match_pattern(&p(&["hostname", "*"]), &p(&["hostname"]));
        assert!(!out.matched);
    }

    #[test]
    fn single_star_rejects_multiple_tail() {
        let out = match_pattern(
            &p(&["hostname", "*"]),
            &p(&["hostname", "newhost", "extra"]),
        );
        assert!(!out.matched);
    }

    // ------- double-star (tail) -------

    #[test]
    fn double_star_matches_zero_tail() {
        let out = match_pattern(&p(&["hostname", "**"]), &p(&["hostname"]));
        assert!(out.matched);
        // 1.0 + 0.01 for empty-tail double-star.
        assert!(out.score > 1.0 && out.score < 1.1);
    }

    #[test]
    fn double_star_matches_many_tail() {
        let out = match_pattern(
            &p(&["aws", "s3", "**"]),
            &p(&["aws", "s3", "cp", "src", "dst"]),
        );
        assert!(out.matched);
        // 1.0 + 1.0 + (0.25 * 3) = 2.75
        assert!((out.score - 2.75).abs() < 0.01);
    }

    #[test]
    fn more_literals_score_higher_than_more_globs() {
        let lit = match_pattern(&p(&["a", "b", "c"]), &p(&["a", "b", "c"]));
        let glob = match_pattern(&p(&["a", "*", "*"]), &p(&["a", "b", "c"]));
        assert!(lit.matched);
        assert!(glob.matched);
        assert!(lit.score > glob.score);
    }

    // ------- specificity invariants -------

    #[test]
    fn double_star_loses_to_explicit_literals() {
        let star = match_pattern(&p(&["aws", "**"]), &p(&["aws", "s3", "cp"]));
        let lit = match_pattern(&p(&["aws", "s3", "cp"]), &p(&["aws", "s3", "cp"]));
        assert!(lit.score > star.score);
    }

    #[test]
    fn single_star_beats_double_star_when_lengths_match() {
        let single = match_pattern(&p(&["x", "*"]), &p(&["x", "y"]));
        let double = match_pattern(&p(&["x", "**"]), &p(&["x", "y"]));
        // single = 1.0 + 0.5 = 1.5; double = 1.0 + 0.25 = 1.25.
        assert!(single.score > double.score);
    }

    // ------- exclude_argv -------

    #[test]
    fn exclude_argv_suppresses_match() {
        let dm = DescriptorMatch {
            argv: p(&["hostname", "**"]),
            exclude_argv: vec![p(&["hostname", "-h"])],
            exit_codes_count_as_success: vec![0],
        };
        let out = match_descriptor(&dm, &p(&["hostname", "-h"]));
        assert!(!out.matched);
        let out2 = match_descriptor(&dm, &p(&["hostname", "newhost"]));
        assert!(out2.matched);
    }

    #[test]
    fn empty_argv_does_not_match() {
        let out = match_pattern(&p(&["hostname"]), &[]);
        assert!(!out.matched);
    }

    #[test]
    fn empty_pattern_does_not_match() {
        let out = match_pattern(&[], &p(&["hostname"]));
        assert!(!out.matched);
    }

    #[test]
    fn binary_name_mismatch_after_glob_still_fails() {
        // The matcher anchors on the first token. Lint forbids glob in
        // pattern[0], so a malformed pattern that tries to glob the
        // binary still scores against argv[0] literally — and fails.
        let out = match_pattern(&p(&["aws", "s3", "*"]), &p(&["gcloud", "s3", "cp"]));
        assert!(!out.matched);
    }
}
