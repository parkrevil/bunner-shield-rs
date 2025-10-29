use super::*;
use crate::executor::PolicyMode;

#[test]
fn given_new_options_when_mode_then_returns_enforce() {
    let options = CspOptions::new();

    assert_eq!(options.mode(), PolicyMode::Enforce);
}

#[test]
fn given_report_only_base_when_merge_then_preserves_report_only_mode() {
    let base = CspOptions::new()
        .report_only()
        .default_src([CspSource::SelfKeyword]);
    let overlay = CspOptions::new().script_src(|script| script.sources([CspSource::None]));

    let merged = base.merge(&overlay);

    assert_eq!(merged.mode(), PolicyMode::ReportOnly);
}

#[test]
fn given_enforce_base_when_merge_report_only_overlay_then_keeps_enforce_mode() {
    let base = CspOptions::new()
        .default_src([CspSource::SelfKeyword])
        .report_to_merge_strategy(ReportToMergeStrategy::LastWins);
    let overlay = CspOptions::new().report_only().report_to("overlay");

    let merged = base.merge(&overlay);

    assert_eq!(merged.mode(), PolicyMode::Enforce);
}
