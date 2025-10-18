use std::collections::HashSet;

use super::sources::CspSource;

pub(crate) fn format_sources<I, S>(sources: I) -> String
where
    I: IntoIterator<Item = S>,
    S: Into<CspSource>,
{
    let mut parts: Vec<String> = Vec::new();
    let mut seen = HashSet::new();

    for source in sources.into_iter() {
        let rendered = source.into().to_string();
        if rendered.is_empty() {
            continue;
        }

        if seen.insert(rendered.clone()) {
            parts.push(rendered);
        }
    }

    parts.join(" ")
}

pub(crate) fn sanitize_token_input(input: String) -> String {
    input.trim().trim_matches('\'').to_string()
}

pub(crate) fn contains_token(value: &str, token: &str) -> bool {
    value.split_whitespace().any(|existing| existing == token)
}
