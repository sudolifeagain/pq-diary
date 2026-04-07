//! Template variable extraction and expansion engine.
//!
//! Parses `{{var_name}}` patterns from template bodies, classifies each variable
//! as [`VariableKind::Builtin`] (`date`, `datetime`, `title`) or
//! [`VariableKind::Custom`], and substitutes them with caller-supplied values.

use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Builtin variable name: current date in `YYYY-MM-DD` format.
pub const BUILTIN_DATE: &str = "date";
/// Builtin variable name: current datetime in `YYYY-MM-DD HH:MM:SS` format.
pub const BUILTIN_DATETIME: &str = "datetime";
/// Builtin variable name: entry title.
pub const BUILTIN_TITLE: &str = "title";

const BUILTIN_NAMES: &[&str] = &[BUILTIN_DATE, BUILTIN_DATETIME, BUILTIN_TITLE];

/// Kind of a template variable.
#[derive(Debug, PartialEq)]
pub enum VariableKind {
    /// System-assigned variable: `{{date}}`, `{{datetime}}`, or `{{title}}`.
    Builtin,
    /// User-supplied variable: any `{{name}}` not in the builtin set.
    Custom,
}

/// A reference to a `{{var_name}}` occurrence within a template body.
#[derive(Debug)]
pub struct VariableRef {
    /// Variable name (the content between `{{` and `}}`).
    pub name: String,
    /// Whether the variable is a builtin or custom.
    pub kind: VariableKind,
    /// Byte offset of the opening `{{` in the original body string.
    pub offset: usize,
}

/// Returns a reference to the compiled variable regex, initialised at most once.
fn var_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Infallible: pattern is a compile-time literal that always compiles.
        Regex::new(r"\{\{(\w+)\}\}").unwrap_or_else(|_| unreachable!())
    })
}

/// Extract all `{{var_name}}` references from `body`.
///
/// Variables are returned in the order they appear. Duplicate variable names
/// produce one [`VariableRef`] per occurrence.  Empty `{{}}` patterns are
/// silently ignored because `\w+` requires at least one word character.
///
/// # Examples
///
/// ```
/// use pq_diary_core::template_engine::{extract_variables, VariableKind};
///
/// let refs = extract_variables("日付: {{date}}");
/// assert_eq!(refs.len(), 1);
/// assert_eq!(refs[0].name, "date");
/// assert!(matches!(refs[0].kind, VariableKind::Builtin));
/// ```
pub fn extract_variables(body: &str) -> Vec<VariableRef> {
    var_regex()
        .captures_iter(body)
        .filter_map(|cap| {
            let m = cap.get(0)?;
            let name = cap.get(1)?.as_str().to_string();
            let kind = if BUILTIN_NAMES.contains(&name.as_str()) {
                VariableKind::Builtin
            } else {
                VariableKind::Custom
            };
            Some(VariableRef {
                name,
                kind,
                offset: m.start(),
            })
        })
        .collect()
}

/// Expand all `{{var_name}}` occurrences in `body` using the provided map.
///
/// Each `{{name}}` is replaced by `vars[name]`.  Variables whose names are not
/// present in `vars` are left unchanged (i.e. the `{{name}}` literal is kept).
///
/// The result is always a new `String`; the caller is responsible for zeroizing
/// it if the content is considered secret.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use pq_diary_core::template_engine::expand;
///
/// let mut vars = HashMap::new();
/// vars.insert("date".to_string(), "2026-04-05".to_string());
/// let result = expand("日付: {{date}}", &vars);
/// assert_eq!(result, "日付: 2026-04-05");
/// ```
pub fn expand(body: &str, vars: &HashMap<String, String>) -> String {
    var_regex()
        .replace_all(body, |caps: &regex::Captures| match caps.get(1) {
            Some(name_match) => vars
                .get(name_match.as_str())
                .cloned()
                .unwrap_or_else(|| caps.get(0).map_or_else(String::new, |m| m.as_str().to_string())),
            None => caps.get(0).map_or_else(String::new, |m| m.as_str().to_string()),
        })
        .into_owned()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // TC-043-01: 基本変数 {{date}} の抽出
    // =========================================================================

    /// TC-043-01: extract_variables finds {{date}} and classifies it as Builtin.
    #[test]
    fn tc_043_01_extract_builtin_date() {
        let refs = extract_variables("日付: {{date}}");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "date");
        assert!(
            matches!(refs[0].kind, VariableKind::Builtin),
            "date must be Builtin"
        );
    }

    // =========================================================================
    // TC-043-02: カスタム変数の抽出
    // =========================================================================

    /// TC-043-02: extract_variables finds {{project_name}} and classifies it as Custom.
    #[test]
    fn tc_043_02_extract_custom_variable() {
        let refs = extract_variables("PJ: {{project_name}}");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "project_name");
        assert!(
            matches!(refs[0].kind, VariableKind::Custom),
            "project_name must be Custom"
        );
    }

    // =========================================================================
    // TC-043-03: 基本変数の展開
    // =========================================================================

    /// TC-043-03: expand substitutes {{date}} with the provided value.
    #[test]
    fn tc_043_03_expand_builtin_date() {
        let mut vars = HashMap::new();
        vars.insert("date".to_string(), "2026-04-05".to_string());
        let result = expand("日付: {{date}}", &vars);
        assert_eq!(result, "日付: 2026-04-05");
    }

    // =========================================================================
    // TC-043-04: 同一変数の複数出現
    // =========================================================================

    /// TC-043-04: expand replaces every occurrence of {{date}}.
    #[test]
    fn tc_043_04_expand_repeated_variable() {
        let mut vars = HashMap::new();
        vars.insert("date".to_string(), "2026-04-05".to_string());
        let result = expand("{{date}} メモ\n---\n{{date}} 終了", &vars);
        assert_eq!(result, "2026-04-05 メモ\n---\n2026-04-05 終了");
    }

    // =========================================================================
    // TC-043-05: 変数なしテンプレート
    // =========================================================================

    /// TC-043-05: extract_variables on plain text returns an empty Vec.
    #[test]
    fn tc_043_05_extract_no_variables() {
        let refs = extract_variables("固定テキスト");
        assert!(refs.is_empty(), "no variables expected in plain text");
    }

    // =========================================================================
    // TC-043-06: 空中括弧 {{}} の処理
    // =========================================================================

    /// TC-043-06: empty {{}} does not match because \w+ requires at least one
    /// word character.
    #[test]
    fn tc_043_06_empty_braces_ignored() {
        let refs = extract_variables("テスト {{}}");
        assert!(refs.is_empty(), "{{}} must not produce a VariableRef");
    }

    // =========================================================================
    // TC-043-07: 複数種類の変数混在
    // =========================================================================

    /// TC-043-07: extract_variables handles a mix of Builtin and Custom variables.
    #[test]
    fn tc_043_07_mixed_variable_kinds() {
        let refs = extract_variables("{{date}} - {{project_name}} by {{title}}");
        assert_eq!(refs.len(), 3);
        assert!(matches!(refs[0].kind, VariableKind::Builtin), "date→Builtin");
        assert!(
            matches!(refs[1].kind, VariableKind::Custom),
            "project_name→Custom"
        );
        assert!(
            matches!(refs[2].kind, VariableKind::Builtin),
            "title→Builtin"
        );
        assert_eq!(refs[0].name, "date");
        assert_eq!(refs[1].name, "project_name");
        assert_eq!(refs[2].name, "title");
    }

    // =========================================================================
    // Additional: 未定義変数はそのまま残る
    // =========================================================================

    /// Undefined variables in expand are left as-is.
    #[test]
    fn expand_undefined_variable_kept() {
        let vars: HashMap<String, String> = HashMap::new();
        let result = expand("{{unknown}} stays", &vars);
        assert_eq!(result, "{{unknown}} stays");
    }

    // =========================================================================
    // Additional: datetime と title も Builtin として認識される
    // =========================================================================

    /// datetime and title are also recognized as Builtin.
    #[test]
    fn extract_datetime_and_title_are_builtin() {
        let refs = extract_variables("{{datetime}} {{title}}");
        assert_eq!(refs.len(), 2);
        assert!(matches!(refs[0].kind, VariableKind::Builtin));
        assert!(matches!(refs[1].kind, VariableKind::Builtin));
        assert_eq!(refs[0].name, "datetime");
        assert_eq!(refs[1].name, "title");
    }

    // =========================================================================
    // Additional: offset フィールドが正しい値を持つ
    // =========================================================================

    /// VariableRef.offset holds the correct byte position of {{.
    #[test]
    fn extract_variable_offset_is_correct() {
        // "abc " is 4 bytes, so {{date}} starts at byte 4
        let refs = extract_variables("abc {{date}}");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].offset, 4);
    }
}
