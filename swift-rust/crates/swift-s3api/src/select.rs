// Copyright (c) 2026 OpenStack Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Bounded CSV S3 Select: `*` / `_N` projection, `AND` of `col = lit`, `LIMIT`.
//! Not a SQL engine. Not JSON or Parquet.

const LIMIT_MAX: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectProjection {
    Star,
    Columns(Vec<usize>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectPredicate {
    pub column: usize,
    pub literal: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectPlan {
    pub projection: SelectProjection,
    pub predicates: Vec<SelectPredicate>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(String),
    Quoted(String),
}

pub fn extract_select_expression(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let lower = text.to_ascii_lowercase();
    if let Some(start) = lower.find("<expression>") {
        let rest = &text[start + "<expression>".len()..];
        let rest_l = rest.to_ascii_lowercase();
        if let Some(end) = rest_l.find("</expression>") {
            return rest[..end].trim().to_string();
        }
    }
    text.trim().to_string()
}

pub fn parse_select_expression(body: &[u8]) -> Option<SelectPlan> {
    parse_select_expr(&extract_select_expression(body))
}

fn parse_select_expr(expr: &str) -> Option<SelectPlan> {
    let toks = tokenize(expr)?;
    if toks.iter().any(is_unsupported_word) {
        return None;
    }
    let mut i = 0;
    expect_word(&toks, &mut i, "SELECT")?;
    let projection = parse_projection(&toks, &mut i)?;
    expect_word(&toks, &mut i, "FROM")?;
    expect_word(&toks, &mut i, "S3OBJECT")?;
    if let Some(Tok::Word(alias)) = toks.get(i) {
        if is_ident(alias) && !is_reserved_alias(alias) {
            i += 1;
        }
    }
    let mut predicates = Vec::new();
    if next_is_word(&toks, i, "WHERE") {
        i += 1;
        loop {
            predicates.push(parse_predicate(&toks, &mut i)?);
            if next_is_word(&toks, i, "AND") {
                i += 1;
                continue;
            }
            break;
        }
    }
    let mut limit = None;
    if next_is_word(&toks, i, "LIMIT") {
        i += 1;
        limit = Some(parse_limit(toks.get(i)?)?);
        i += 1;
    }
    if i != toks.len() {
        return None;
    }
    Some(SelectPlan {
        projection,
        predicates,
        limit,
    })
}

fn tokenize(expr: &str) -> Option<Vec<Tok>> {
    let chars: Vec<char> = expr.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() || c == ',' || c == ';' {
            i += 1;
            continue;
        }
        if c == '\'' || c == '"' {
            i += 1;
            let mut inner = String::new();
            let mut closed = false;
            while i < chars.len() {
                if chars[i] == c {
                    closed = true;
                    i += 1;
                    break;
                }
                inner.push(chars[i]);
                i += 1;
            }
            if !closed {
                return None;
            }
            out.push(Tok::Quoted(inner));
            continue;
        }
        if c == '=' {
            out.push(Tok::Word("=".to_string()));
            i += 1;
            continue;
        }
        let mut word = String::new();
        while i < chars.len() {
            let d = chars[i];
            if d.is_whitespace() || d == ',' || d == ';' || d == '=' || d == '\'' || d == '"' {
                break;
            }
            word.push(d);
            i += 1;
        }
        if !word.is_empty() {
            out.push(Tok::Word(word));
        }
    }
    Some(out)
}

fn parse_projection(toks: &[Tok], i: &mut usize) -> Option<SelectProjection> {
    if next_is_word(toks, *i, "*") {
        *i += 1;
        return Some(SelectProjection::Star);
    }
    let mut cols = vec![parse_column(toks.get(*i)?)?];
    *i += 1;
    while let Some(tok) = toks.get(*i) {
        if parse_column(tok).is_none() {
            break;
        }
        cols.push(parse_column(tok)?);
        *i += 1;
    }
    Some(SelectProjection::Columns(cols))
}

fn parse_predicate(toks: &[Tok], i: &mut usize) -> Option<SelectPredicate> {
    let column = parse_column(toks.get(*i)?)?;
    *i += 1;
    expect_word(toks, i, "=")?;
    let literal = parse_literal(toks.get(*i)?)?;
    *i += 1;
    Some(SelectPredicate { column, literal })
}

fn parse_column(tok: &Tok) -> Option<usize> {
    let Tok::Word(w) = tok else {
        return None;
    };
    let name = if let Some((alias, rest)) = w.split_once('.') {
        if !is_ident(alias) {
            return None;
        }
        rest
    } else {
        w.as_str()
    };
    if !name.starts_with('_') {
        return None;
    }
    let digits = &name[1..];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: usize = digits.parse().ok()?;
    (n >= 1).then_some(n)
}

fn parse_literal(tok: &Tok) -> Option<String> {
    match tok {
        Tok::Quoted(s) => Some(s.clone()),
        Tok::Word(w) if is_integer_token(w) => Some(w.clone()),
        _ => None,
    }
}

fn parse_limit(tok: &Tok) -> Option<usize> {
    let Tok::Word(w) = tok else {
        return None;
    };
    let n: usize = w.parse().ok()?;
    (1..=LIMIT_MAX).contains(&n).then_some(n)
}

fn is_integer_token(w: &str) -> bool {
    let s = w.strip_prefix('-').unwrap_or(w);
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn expect_word(toks: &[Tok], i: &mut usize, want: &str) -> Option<()> {
    if next_is_word(toks, *i, want) {
        *i += 1;
        Some(())
    } else {
        None
    }
}

fn next_is_word(toks: &[Tok], i: usize, want: &str) -> bool {
    match toks.get(i) {
        Some(Tok::Word(w)) => w.eq_ignore_ascii_case(want),
        _ => false,
    }
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {
            chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        _ => false,
    }
}

fn is_reserved_alias(s: &str) -> bool {
    matches!(
        s.to_ascii_uppercase().as_str(),
        "LIMIT"
            | "WHERE"
            | "JOIN"
            | "GROUP"
            | "BY"
            | "OR"
            | "LIKE"
            | "AND"
            | "HAVING"
            | "ORDER"
            | "UNION"
            | "ON"
            | "AS"
            | "SELECT"
            | "FROM"
            | "S3OBJECT"
    )
}

fn is_unsupported_word(tok: &Tok) -> bool {
    let Tok::Word(w) = tok else {
        return false;
    };
    matches!(
        w.to_ascii_uppercase().as_str(),
        "JOIN" | "OR" | "LIKE" | "GROUP" | "HAVING" | "<" | ">" | "<=" | ">="
    )
}

/// WHERE compares trimmed field text to the literal as written (quoted
/// inners unquoted). Integer lits use exact decimal-token equality, not
/// numeric: `2` matches `2`, not `02`.
pub fn apply_select_plan(payload: &[u8], plan: &SelectPlan) -> Vec<u8> {
    if payload.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut taken = 0usize;
    let limit = plan.limit.unwrap_or(usize::MAX);
    for line in payload.split_inclusive(|&b| b == b'\n') {
        if taken >= limit {
            break;
        }
        let has_nl = line.ends_with(&[b'\n']);
        let mut row = if has_nl {
            &line[..line.len() - 1]
        } else {
            line
        };
        if row.ends_with(&[b'\r']) {
            row = &row[..row.len() - 1];
        }
        let text = String::from_utf8_lossy(row);
        let fields = split_csv_fields(&text);
        if !plan.predicates.iter().all(|p| row_matches(&fields, p)) {
            continue;
        }
        match &plan.projection {
            SelectProjection::Star => {
                out.extend_from_slice(row);
                if has_nl {
                    out.push(b'\n');
                }
            }
            SelectProjection::Columns(cols) => {
                for (n, idx) in cols.iter().enumerate() {
                    if n > 0 {
                        out.push(b',');
                    }
                    if let Some(field) = fields.get(*idx - 1) {
                        out.extend_from_slice(field.as_bytes());
                    }
                }
                out.push(b'\n');
            }
        }
        taken += 1;
    }
    out
}

fn row_matches(fields: &[String], pred: &SelectPredicate) -> bool {
    fields
        .get(pred.column - 1)
        .map(|s| s.trim() == pred.literal)
        .unwrap_or(false)
}

fn split_csv_fields(row: &str) -> Vec<String> {
    let chars: Vec<char> = row.chars().collect();
    let mut fields = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '"' {
            if let Some(end) = quoted_field_end(&chars, i) {
                fields.push(chars[i + 1..end].iter().collect());
                i = end + 1;
                if i < chars.len() && chars[i] == ',' {
                    i += 1;
                }
                continue;
            }
        }
        let start = i;
        while i < chars.len() && chars[i] != ',' {
            i += 1;
        }
        fields.push(chars[start..i].iter().collect());
        if i < chars.len() && chars[i] == ',' {
            i += 1;
        }
    }
    if row.ends_with(',') {
        fields.push(String::new());
    }
    fields
}

fn quoted_field_end(chars: &[char], start: usize) -> Option<usize> {
    let mut i = start + 1;
    while i < chars.len() {
        if chars[i] == '"' {
            let next = i + 1;
            if next == chars.len() || chars[next] == ',' {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(expr: &str) -> SelectPlan {
        parse_select_expr(expr).expect(expr)
    }

    #[test]
    fn parse_star() {
        assert_eq!(
            plan("SELECT * FROM S3Object").projection,
            SelectProjection::Star
        );
        assert!(parse_select_expression(
            b"<SelectRequest><Expression>SELECT * FROM S3Object</Expression></SelectRequest>"
        )
        .is_some());
    }

    #[test]
    fn parse_limit() {
        assert_eq!(plan("SELECT * FROM S3Object LIMIT 2").limit, Some(2));
        assert_eq!(plan("SELECT * FROM S3Object s LIMIT 2").limit, Some(2));
        assert!(parse_select_expr("SELECT * FROM S3Object LIMIT 0").is_none());
        assert!(parse_select_expr("SELECT * FROM S3Object LIMIT 1000001").is_none());
    }

    #[test]
    fn parse_projection() {
        assert_eq!(
            plan("SELECT _1 FROM S3Object").projection,
            SelectProjection::Columns(vec![1])
        );
        assert_eq!(
            plan("SELECT _1, _3 FROM S3Object").projection,
            SelectProjection::Columns(vec![1, 3])
        );
        assert_eq!(
            plan("SELECT _1,_3 FROM S3Object").projection,
            SelectProjection::Columns(vec![1, 3])
        );
    }

    #[test]
    fn parse_where() {
        let p = plan("SELECT _1 FROM S3Object WHERE _2 = 'blue'");
        assert_eq!(p.projection, SelectProjection::Columns(vec![1]));
        assert_eq!(
            p.predicates,
            vec![SelectPredicate {
                column: 2,
                literal: "blue".into(),
            }]
        );
    }

    #[test]
    fn parse_where_limit() {
        let p = plan("SELECT * FROM S3Object WHERE _1 = 'red' LIMIT 1");
        assert_eq!(p.projection, SelectProjection::Star);
        assert_eq!(p.predicates[0].literal, "red");
        assert_eq!(p.limit, Some(1));
    }

    #[test]
    fn parse_alias() {
        assert_eq!(
            plan("SELECT s._2 FROM S3Object s").projection,
            SelectProjection::Columns(vec![2])
        );
    }

    #[test]
    fn reject_join() {
        assert!(parse_select_expr("SELECT * FROM S3Object JOIN x").is_none());
    }

    #[test]
    fn reject_or() {
        assert!(parse_select_expr("SELECT * FROM S3Object WHERE _1 = 'a' OR _2 = 'b'").is_none());
    }

    #[test]
    fn reject_like() {
        assert!(parse_select_expr("SELECT * FROM S3Object WHERE _1 LIKE 'a'").is_none());
    }

    #[test]
    fn reject_header_name() {
        assert!(parse_select_expr("SELECT _name FROM S3Object").is_none());
        assert!(parse_select_expr("SELECT name FROM S3Object").is_none());
    }

    #[test]
    fn apply_projection() {
        let p = plan("SELECT _1, _3 FROM S3Object");
        assert_eq!(
            apply_select_plan(b"red,1,x\nblue,2,y\n", &p),
            b"red,x\nblue,y\n"
        );
        assert_eq!(apply_select_plan(b"red\n", &p), b"red,\n");
    }

    #[test]
    fn apply_where_match() {
        let p = plan("SELECT _1 FROM S3Object WHERE _2 = '2'");
        assert_eq!(
            apply_select_plan(b"red,1\nblue,2\ngreen,3\n", &p),
            b"blue\n"
        );
    }

    #[test]
    fn apply_where_miss() {
        let p = plan("SELECT _1 FROM S3Object WHERE _2 = '9'");
        assert_eq!(apply_select_plan(b"red,1\nblue,2\n", &p), b"");
    }

    #[test]
    fn apply_limit_after_where() {
        let p = plan("SELECT * FROM S3Object WHERE _2 = 'keep' LIMIT 1");
        assert_eq!(
            apply_select_plan(b"a,keep\nb,skip\nc,keep\n", &p),
            b"a,keep\n"
        );
    }
}
