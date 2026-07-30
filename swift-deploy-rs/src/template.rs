use anyhow::{Context, Result, bail};
use minijinja::value::Value as JinjaValue;
use minijinja::{Environment, Error, ErrorKind, UndefinedBehavior};
use serde_json::Value;

/// Strict Jinja-compatible renderer for the syntax used by the selected v3
/// deployment bundle.
pub struct Renderer {
    environment: Environment<'static>,
}

impl Renderer {
    #[must_use]
    pub fn new() -> Self {
        let mut environment = Environment::new();
        environment.set_undefined_behavior(UndefinedBehavior::Strict);
        environment.set_keep_trailing_newline(true);
        environment.add_filter("intersect", intersect);
        environment.add_test("failed", |value: JinjaValue| {
            value
                .get_attr("failed")
                .is_ok_and(|failed| failed.is_true())
        });
        environment.set_unknown_method_callback(python_method);
        Self { environment }
    }

    /// Render a Jinja template string using a JSON-compatible context.
    pub fn render_str(&self, source: &str, context: &Value) -> Result<String> {
        self.environment
            .render_str(source, context)
            .with_context(|| format!("render template {source:?}"))
    }

    /// Evaluate a task condition with strict undefined-variable behavior.
    pub fn eval_bool(&self, expression: &str, context: &Value) -> Result<bool> {
        let rendered;
        let expression = if exact_expression(expression).is_none()
            && (expression.contains("{{") || expression.contains("{%"))
        {
            rendered = self.render_str(expression, context)?;
            rendered.trim()
        } else {
            strip_expression_markers(expression)
        };
        let compiled = self
            .environment
            .compile_expression(expression)
            .with_context(|| format!("compile expression {expression:?}"))?;
        Ok(compiled
            .eval(context)
            .with_context(|| format!("evaluate expression {expression:?}"))?
            .is_true())
    }

    /// Evaluate an expression while preserving its JSON-compatible type.
    pub fn eval_value(&self, expression: &str, context: &Value) -> Result<Value> {
        let expression = strip_expression_markers(expression);
        let compiled = self
            .environment
            .compile_expression(expression)
            .with_context(|| format!("compile expression {expression:?}"))?;
        let value = compiled
            .eval(context)
            .with_context(|| format!("evaluate expression {expression:?}"))?;
        serde_json::to_value(value).context("convert rendered value to JSON")
    }

    /// Resolve nested Jinja-valued variables to a stable context. Exact
    /// `{{ expression }}` values retain booleans, numbers, lists, and maps.
    pub fn resolve_context(&self, context: &Value) -> Result<Value> {
        let mut resolved = context.clone();
        for _ in 0..32 {
            let next = self.resolve_once(&resolved, &resolved)?;
            if next == resolved {
                return Ok(next);
            }
            resolved = next;
        }
        bail!("template variable resolution did not converge after 32 passes")
    }

    /// Render a JSON value recursively against an already resolved context.
    pub fn render_value(&self, value: &Value, context: &Value) -> Result<Value> {
        self.resolve_once(value, context)
    }

    fn resolve_once(&self, value: &Value, context: &Value) -> Result<Value> {
        match value {
            Value::String(source) => {
                if exact_expression(source).is_some() {
                    self.eval_value(source, context)
                } else if source.contains("{{") || source.contains("{%") {
                    Ok(Value::String(self.render_str(source, context)?))
                } else {
                    Ok(value.clone())
                }
            }
            Value::Array(values) => values
                .iter()
                .map(|item| self.resolve_once(item, context))
                .collect::<Result<Vec<_>>>()
                .map(Value::Array),
            Value::Object(values) => values
                .iter()
                .map(|(key, item)| Ok((key.clone(), self.resolve_once(item, context)?)))
                .collect::<Result<serde_json::Map<_, _>>>()
                .map(Value::Object),
            _ => Ok(value.clone()),
        }
    }
}

impl Default for Renderer {
    fn default() -> Self {
        Self::new()
    }
}

fn strip_expression_markers(expression: &str) -> &str {
    let trimmed = expression.trim();
    exact_expression(trimmed).unwrap_or(trimmed)
}

fn exact_expression(source: &str) -> Option<&str> {
    // Only a string that is ONE expression counts: after stripping the outer
    // markers the inside must not contain further jinja delimiters, or a
    // string like "{{ a }}:{{ b }}" would be mangled into "a }}:{{ b" and
    // crash the expression lexer. Multi-part strings render as templates.
    source
        .trim()
        .strip_prefix("{{")
        .and_then(|value| value.strip_suffix("}}"))
        .map(str::trim)
        .filter(|inner| {
            !inner.contains("{{") && !inner.contains("}}") && !inner.contains("{%")
        })
}

fn intersect(left: JinjaValue, right: JinjaValue) -> Result<JinjaValue, Error> {
    let right_values = right.try_iter()?.collect::<Vec<_>>();
    let mut result = Vec::new();
    for item in left.try_iter()? {
        if right_values.contains(&item) && !result.contains(&item) {
            result.push(item);
        }
    }
    Ok(JinjaValue::from(result))
}

fn python_method(
    _state: &minijinja::State<'_, '_>,
    value: &JinjaValue,
    method: &str,
    arguments: &[JinjaValue],
) -> Result<JinjaValue, Error> {
    match method {
        "split" => {
            let source = string_value(value, method)?;
            if arguments.len() > 1 {
                return Err(invalid_method_call(method, "expected zero or one argument"));
            }
            let parts: Vec<String> = if let Some(separator) = arguments.first() {
                let separator = string_value(separator, method)?;
                if separator.is_empty() {
                    return Err(invalid_method_call(method, "separator must not be empty"));
                }
                source.split(separator).map(str::to_owned).collect()
            } else {
                source.split_whitespace().map(str::to_owned).collect()
            };
            Ok(JinjaValue::from(parts))
        }
        "find" => {
            if arguments.len() != 1 {
                return Err(invalid_method_call(method, "expected one argument"));
            }
            let source = string_value(value, method)?;
            let needle = string_value(&arguments[0], method)?;
            let index = source
                .find(needle)
                .and_then(|position| i64::try_from(position).ok())
                .unwrap_or(-1);
            Ok(JinjaValue::from(index))
        }
        "join" => {
            if arguments.len() != 1 {
                return Err(invalid_method_call(
                    method,
                    "expected one iterable argument",
                ));
            }
            let separator = string_value(value, method)?;
            let joined = arguments[0]
                .try_iter()?
                .map(|item| item.to_string())
                .collect::<Vec<_>>()
                .join(separator);
            Ok(JinjaValue::from(joined))
        }
        "lower" => {
            if !arguments.is_empty() {
                return Err(invalid_method_call(method, "expected no arguments"));
            }
            Ok(JinjaValue::from(
                string_value(value, method)?.to_lowercase(),
            ))
        }
        "strip" => {
            if !arguments.is_empty() {
                return Err(invalid_method_call(
                    method,
                    "only whitespace stripping is supported",
                ));
            }
            Ok(JinjaValue::from(
                string_value(value, method)?.trim().to_owned(),
            ))
        }
        "replace" => {
            if arguments.len() != 2 {
                return Err(invalid_method_call(method, "expected old and new strings"));
            }
            let source = string_value(value, method)?;
            let old = string_value(&arguments[0], method)?;
            let new = string_value(&arguments[1], method)?;
            Ok(JinjaValue::from(source.replace(old, new)))
        }
        "get" => {
            if !(1..=2).contains(&arguments.len()) {
                return Err(invalid_method_call(
                    method,
                    "expected key and optional default",
                ));
            }
            let found = value.get_item(&arguments[0])?;
            if found.is_undefined() {
                Ok(arguments.get(1).cloned().unwrap_or(JinjaValue::UNDEFINED))
            } else {
                Ok(found)
            }
        }
        _ => Err(Error::from(ErrorKind::UnknownMethod)),
    }
}

fn string_value<'a>(value: &'a JinjaValue, method: &str) -> Result<&'a str, Error> {
    value
        .as_str()
        .ok_or_else(|| invalid_method_call(method, "receiver and arguments must be strings"))
}

fn invalid_method_call(method: &str, detail: &str) -> Error {
    Error::new(
        ErrorKind::InvalidOperation,
        format!("invalid .{method}() call: {detail}"),
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn expression_markers_are_optional() {
        let renderer = Renderer::new();
        assert!(
            renderer
                .eval_bool("{{ enabled }}", &json!({"enabled": true}))
                .expect("expression")
        );
    }

    #[test]
    fn multi_expression_strings_render_as_templates() {
        // "{{ a }}:{{ b }}" must NOT be treated as one bare expression
        // (stripping the outer markers would feed "a }}:{{ b" to the
        // expression lexer and panic it) — it renders as a template.
        let renderer = Renderer::new();
        let ctx = json!({"a": "acct", "b": "user"});
        let out = renderer
            .render_value(&json!("{{ a }}:{{ b }}"), &ctx)
            .expect("multi-expression string renders");
        assert_eq!(out, json!("acct:user"));
        // a single exact expression still evaluates to its typed value
        let out = renderer
            .render_value(&json!("{{ a }}"), &ctx)
            .expect("exact expression");
        assert_eq!(out, json!("acct"));
    }
}
