//! Minimal hand-rolled SVG line charts for run reports.
//!
//! No external chart library: each chart is polylines, tick lines and text.
//! Y axes start at zero, ticks carry labels and units, and the legend shows
//! each series' final value. Styling is deliberately plain: dark ink on a
//! light page, muted line colors, no gradients and no effects.

/// Muted line palette for multi-series charts (ops on white background).
pub const SERIES_COLORS: [&str; 6] = [
    "#3d6a8f", "#9a6a33", "#5d7f4c", "#8a5a78", "#437f78", "#66665f",
];

/// Tonal triple for percentile lines: p50 lightest, p99 darkest.
pub const PERCENTILE_COLORS: [&str; 3] = ["#8fa5b8", "#5f7f9a", "#2e4d68"];

pub struct Series {
    pub name: String,
    /// (x seconds, y value), in x order.
    pub points: Vec<(f64, f64)>,
}

pub struct ChartSpec {
    pub title: String,
    /// Unit shown on the y axis and after legend values, e.g. "ops/s".
    pub y_unit: String,
    /// X axis caption, e.g. "time (s)".
    pub x_label: String,
    pub series: Vec<Series>,
    /// Line colors; cycled if fewer than series. Empty selects the default
    /// muted palette.
    pub palette: Vec<&'static str>,
}

const WIDTH: f64 = 900.0;
const HEIGHT: f64 = 260.0;
const ML: f64 = 64.0; // left margin: y tick labels
const MR: f64 = 208.0; // right margin: legend
const MT: f64 = 30.0; // top margin: title
const MB: f64 = 40.0; // bottom margin: x ticks + label

/// Round a raw step to 1/2/5 times a power of ten.
fn nice_step(range: f64, target_ticks: usize) -> f64 {
    let raw = (range / target_ticks.max(1) as f64).max(1e-12);
    let mag = 10f64.powf(raw.log10().floor());
    let norm = raw / mag;
    let n = if norm <= 1.0 {
        1.0
    } else if norm <= 2.0 {
        2.0
    } else if norm <= 5.0 {
        5.0
    } else {
        10.0
    };
    n * mag
}

/// Compact number formatting for tick and legend labels.
pub fn fmt_num(v: f64) -> String {
    if !v.is_finite() {
        return "0".into();
    }
    let a = v.abs();
    let s = if a >= 100.0 {
        // round() first: `{:.0}` alone rounds ties-to-even (1234.5 -> "1234").
        format!("{:.0}", v.round())
    } else if a >= 10.0 {
        format!("{v:.1}")
    } else {
        format!("{v:.2}")
    };
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Render one line chart as a standalone `<svg>` element.
pub fn line_chart_svg(spec: &ChartSpec) -> String {
    let plot_w = WIDTH - ML - MR;
    let plot_h = HEIGHT - MT - MB;

    let x_max = spec
        .series
        .iter()
        .flat_map(|s| s.points.iter().map(|p| p.0))
        .fold(0.0f64, f64::max)
        .max(1.0);
    let y_data_max = spec
        .series
        .iter()
        .flat_map(|s| s.points.iter().map(|p| p.1))
        .fold(0.0f64, f64::max);

    let y_step = nice_step(if y_data_max > 0.0 { y_data_max } else { 1.0 }, 4);
    let y_max = (y_step * (y_data_max / y_step).ceil()).max(y_step);
    let x_step = nice_step(x_max, 6);

    let px = |x: f64| ML + (x / x_max) * plot_w;
    let py = |y: f64| MT + plot_h - (y / y_max) * plot_h;

    let palette: &[&str] = if spec.palette.is_empty() {
        &SERIES_COLORS
    } else {
        &spec.palette
    };

    let mut svg = String::with_capacity(8 * 1024);
    // No xmlns: these SVGs are always inlined into HTML5 documents, where the
    // namespace is implied — and its URL would be the report's only external
    // reference, breaking the "fully self-contained" guarantee.
    svg.push_str(&format!(
        r#"<svg viewBox="0 0 {WIDTH} {HEIGHT}" width="{WIDTH}" height="{HEIGHT}" role="img" font-family="inherit">"#
    ));
    svg.push_str(&format!(
        r##"<text x="{ML}" y="18" font-size="13" font-weight="600" fill="#1c1c1a">{}</text>"##,
        esc(&spec.title)
    ));

    // Horizontal grid lines + y tick labels.
    let mut y = 0.0;
    while y <= y_max + y_step * 1e-6 {
        let yy = py(y);
        svg.push_str(&format!(
            r##"<line x1="{ML}" y1="{yy:.1}" x2="{:.1}" y2="{yy:.1}" stroke="#e6e6e1" stroke-width="1"/>"##,
            ML + plot_w
        ));
        svg.push_str(&format!(
            r##"<text x="{:.1}" y="{yy:.1}" dy="0.32em" font-size="11" fill="#4a4a45" text-anchor="end">{}</text>"##,
            ML - 8.0,
            fmt_num(y)
        ));
        y += y_step;
    }

    // X ticks.
    let mut x = 0.0;
    while x <= x_max + x_step * 1e-6 {
        let xx = px(x);
        svg.push_str(&format!(
            r##"<line x1="{xx:.1}" y1="{:.1}" x2="{xx:.1}" y2="{:.1}" stroke="#b9b9b2" stroke-width="1"/>"##,
            MT + plot_h,
            MT + plot_h + 4.0
        ));
        svg.push_str(&format!(
            r##"<text x="{xx:.1}" y="{:.1}" font-size="11" fill="#4a4a45" text-anchor="middle">{}</text>"##,
            MT + plot_h + 17.0,
            fmt_num(x)
        ));
        x += x_step;
    }

    // Axis captions.
    svg.push_str(&format!(
        r##"<text x="{:.1}" y="{:.1}" font-size="11" fill="#4a4a45" text-anchor="middle">{}</text>"##,
        ML + plot_w / 2.0,
        MT + plot_h + 33.0,
        esc(&spec.x_label)
    ));
    svg.push_str(&format!(
        r##"<text x="{:.1}" y="18" font-size="11" fill="#4a4a45" text-anchor="end">{}</text>"##,
        ML + plot_w,
        esc(&spec.y_unit)
    ));

    // Plot frame.
    svg.push_str(&format!(
        r##"<rect x="{ML}" y="{MT}" width="{plot_w:.1}" height="{plot_h:.1}" fill="none" stroke="#b9b9b2" stroke-width="1"/>"##
    ));

    // Series lines and legend.
    for (i, s) in spec.series.iter().enumerate() {
        let color = palette[i % palette.len()];
        if s.points.len() == 1 {
            let (x0, y0) = s.points[0];
            svg.push_str(&format!(
                r#"<circle cx="{:.1}" cy="{:.1}" r="2.5" fill="{color}"/>"#,
                px(x0),
                py(y0.min(y_max))
            ));
        } else if !s.points.is_empty() {
            let pts: Vec<String> = s
                .points
                .iter()
                .map(|(x0, y0)| format!("{:.1},{:.1}", px(*x0), py(y0.min(y_max))))
                .collect();
            svg.push_str(&format!(
                r#"<polyline points="{}" fill="none" stroke="{color}" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round"/>"#,
                pts.join(" ")
            ));
        }
        let ly = MT + 8.0 + i as f64 * 18.0;
        let lx = ML + plot_w + 14.0;
        svg.push_str(&format!(
            r#"<line x1="{lx:.1}" y1="{ly:.1}" x2="{:.1}" y2="{ly:.1}" stroke="{color}" stroke-width="2.5"/>"#,
            lx + 16.0
        ));
        let last = s.points.last().map(|p| p.1).unwrap_or(0.0);
        svg.push_str(&format!(
            r##"<text x="{:.1}" y="{ly:.1}" dy="0.32em" font-size="12" fill="#2a2a26">{}: {} {}</text>"##,
            lx + 22.0,
            esc(&s.name),
            fmt_num(last),
            esc(&spec.y_unit)
        ));
    }

    svg.push_str("</svg>");
    svg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chart_contains_axes_series_and_legend() {
        let spec = ChartSpec {
            title: "throughput (ops/s)".into(),
            y_unit: "ops/s".into(),
            x_label: "time (s)".into(),
            series: vec![
                Series {
                    name: "write".into(),
                    points: vec![(0.0, 10.0), (5.0, 20.0), (10.0, 15.0)],
                },
                Series {
                    name: "read".into(),
                    points: vec![(0.0, 30.0), (5.0, 25.0), (10.0, 40.0)],
                },
            ],
            palette: vec![],
        };
        let svg = line_chart_svg(&spec);
        assert!(svg.starts_with("<svg"));
        assert!(svg.ends_with("</svg>"));
        assert_eq!(svg.matches("<polyline").count(), 2);
        assert!(svg.contains("throughput (ops/s)"));
        // Legend carries final values.
        assert!(svg.contains("write: 15 ops/s"));
        assert!(svg.contains("read: 40 ops/s"));
        // No decoration.
        assert!(!svg.contains("gradient"));
        assert!(!svg.contains("filter"));
    }

    #[test]
    fn single_point_series_renders_marker() {
        let spec = ChartSpec {
            title: "t".into(),
            y_unit: "ms".into(),
            x_label: "time (s)".into(),
            series: vec![Series {
                name: "write".into(),
                points: vec![(0.0, 5.0)],
            }],
            palette: vec![],
        };
        let svg = line_chart_svg(&spec);
        assert!(svg.contains("<circle"));
        assert!(!svg.contains("<polyline"));
    }

    #[test]
    fn escapes_user_text() {
        let spec = ChartSpec {
            title: "a<b&c".into(),
            y_unit: "ops/s".into(),
            x_label: "time (s)".into(),
            series: vec![],
            palette: vec![],
        };
        let svg = line_chart_svg(&spec);
        assert!(svg.contains("a&lt;b&amp;c"));
    }

    #[test]
    fn number_formatting() {
        assert_eq!(fmt_num(0.0), "0");
        assert_eq!(fmt_num(1234.5), "1235");
        assert_eq!(fmt_num(12.34), "12.3");
        assert_eq!(fmt_num(1.5), "1.5");
        assert_eq!(fmt_num(2.0), "2");
    }
}
