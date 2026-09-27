//! The main content area: the per-tab resource table and the all-clusters
//! aggregate table, with their column sizing.
//!
//! Split out of `ui`; imports and shared render helpers arrive via `super::*`.

#[allow(clippy::wildcard_imports)]
use super::*;
use ratatui::widgets::{HighlightSpacing, TableState};

pub(super) fn render_body(frame: &mut Frame, app: &mut App, area: Rect) {
    if app.aggregating() {
        render_aggregate(frame, app, area);
        return;
    }
    match app.tab {
        Tab::Ssh => render_resource(
            frame,
            area,
            "SSH nodes",
            &app.lists.nodes,
            &app.visible,
            &mut app.table,
        ),
        Tab::Kube => render_resource(
            frame,
            area,
            "Kube clusters",
            &app.lists.kube,
            &app.visible,
            &mut app.table,
        ),
        Tab::Db => render_resource(
            frame,
            area,
            "Databases",
            &app.lists.dbs,
            &app.visible,
            &mut app.table,
        ),
        Tab::Apps => render_resource(
            frame,
            area,
            "Apps",
            &app.lists.apps,
            &app.visible,
            &mut app.table,
        ),
        Tab::Requests => render_resource(
            frame,
            area,
            "Access requests",
            &app.lists.requests,
            &app.visible,
            &mut app.table,
        ),
        Tab::Users => {
            render_resource(
                frame,
                area,
                "Users",
                &app.lists.users,
                &app.visible,
                &mut app.table,
            );
        }
        Tab::Roles => {
            render_resource(
                frame,
                area,
                "Roles",
                &app.lists.roles,
                &app.visible,
                &mut app.table,
            );
        }
        Tab::Tokens => render_resource(
            frame,
            area,
            "Tokens",
            &app.lists.tokens,
            &app.visible,
            &mut app.table,
        ),
        Tab::Bots => render_resource(
            frame,
            area,
            "Bots",
            &app.lists.bots,
            &app.visible,
            &mut app.table,
        ),
        Tab::Inventory => render_resource(
            frame,
            area,
            "Inventory",
            &app.lists.instances,
            &app.visible,
            &mut app.table,
        ),
        Tab::Recordings => render_resource(
            frame,
            area,
            "Recordings",
            &app.lists.recordings,
            &app.visible,
            &mut app.table,
        ),
    }
}

/// Generic resource table driven by the `Resource` trait.
fn render_resource<T: Resource>(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    items: &[T],
    visible: &[usize],
    table_state: &mut TableState,
) {
    let cols = T::columns();
    let header =
        Row::new(cols.iter().copied()).style(Style::default().add_modifier(Modifier::BOLD));
    // First column narrow-ish, last column (labels/uri) widest.
    let widths = column_widths(cols.len());
    let title = format!(" {label} ({}) ", visible.len());
    render_windowed(frame, area, visible.len(), table_state, |window| {
        // Only the rows on screen are formatted (see `render_windowed`).
        let rows: Vec<Row> = visible
            .get(window)
            .unwrap_or_default()
            .iter()
            .filter_map(|&i| items.get(i))
            .map(|it| Row::new(it.row()))
            .collect();
        styled_table(rows, widths, header, title)
    });
}

/// A body table with the shared chrome (bordered title, bold header, highlight).
fn styled_table<'a>(
    rows: Vec<Row<'a>>,
    widths: Vec<Constraint>,
    header: Row<'a>,
    title: String,
) -> Table<'a> {
    Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ")
}

/// Render a bordered, one-line-header table of `len` single-line rows, building
/// only the rows that fit on screen: `build` gets the index window to turn into
/// rows. Listings can hold thousands of entries, and formatting every row on
/// every frame (just to have ratatui draw a screenful) is most of the render
/// cost. The window is the one ratatui's own `Table` would pick from `state`
/// (keep the offset, scroll just enough to show the selection), and `state`
/// ends up exactly as a full render would leave it, so scrolling is unchanged.
fn render_windowed<'a>(
    frame: &mut Frame,
    area: Rect,
    len: usize,
    state: &mut TableState,
    build: impl FnOnce(std::ops::Range<usize>) -> Table<'a>,
) {
    // Inside the borders, below the one-line header.
    if area.width <= 2 || area.height <= 2 {
        // No room for a table at all: ratatui draws just the block, state untouched.
        frame.render_stateful_widget(build(0..0), area, &mut TableState::default());
        return;
    }
    let height = usize::from(area.height - 3);
    // Mirror the full render's clamping of the selection to the row count.
    let selected = if len == 0 {
        None
    } else {
        state.selected().map(|s| s.min(len - 1))
    };
    state.select(selected);
    let (start, end) = viewport(len, state.offset(), selected, height);
    let mut window_state =
        TableState::default().with_selected(selected.and_then(|s| s.checked_sub(start)));
    let mut table = build(start..end);
    if start == end && selected.is_some() {
        // No row fits (zero-height body): a full render would still keep the
        // selection and so reserve the highlight column in the header layout.
        table = table.highlight_spacing(HighlightSpacing::Always);
    }
    frame.render_stateful_widget(table, area, &mut window_state);
    if len > 0 {
        *state.offset_mut() = start;
    }
}

/// The `[start, end)` rows a ratatui `Table` shows for `len` one-line rows in
/// `height` lines, starting from the stored `offset` and scrolling just enough
/// to keep `selected` visible (the same rule as its internal `visible_rows`).
fn viewport(len: usize, offset: usize, selected: Option<usize>, height: usize) -> (usize, usize) {
    if len == 0 {
        return (0, 0);
    }
    let last = len - 1;
    let selected = selected.map(|s| s.min(last));
    let mut start = offset.min(last);
    if let Some(sel) = selected {
        start = start.min(sel);
    }
    let mut end = start.saturating_add(height).min(len);
    if let Some(sel) = selected
        && sel >= end
    {
        end = sel + 1;
        start = start.max(end.saturating_sub(height));
    }
    (start, end)
}

/// All-clusters aggregate table: a CLUSTER column prepended to the tab's rows.
fn render_aggregate(frame: &mut Frame, app: &mut App, area: Rect) {
    let cols = crate::app::tab_columns(app.tab);
    let mut headers: Vec<&str> = Vec::with_capacity(cols.len() + 1);
    headers.push("CLUSTER");
    headers.extend_from_slice(cols);
    let header = Row::new(headers.clone()).style(Style::default().add_modifier(Modifier::BOLD));
    let widths = column_widths(headers.len());
    let title = format!(
        " {} - ALL CLUSTERS ({}) ",
        app.tab.title(),
        app.visible.len()
    );
    let (visible, agg_rows) = (&app.visible, &app.agg.rows);
    render_windowed(frame, area, visible.len(), &mut app.table, |window| {
        // Only the on-screen rows, borrowing their cells rather than cloning.
        let rows: Vec<Row> = visible
            .get(window)
            .unwrap_or_default()
            .iter()
            .filter_map(|&i| agg_rows.get(i))
            .map(|r| {
                let cells =
                    std::iter::once(r.cluster.as_str()).chain(r.cells.iter().map(String::as_str));
                let row = Row::new(cells);
                // A cluster with no live session shows a dimmed placeholder row
                // prompting `L` to log in, set apart from real resource rows.
                if r.login_required {
                    row.style(Style::default().fg(Color::Yellow))
                } else {
                    row
                }
            })
            .collect();
        styled_table(rows, widths, header, title)
    });
}

fn column_widths(n: usize) -> Vec<Constraint> {
    if n <= 1 {
        return vec![Constraint::Percentage(100)];
    }
    // Name column 25%, last column the remainder, middle columns share evenly.
    let last = 40u16;
    let first = 25u16;
    let mids = n - 2;
    let mut widths = vec![Constraint::Percentage(first)];
    if mids > 0 {
        let each = (100 - first - last) / u16::try_from(mids).unwrap_or(1);
        for _ in 0..mids {
            widths.push(Constraint::Percentage(each));
        }
    }
    widths.push(Constraint::Percentage(last));
    widths
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn table_of(names: &[String]) -> Table<'_> {
        let rows: Vec<Row> = names.iter().map(|n| Row::new(vec![n.as_str()])).collect();
        let header = Row::new(vec!["NAME"]).style(Style::default().add_modifier(Modifier::BOLD));
        styled_table(rows, column_widths(1), header, " t ".to_owned())
    }

    // Rendering only the viewport window must look exactly like ratatui's full
    // render and leave the same offset/selection behind, across a scroll session
    // (moves down past the bottom, jumps, back up, list shrinking under a filter).
    #[test]
    fn windowed_render_matches_full_render() {
        let all: Vec<String> = (0..200).map(|i| format!("row-{i:03}")).collect();
        let steps: [(usize, Option<usize>); 11] = [
            (200, Some(0)),
            (200, Some(5)),
            (200, Some(12)),
            (200, Some(13)),
            (200, Some(150)),
            (200, Some(140)),
            (200, Some(120)),
            (200, Some(199)),
            (30, Some(150)),
            (3, Some(1)),
            (0, None),
        ];
        for height in [2u16, 3, 4, 10] {
            let mut full_state = TableState::default();
            let mut win_state = TableState::default();
            for (len, sel) in steps {
                let names = all.get(..len).unwrap();
                full_state.select(sel);
                win_state.select(sel);

                let mut full = Terminal::new(TestBackend::new(20, height)).unwrap();
                full.draw(|f| f.render_stateful_widget(table_of(names), f.area(), &mut full_state))
                    .unwrap();
                let mut win = Terminal::new(TestBackend::new(20, height)).unwrap();
                win.draw(|f| {
                    let area = f.area();
                    render_windowed(f, area, len, &mut win_state, |w| {
                        table_of(names.get(w).unwrap())
                    });
                })
                .unwrap();

                assert_eq!(
                    full.backend().buffer(),
                    win.backend().buffer(),
                    "height {height}, len {len}, sel {sel:?}"
                );
                assert_eq!(full_state.offset(), win_state.offset());
                assert_eq!(full_state.selected(), win_state.selected());
            }
        }
    }

    #[test]
    fn viewport_keeps_offset_and_follows_selection() {
        assert_eq!(viewport(0, 0, None, 10), (0, 0));
        assert_eq!(viewport(100, 0, Some(3), 10), (0, 10));
        assert_eq!(viewport(100, 0, Some(10), 10), (1, 11));
        assert_eq!(viewport(100, 50, Some(40), 10), (40, 50));
        assert_eq!(viewport(100, 50, Some(55), 10), (50, 60));
        assert_eq!(viewport(5, 50, None, 10), (4, 5));
    }
}
