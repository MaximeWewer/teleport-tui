//! The main content area: the per-tab resource table and the all-clusters
//! aggregate table, with their column sizing.
//!
//! Split out of `ui`; imports and shared render helpers arrive via `super::*`.

#[allow(clippy::wildcard_imports)]
use super::*;

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
            &app.nodes,
            &app.visible,
            &mut app.table,
        ),
        Tab::Kube => render_resource(
            frame,
            area,
            "Kube clusters",
            &app.kube,
            &app.visible,
            &mut app.table,
        ),
        Tab::Db => render_resource(
            frame,
            area,
            "Databases",
            &app.dbs,
            &app.visible,
            &mut app.table,
        ),
        Tab::Apps => render_resource(frame, area, "Apps", &app.apps, &app.visible, &mut app.table),
        Tab::Requests => render_resource(
            frame,
            area,
            "Access requests",
            &app.requests,
            &app.visible,
            &mut app.table,
        ),
        Tab::Users => {
            render_resource(
                frame,
                area,
                "Users",
                &app.users,
                &app.visible,
                &mut app.table,
            );
        }
        Tab::Roles => {
            render_resource(
                frame,
                area,
                "Roles",
                &app.roles,
                &app.visible,
                &mut app.table,
            );
        }
        Tab::Tokens => render_resource(
            frame,
            area,
            "Tokens",
            &app.tokens,
            &app.visible,
            &mut app.table,
        ),
        Tab::Bots => render_resource(frame, area, "Bots", &app.bots, &app.visible, &mut app.table),
        Tab::Inventory => render_resource(
            frame,
            area,
            "Inventory",
            &app.instances,
            &app.visible,
            &mut app.table,
        ),
        Tab::Recordings => render_resource(
            frame,
            area,
            "Recordings",
            &app.recordings,
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
    table_state: &mut ratatui::widgets::TableState,
) {
    let cols = T::columns();
    let header =
        Row::new(cols.iter().copied()).style(Style::default().add_modifier(Modifier::BOLD));
    let rows: Vec<Row> = visible
        .iter()
        .filter_map(|&i| items.get(i))
        .map(|it| Row::new(it.row()))
        .collect();

    // First column narrow-ish, last column (labels/uri) widest.
    let widths = column_widths(cols.len());
    let title = format!(" {label} ({}) ", visible.len());
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(table, area, table_state);
}

/// All-clusters aggregate table: a CLUSTER column prepended to the tab's rows.
fn render_aggregate(frame: &mut Frame, app: &mut App, area: Rect) {
    let cols = crate::app::tab_columns(app.tab);
    let mut headers: Vec<&str> = Vec::with_capacity(cols.len() + 1);
    headers.push("CLUSTER");
    headers.extend_from_slice(cols);
    let header = Row::new(headers.clone()).style(Style::default().add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = app
        .visible
        .iter()
        .filter_map(|&i| app.agg_rows.get(i))
        .map(|r| {
            let mut cells = Vec::with_capacity(r.cells.len() + 1);
            cells.push(r.cluster.clone());
            cells.extend(r.cells.iter().cloned());
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

    let widths = column_widths(headers.len());
    let title = format!(
        " {} — ALL CLUSTERS ({}) ",
        app.tab.title(),
        app.visible.len()
    );
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(table, area, &mut app.table);
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
