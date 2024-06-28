import json
import os
from collections import defaultdict
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from urllib.parse import urlencode
from urllib.parse import urlparse

import flask
import mmh3
import numpy as np
import obsinthe.prometheus as prom
import pandas as pd
import plotly.express as px
from dash import Dash
from dash import dcc
from dash import html
from dash import Input
from dash import Output


app = Dash(
    title="OpenShift Health Console Prototype",
    assets_ignore=r".*",
    external_stylesheets=[
        "./assets/patternfly5/patternfly.css",
        "./assets/patternfly5/patternfly-addons.css",
        "./assets/custom.css",
    ],
    external_scripts=[
        "./assets/jquery/jquery-3.7.1.min.js",
        "./assets/custom.js",
    ],
)


COLORS = {
    "red": "#c9190b",
    "orange": "#f0ab00",
    "blue": "#0066cc",
}

OCP_CONSOLE_URL = os.getenv("OCP_CONSOLE_URL", None)
PROM_URL = os.getenv("PROM_URL", "http://localhost:9090")
PROM_ACCESS_TOKEN = os.getenv("PROM_ACCESS_TOKEN", "")

if access_token_file := os.getenv("PROM_ACCESS_TOKEN_FILE"):
    with open(access_token_file) as f:
        PROM_ACCESS_TOKEN = f.read().strip()

SSL_VERIFY = True

if ssl_verify := os.getenv("SSL_VERIFY"):
    if ssl_verify == "false":
        SSL_VERIFY = False
    else:
        # Assume it's a path to a CA bundle.
        SSL_VERIFY = ssl_verify

# Prometheus can't go beyond 11000 points per series.
RESOLUTION_LIMIT = 11000

# Useful for pinning the end date to a specific value for testing.
DEFAULT_END_DATE = os.getenv("DEFAULT_END_DATE", None)

# Prefix for the source labels in the Prometheus alerts.
SRC_PREFIX = "src_"

# We consider an incident long-standing if it lasts more than 90% of the window.
LONG_STANDING_MIN_DAYS = 6

# How long to wait before considering an incident resolved.
CURRENT_TIME_TOLERANCE = timedelta(minutes=3)

# the metric cluster:health:components:map value represents the health of a component.
# We need to extract the value into a separate column and map it to a severity level.
HEALTH_VALUE_SEVERITY = {0: "healthy", 1: "warning", 2: "critical"}

# Severity rank for sorting alerts - the lower the more important.
SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}


# Plotly graph configuration.
GRAPH_CONFIG = {"displaylogo": False}

CLIENT = prom.Client(
    url=PROM_URL,
    token=PROM_ACCESS_TOKEN,
)
CLIENT.ssl_verification = SSL_VERIFY


class AlertIdMapper:
    """Maps alert labels to Openshift Console alert IDs."""

    def __init__(self):
        self.alert_id_map = defaultdict(list)
        self.load()

    def load(self):
        rules_json = CLIENT.get("/api/v1/rules").json()
        rules_data = []
        for g in rules_json["data"]["groups"]:
            rules = [r for r in g["rules"] if r["type"] == "alerting"]
            if rules:
                rules_data.extend(
                    [
                        {"group_name": g["name"], "group_file": g["file"], **r}
                        for r in rules
                    ]
                )

        for r in rules_data:
            mapping = {}
            mapping["alertname"] = r["name"]
            mapping["labels"] = {
                k: v for k, v in r["labels"].items() if k != "prometheus"
            }
            mapping["id"] = self.rule_alert_id(r)
            self.alert_id_map[r["name"]].append(mapping)

    def rule_alert_id(self, rule):
        s = ",".join(
            [
                rule["group_file"],
                rule["group_name"],
                rule["name"],
                str(rule["duration"]),
                rule["query"],
            ]
            + [f"{v}={k}" for (k, v) in rule["labels"].items()]
        )
        return mmh3.hash(s, 0, signed=False)

    def id_for_alert(self, labels):
        mappings = self.alert_id_map[labels["alertname"]]
        for m in mappings:
            if m["labels"].items() <= labels.items():
                return m["id"]
        return None

    def url_for_alert(self, labels, console_url):
        labels = {
            k: v for k, v in labels.items() if k not in ["__name__", "alertstate"]
        }
        alert_id = self.id_for_alert(labels)
        if alert_id:
            return self.format_url(alert_id, labels, console_url)

    def format_url(self, alert_id, labels, console_url):
        query = urlencode(labels)
        return f"{console_url}/monitoring/alerts/{alert_id}?{query}"


ALERT_ID_MAPPER = AlertIdMapper()


##################
#  HTML helpers  #
##################


def el(el_type, class_name, children=None, **kwargs):
    return el_type(className=class_name, children=children, **kwargs)


def span(class_name, children, **kwargs):
    return el(html.Span, class_name, children, **kwargs)


def div(class_name, children, **kwargs):
    return el(html.Div, class_name, children, **kwargs)


def flex_inline(children):
    return html.Div(
        children, className="pf-v5-l-flex pf-m-inline-flex pf-m-space-items-sm"
    )


def flex_item(children):
    return html.Div(
        className="pf-v5-l-flex__item",
        children=children,
    )


def icon_el(class_name):
    return el(html.I, class_name, [])


def icon(icon_name):
    if icon_name in ["critical"]:
        class_name = "fa-exclamation-circle pf-v5-u-danger-color-100"
    elif icon_name in ["warning"]:
        class_name = "fa-exclamation-triangle  pf-v5-u-warning-color-100"
    elif icon_name in ["info"]:
        class_name = "fa-info-circle pf-v5-u-info-color-100"
    else:
        class_name = icon_name

    return icon_el(f"fas fa-fw {class_name}")


def icon_text(icon_name, text):
    return flex_inline([flex_item(icon(icon_name)), flex_item(text)])


#################################
#  Data loading and processing  #
#################################


def promql_group_conditions(group_ids):
    conditions = ["src_alertname != 'Watchdog'"]
    if group_ids:
        group_ids_regex = "|".join(group_ids)
        conditions.append(f"group_id =~ '{group_ids_regex}'")
    return ",".join(conditions)


def resolution(start, end):
    # Minimum resolution to start with
    resolution = timedelta(minutes=1)

    if (end - start) / resolution > RESOLUTION_LIMIT:
        # Too many data points - increase the resolution
        resolution = timedelta(minutes=5)

    if (end - start) / resolution > RESOLUTION_LIMIT:
        # Given we're limiting the select box on 15 days, we should never reach this.
        raise ("Resolution limit exceeded")

    return resolution


def load_health_components_map(start, end, group_ids=[]):
    raw = CLIENT.query_range(
        f"cluster:health:components:map{{{promql_group_conditions(group_ids)}}}",
        start,
        end,
        resolution(start, end).total_seconds(),
    )
    data = prom.data.raw_to_ds(raw)
    return data


def load_components_ranking(start, end):
    # +1 to avoid 0 days interval
    days = (end - start).days + 1

    data = CLIENT.query(f"last_over_time(cluster:health:components[{days}d])", end)
    ret = prom.data.raw_to_ds(data).df
    ret = ret[["layer", "component", "value"]]
    ret.rename(columns={"value": "rank_component"}, inplace=True)

    # Avoid potential duplicates when mapping to components.
    ret.drop_duplicates(["layer", "component"], inplace=True)
    return ret


def load_incidents(start, end, group_ids=[]):
    res = resolution(start, end)
    raw = CLIENT.query_range(
        (
            "max by (group_id) "
            f"(cluster:health:components:map{{{promql_group_conditions(group_ids)}}})"
        ),
        start,
        end,
        res.total_seconds(),
    )
    data = prom.data.raw_to_ds(raw)
    if data is None:
        return None

    data = extract_component_health(data)
    intervals = data.to_intervals_ds(res)
    intervals_df = intervals.merge_overlaps(res, ["group_id", "health_severity"]).df
    intervals_df.drop("sub_intervals", inplace=True, axis=1)

    intervals_df.rename(
        columns={"start": "chunk_start", "end": "chunk_end"},
        inplace=True,
    )
    return intervals_df


def query_alerts(start, end, query=None):
    if query is None:
        query = "ALERTS{alertstate='firing'}"

    res = resolution(start, end)

    raw = CLIENT.query_range(query, start, end, res.total_seconds())
    ds = prom.data.raw_to_ds(raw, columns=["alertname", "namespace", "severity"])
    if ds:
        df = ds.to_intervals_ds(res).df

        # dedup flapping alerts into a single record with min start and max end.
        df["extra_str"] = df["extra"].map(lambda d: json.dumps(d, sort_keys=True))
        if "namespace" not in df.columns:
            df["namespace"] = None
        df = df.groupby(
            ["alertname", "namespace", "severity", "extra_str"],
            as_index=False,
            dropna=False,
        ).agg(start=("start", "min"), end=("end", "max"), extra=("extra", "first"))
        df.drop("extra_str", axis=1, inplace=True)
        return df


def components_map_alerts_labels(components_map):
    return [c for c in components_map.columns if c.startswith(SRC_PREFIX)]


def alerts_add_components(alerts, components_map):
    component_alerts_labels = components_map_alerts_labels(components_map)
    # The alerts side of the join doesn't have the SRC_PREFIX in the column names.
    alerts_labels = [lbl.replace(SRC_PREFIX, "", 1) for lbl in component_alerts_labels]

    for c in component_alerts_labels:
        if c not in alerts.columns:
            alerts[c] = None

    return alerts.merge(
        components_map[
            ["component", "layer"] + component_alerts_labels
        ].drop_duplicates(),
        left_on=alerts_labels,
        right_on=component_alerts_labels,
    )


def load_incident_alerts(components_map):
    alerts_labels = components_map_alerts_labels(components_map)

    incident_start = components_map["start"].min()
    incident_end = components_map["end"].max()

    components_map = (
        components_map[alerts_labels].drop_duplicates().replace(np.nan, None)
    )
    # remove the src_ prefix from the columns to match the labels in the alerts.
    components_map.columns = [
        c.replace(SRC_PREFIX, "", 1) for c in components_map.columns
    ]

    filter_labels = components_map.to_dict(orient="records")

    def dict_to_promql_filter(d):
        return ", ".join([f'{k}="{v}"' for (k, v) in d.items() if v is not None])

    alerts_query = " or ".join(
        [
            f"ALERTS{{alertstate='firing', {dict_to_promql_filter(d)}}}"
            for d in filter_labels
        ]
    )
    return query_alerts(incident_start, incident_end, alerts_query)


def current_time_tolerant_end(end):
    return min(end, datetime.now(timezone.utc) - CURRENT_TIME_TOLERANCE)


def load_alerts(start, end, group_ids=None):
    last_end = current_time_tolerant_end(end)
    health_components_map = load_health_components_map(start, end, group_ids=group_ids)
    if health_components_map is None:
        return None

    components_map_df = health_components_map.to_intervals_ds(resolution(start, end)).df
    if group_ids:
        alerts_data_list = []
        for _, g in components_map_df.groupby("group_id"):
            alerts_df = load_incident_alerts(g)
            if alerts_df is not None:
                alerts_data_list.append(alerts_df)

        if not alerts_data_list:
            return None
        intervals_df = pd.concat(alerts_data_list, ignore_index=True)
    else:
        intervals_df = query_alerts(start, end)

    if intervals_df is None:
        return None

    intervals_df = alerts_add_components(intervals_df, components_map_df)
    intervals_df["alertstate"] = "firing"
    active_alerts_mask = intervals_df["end"] >= last_end
    intervals_df.loc[~active_alerts_mask, "alertstate"] = "resolved"
    # we keep the default end value in separate column for sorting
    intervals_df["end_default"] = intervals_df["end"].copy()
    intervals_df.loc[active_alerts_mask, "end"] = None
    if "namespace" not in intervals_df.columns:
        intervals_df["namespace"] = None

    return intervals_df


def split_unique_values(values):
    # reconstruct the pairs of (timestamp, value)
    v = values.reshape(-1, 2)
    # lexsoft by value and timestamp (we need values ascending to for the next step).
    # Note that lexsort sorts by the last arg first.
    v = v[np.lexsort((v[:, 0], v[:, 1]))]
    # split by index of unique values
    split = np.split(v, np.unique(v[:, 1], return_index=True)[1][1:])
    # put back in original shape
    split = [a.reshape(-1) for a in split]
    return split


def extract_component_health(ds):
    df = ds.df.copy()
    df["values"] = df["values"].map(split_unique_values)
    df = df.explode("values", ignore_index=True)
    df["health_severity"] = df["values"].map(lambda a: HEALTH_VALUE_SEVERITY[a[1]])
    return prom.data.RangeDataset(df)


#########################
#  Dash app core logic  #
#########################

# fmt: off
def page_layout(body_layout):
    return div("pf-v5-c-page",
               [el(html.Header, "pf-v5-c-masthead",
                   [div("pf-v5-c-masthead__main",
                        [div("pf-v5-c-masthead__content",
                             [div("pf-v5-c-masthead__title",
                                  [el(html.H1,
                                      "pf-v5-c-title",
                                      [icon_text("pf-icon pf-v5-pficon-monitoring",
                                                 "Health Console")])])])])]),
                el(html.Main, "pf-v5-c-page__main",
                   [el(html.Section, "pf-v5-c-page__main-section co-page-backdrop",
                       [div("pf-v5-c-page__main-section-body",
                            body_layout)])])])
# fmt: on


app.layout = page_layout(
    [
        div(
            "pf-v5-l-stack pf-m-gutter",
            [
                div(
                    "pf-v5-c-card",
                    [
                        flex_inline(
                            [
                                flex_item(
                                    dcc.Checklist(
                                        [
                                            {"value": "info", "label": "Info only"},
                                            {"value": "inactive", "label": "Inactive"},
                                            {
                                                "value": "long-standing",
                                                "label": "Long-standing",
                                            },
                                        ],
                                        id="filter-mode",
                                        inline=True,
                                    ),
                                ),
                                flex_item(
                                    dcc.Dropdown(
                                        [
                                            {"value": "1", "label": "1 day"},
                                            {"value": "3", "label": "3 days"},
                                            {"value": "7", "label": "7 days"},
                                            {"value": "15", "label": "15 days"},
                                        ],
                                        "3",
                                        id="time-window-size",
                                        clearable=False,
                                    ),
                                ),
                                flex_item(
                                    dcc.DatePickerSingle(
                                        id="time-window-end",
                                        date=DEFAULT_END_DATE,
                                        clearable=True,
                                        display_format="YYYY-MM-DD",
                                        placeholder="now",
                                    ),
                                ),
                                flex_item(
                                    html.A(icon_el("fas fa-redo"), id="refresh-link")
                                ),
                            ]
                        ),
                    ],
                ),
                dcc.Loading(
                    delay_show=500,  # wait a bit to avoid flickering
                    children=div(
                        "pf-v5-c-card",
                        [
                            dcc.Graph(
                                id="incidents-timeline-graph",
                                config=GRAPH_CONFIG,
                            ),
                        ],
                    ),
                ),
                dcc.Input(id="incidents-selected", type="hidden"),
                dcc.Loading(
                    className="alerts-loading",
                    children=[
                        div(
                            "pf-v5-c-card",
                            dcc.Graph(
                                id="alerts-timeline-graph",
                                config=GRAPH_CONFIG,
                            ),
                        ),
                        div(
                            "alerts pf-v5-c-card",
                            div("pf-v5-c-card__body", [], id="alerts"),
                        ),
                    ],
                ),
                dcc.Input(id="dummy", type="hidden"),
            ],
        ),
    ]
)


def format_state(state):
    if state == "firing":
        return icon_text("fa-bell", "Firing")
    elif state == "resolved":
        return icon_text("fa-check", "Resolved")
    else:
        return state


def format_severity(severity):
    if severity == "warning":
        return icon_text("warning", "Warning")
    elif severity == "info":
        return icon_text("info", "Info")
    elif severity == "critical":
        return icon_text("critical", "Critical")
    else:
        return icon_text("warning", severity)


# fmt: off
def build_expandable_table(columns, data, expand_all=False):
    content = [el(html.Thead, "pf-v5-c-table__thead", [
        el(html.Tr, "pf-v5-c-table__tr pf-m-row", [
            el(html.Th, "pf-v5-c-table__th", column) for column in columns
        ]),
    ])]

    for row in data:
        cells = []
        nested_table = None
        expanded = False
        for cell in row:
            if isinstance(cell, RowExpansion):
                tbl = div("pf-v5-c-table__expandable-row-content", [cell.content])
                expanded = cell.expanded or expand_all
                nested_table = [
                    el(html.Td, "pf-v5-c-table__td"),
                    el(html.Td, "pf-v5-c-table__td", tbl, colSpan=len(columns) - 1)
                ]
            else:
                cells.append(el(html.Td, "pf-v5-c-table__td", cell))

        group_content = []
        group_content.append(el(html.Tr, "pf-v5-c-table__tr pf-m-row", cells))

        expanded_class = ""
        if expanded:
            expanded_class = "pf-m-expanded"

        if nested_table:
            style = None
            if not expanded:
                style = {"display": "none"}
            group_content.append(el(html.Tr,
                                    f"pf-v5-c-table__tr pf-m-row {expanded_class}",
                                    nested_table,
                                    style=style,
                                    ))

        content.append(el(html.Tbody, f"pf-v5-c-table__tbody {expanded_class}",
                          group_content, role="rowgroup"))

    return el(html.Table, "pf-v5-c-table pf-m-grid-md", content)
# fmt: on


def selected_groups_from_click_data(click_data):
    if click_data is not None:
        return [p["label"] for p in click_data["points"]]


def update_timeline_selection(data, new_selection):
    update = {"data": [{"selectedpoints": []} for _ in range(len(data))]}
    for i, group in enumerate(data):
        group_selects = [
            i for i, g in enumerate(group["customdata"]) if g[0] in new_selection
        ]
        update["data"][i]["selectedpoints"] = group_selects
    return update


def filter_incidents(df, start, end, filter_mode):
    if df is None:
        return df

    if filter_mode is None:
        filter_mode = []

    if "info" not in filter_mode:
        # Note that this is a negative filter, so we need to invert the condition.

        incident_severities = df.pivot_table(
            index="group_id",
            columns="health_severity",
            values="chunk_start",
            aggfunc="count",
            fill_value=0,
        )
        for s in ["info", "warning", "critical"]:
            if s not in incident_severities.columns:
                incident_severities[s] = 0

        info_only = incident_severities[
            (incident_severities["warning"] == 0)
            & (incident_severities["critical"] == 0)
        ]
        df = df.query(
            "~group_id.isin(@info_only)", local_dict={"info_only": info_only.index}
        )
    if "inactive" not in filter_mode:
        active = df.query(
            "chunk_end >= @end", local_dict={"end": current_time_tolerant_end(end)}
        )
        df = df.query(
            "group_id.isin(@active)",
            local_dict={"active": active["group_id"].drop_duplicates()},
        )
    if "long-standing" not in filter_mode:
        df_duration = df.copy()
        df_duration["duration"] = df["chunk_end"] - df["chunk_start"]
        incident_durations = df_duration.groupby("group_id")["duration"].sum()
        long_standing_groups = incident_durations[
            incident_durations > pd.to_timedelta(LONG_STANDING_MIN_DAYS, unit="D")
        ].index
        df = df.query(
            "~group_id.isin(@long_standing_groups)",
            local_dict={"long_standing_groups": long_standing_groups},
        )
    return df


def get_start_end(window_size, window_end):
    if window_end:
        end = datetime.strptime(window_end, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    else:
        end = datetime.now(timezone.utc)

    if window_size:
        start = end - timedelta(days=int(window_size))
    else:
        start = end - timedelta(days=7)

    return start, end


def add_alerts_ranking(start, end, alerts):
    """Add ranking columns to alerts for sorting."""
    components_ranks = load_components_ranking(start, end)
    alerts = alerts.merge(
        components_ranks[["layer", "component", "rank_component"]],
        on=["layer", "component"],
        how="left",
    )
    alerts["rank_component"].fillna(1000, inplace=True)

    alerts["rank_state"] = alerts["alertstate"].map({"firing": 0}).fillna(1000)
    alerts["rank_severity"] = alerts["severity"].map(SEVERITY_RANK).fillna(1)

    return alerts


def no_data_fig(title):
    """Render empty figure indicating no data.

    Needed when a figure is expected but no data to render."""
    return (
        px.scatter()
        .update_layout(plot_bgcolor="white", title=title, height=150)
        .update_xaxes(showticklabels=False)
        .update_yaxes(showticklabels=False)
        .add_annotation(text="No Data", showarrow=False)
    )


def build_label_group(labels):
    label_group = []
    for k, v in labels.items():
        if k.lower() in [
            "__name__",
            "_id",
            "tenant_id",
            "prometheus",
            "receive",
            "alertstate",
            "to",
        ]:
            continue
        label_group.append(
            span(
                "pf-v5-c-label pf-m-compact",
                [
                    span(
                        "pf-v5-c-label__content",
                        span("pf-v5-c-label__text", f"{k}={v}"),
                    )
                ],
            )
        )
    # return div("", label_group)
    return div("pf-v5-c-label-group", [div("pf-v5-c-label-group__main", label_group)])


def format_time(time):
    if not pd.isna(time):
        return time.strftime("%Y-%m-%d %H:%M")


def build_alert_element(alert):
    alert_el = html.B(alert.alertname)
    console_url = OCP_CONSOLE_URL
    if console_url is None:
        # Try to guess the console URL from the host.
        url = urlparse(flask.request.host_url)
        _, *domain_url = url.netloc.split(".", 1)
        if domain_url:
            console_url = f"{url.scheme}://console-openshift-console.{domain_url[0]}"

    if console_url:
        alert_url = ALERT_ID_MAPPER.url_for_alert(
            {
                "alertname": alert.alertname,
                "severity": alert.severity,
                "namespace": alert.namespace,
                **alert.extra,
            },
            console_url,
        )

        if alert_url:
            alert_el = html.A(alert_el, href=alert_url, target="_blank")

    return alert_el


def build_alerts_table(alerts):
    alerts.sort_values(["end_default", "start"], inplace=True, ascending=[False, False])
    # alerts = alerts.query('alertstate == "firing"')
    alerts_data = []
    for alert in alerts.itertuples():
        alert_el = build_alert_element(alert)
        alerts_data.append(
            [
                alert_el,
                alert.namespace if hasattr(alert, "namespace") else "",
                format_severity(alert.severity),
                format_state(alert.alertstate),
                format_time(alert.start),
                format_time(alert.end),
                RowExpansion(build_label_group(alert.extra)),
            ]
        )

    return build_expandable_table(
        ["Alert name", "Namespace", "Severity", "State", "Start", "End"],
        alerts_data,
        expand_all=True,
    )


def build_components_alerts_table(alerts):
    components_rows = []
    alerts = alerts.sort_values(["rank_state", "rank_component", "component"])
    for component, component_alerts in alerts.groupby("component", sort=False):
        severities = component_alerts.groupby("severity")["severity"].agg("count")
        severities_rendr = []
        for s, c in severities.items():
            severities_rendr.append(icon_text(s, str(c)))

        if component_alerts["alertstate"].eq("firing").any():
            component_state = "firing"
        else:
            component_state = "resolved"

        row = [
            expand_button(),
            component,
            severities_rendr,
            format_state(component_state),
            RowExpansion(build_alerts_table(component_alerts)),
        ]
        components_rows.append(row)

    return build_expandable_table(
        ["", "Component", "Severity", "State"],
        components_rows,
    )


def expand_button(opened=False):
    button_class = "pf-v5-c-button pf-m-plain expand-component"
    icon_class = "fas fa-angle-right"
    if opened:
        button_class += " pf-m-expanded"
        icon_class = "fas fa-angle-down"
    return el(
        html.Button,
        button_class,
        [div("pf-v5-c-table__toggle-icon", [icon_el(icon_class)])],
    )


class RowExpansion:
    def __init__(self, content):
        # we don't modify this now, but in theory we can allow to expand by default
        self.expanded = False
        self.content = content


def alerts_timeline_figure(start, end, alerts):
    alerts = alerts.sort_values(
        ["rank_component", "rank_severity", "rank_state"],
    )
    alerts["label"] = alerts["component"] + " " + alerts["alertname"]
    fig = px.timeline(
        alerts.reset_index(drop=True),
        title="Alerts Timeline",
        x_start="start",
        x_end="end_default",
        range_x=(start, end),
        y="label",
        hover_data=[
            "alertname",
            "namespace",
            "rank_component",
            "rank_severity",
            "rank_state",
        ],
        color="severity",
        color_discrete_map={
            "info": COLORS["blue"],
            "warning": COLORS["orange"],
            "critical": COLORS["red"],
        },
        category_orders={"label": alerts["label"].unique()},
    )
    fig.update_yaxes(title="", showticklabels=True, side="right")
    alerts_lines_count = alerts["alertname"].nunique()
    # fig.update_layout(bargap=1, height=(140 + (alerts_lines_count * 18)))
    fig.update_layout(
        bargap=1,
        height=(100 + (alerts_lines_count * 20)),
        margin=dict(l=20, r=20, t=60, b=40),
    )
    fig.update_traces(width=0.5)
    fig.update_layout(showlegend=False)

    fig.update_layout(
        plot_bgcolor="white",
    )
    return fig


@app.callback(
    inputs=[
        Input("filter-mode", "value"),
        Input("incidents-selected", "value"),
        Input("incidents-timeline-graph", "clickData"),
        Input("time-window-size", "value"),
        Input("time-window-end", "date"),
        Input("refresh-link", "n_clicks"),
    ],
    output=[
        Output("incidents-timeline-graph", "figure"),
        Output("incidents-selected", "value"),
        Output("incidents-timeline-graph", "clickData"),
    ],
)
def update_incidents_timeline(
    filter_mode,
    incidents_selected_str,
    click_data,
    time_window_size,
    time_window_end,
    _refresh_link_n_clicks,
):
    start, end = get_start_end(time_window_size, time_window_end)

    df = load_incidents(start, end)
    df = filter_incidents(df, start, end, filter_mode)

    if df is None or df.empty:
        return no_data_fig("Incidents Timeline"), "", None

    fig = px.timeline(
        df,
        title="Incidents Timeline",
        x_start="chunk_start",
        x_end="chunk_end",
        range_x=(start, end),
        y="group_id",
        custom_data=["group_id"],
        color="health_severity",
        color_discrete_map={
            "healthy": COLORS["blue"],
            "warning": COLORS["orange"],
            "critical": COLORS["red"],
        },
    )

    fig.update_yaxes(
        title="",
        showticklabels=False,
    )

    incidents_count = df["group_id"].nunique()

    fig.update_layout(
        bargap=1,
        height=(100 + (incidents_count * 20)),
        margin=dict(l=0, r=0, t=60, b=40),
    )
    fig.update_traces(width=0.5)

    fig.update_layout(
        plot_bgcolor="white",
        showlegend=False,
    )

    incidents_selected = []
    if incidents_selected_str:
        incidents_selected = incidents_selected_str.split(",")
        incidents_selected = set(incidents_selected).intersection(set(df["group_id"]))

    incidents_clicked = selected_groups_from_click_data(click_data)
    if incidents_clicked:
        new_incidents_selected = []

        # Merge clicked incidents with already selected. Deselect if already selected.
        already_selected = list(set(incidents_clicked).intersection(incidents_selected))
        new_incidents_selected = set(incidents_selected).union(set(incidents_clicked))
        new_incidents_selected.difference_update(set(already_selected))
        incidents_selected = list(new_incidents_selected)

    # check one more time for cases that deselection left no groups selected
    if incidents_selected:
        fig.update(update_timeline_selection(fig.data, incidents_selected))
    incidents_selected_str = ",".join(incidents_selected)

    return (
        fig,
        incidents_selected_str,
        None,  # Setting clickData to None to allow clicking on the same group again
    )


@app.callback(
    inputs=[
        Input("filter-mode", "value"),
        Input("incidents-selected", "value"),
        Input("time-window-size", "value"),
        Input("time-window-end", "date"),
    ],
    output=[
        Output("alerts-timeline-graph", "figure"),
        Output("alerts", "children"),
    ],
)
def update_alerts_table(
    filter_mode,
    incidents_selected_str,
    time_window_size,
    time_window_end,
):
    start, end = get_start_end(time_window_size, time_window_end)

    group_ids = None
    if incidents_selected_str:
        group_ids = incidents_selected_str.split(",")
    else:
        incidents_df = load_incidents(start, end)
        incidents_df = filter_incidents(incidents_df, start, end, filter_mode)
        if incidents_df is not None:
            group_ids = list(incidents_df["group_id"].dropna().unique())

    alerts = load_alerts(start, end, group_ids=group_ids)

    if alerts is None:
        return no_data_fig("Alerts Timeline"), "No data"

    alerts = add_alerts_ranking(start, end, alerts)

    return (
        alerts_timeline_figure(start, end, alerts),
        build_components_alerts_table(alerts),
    )


# Used to provide expand/hide functionality.
app.clientside_callback(
    """
function(_) {
    registerExpandButtons();
}
""",
    # clientside callbacks need an output, so passing some dummy one.
    Output("dummy", "value"),
    Input("alerts", "children"),
)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8050)
