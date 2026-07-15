"""Sentinel operator dashboard. Run with: streamlit run sentinel/dashboard/app.py

Reads live from the database on every rerun — it never trusts cached state
for anything security-relevant, and it never dispatches scan actions itself.
The only outbound call it makes is a best-effort control-plane POST to the
FastAPI kill switch endpoint, never to a scan target.
"""
from __future__ import annotations

import os
import tempfile

import httpx
import pandas as pd
import streamlit as st

from sentinel.agents.report_agent import build_summary, export_markdown, export_pdf
from sentinel.db.models import Finding, ScanSession, ScanStatus, TargetRegistration
from sentinel.db.session import get_session

KILLSWITCH_URL_TEMPLATE = "http://localhost:8000/api/scans/{scan_session_id}/halt"

STATUS_COLORS = {
    "confirmed": "background-color: #dc2626; color: white;",
    "unconfirmed": "background-color: #f59e0b; color: black;",
    "pending_verification": "background-color: #6b7280; color: white;",
}

st.set_page_config(page_title="Sentinel Pentest Dashboard", layout="wide")


def _session_label(scan_session: ScanSession, domain: str) -> str:
    started = scan_session.started_at.isoformat(sep=" ", timespec="seconds") if scan_session.started_at else "n/a"
    return f"{domain} — {started} — {scan_session.status.value}"


def _style_status(value: str) -> str:
    return STATUS_COLORS.get(value, "")


def _request_halt(scan_session_id: int) -> None:
    url = KILLSWITCH_URL_TEMPLATE.format(scan_session_id=scan_session_id)
    try:
        response = httpx.post(url, timeout=5.0)
        response.raise_for_status()
        st.success(f"Halt request sent for scan session {scan_session_id}.")
    except httpx.HTTPError as exc:
        st.error(f"Could not reach the Sentinel API to halt this scan: {exc}")


def main() -> None:
    st.title("Sentinel Pentest Dashboard")

    with get_session() as db:
        sessions = (
            db.query(ScanSession, TargetRegistration)
            .join(TargetRegistration, ScanSession.target_id == TargetRegistration.id)
            .order_by(ScanSession.started_at.desc())
            .all()
        )

        if not sessions:
            st.info("No scan sessions found yet. Register a target and start a scan first.")
            return

        labels = [_session_label(scan_session, reg.domain) for scan_session, reg in sessions]
        ids = [scan_session.id for scan_session, _ in sessions]

        with st.sidebar:
            st.header("Scan Sessions")
            selected_index = st.selectbox(
                "Active scan session",
                options=range(len(labels)),
                format_func=lambda i: labels[i],
            )
            st.divider()
            if st.button("Refresh"):
                st.rerun()

        scan_session_id = ids[selected_index]
        scan_session, registration = sessions[selected_index]

        if scan_session.status == ScanStatus.HALTED:
            st.error(f"HALTED — {scan_session.halted_reason or 'no reason recorded'}")

        summary = build_summary(db, scan_session_id)

        st.subheader(f"{registration.domain}")
        st.caption(summary["headline"])

        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Applicable CWEs", summary["applicable_cwe_count"])
        col2.metric("Not Applicable CWEs", summary["not_applicable_cwe_count"])
        col3.metric("Tested CWEs", summary["tested_cwe_count"])
        col4.metric("Confirmed Findings", summary["confirmed_count"])
        col5.metric("Unconfirmed Findings", summary["unconfirmed_count"])

        applicable = summary["applicable_cwe_count"]
        tested = summary["tested_cwe_count"]
        progress_ratio = (tested / applicable) if applicable else 0.0
        st.progress(min(max(progress_ratio, 0.0), 1.0))
        st.caption(f"CWE coverage: {tested}/{applicable} applicable CWEs tested")

        st.subheader("Findings")
        findings = db.query(Finding).filter(Finding.scan_session_id == scan_session_id).all()
        if findings:
            findings_df = pd.DataFrame([f.to_dict() for f in findings])
            styled = findings_df.style.map(_style_status, subset=["status"])
            st.dataframe(styled, use_container_width=True)
        else:
            st.write("No findings recorded for this scan session.")

        st.subheader("Reports")
        report_col1, report_col2 = st.columns(2)

        markdown_report = export_markdown(db, scan_session_id)
        report_col1.download_button(
            label="Download Markdown Report",
            data=markdown_report,
            file_name=f"sentinel_report_{scan_session_id}.md",
            mime="text/markdown",
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            pdf_path = os.path.join(tmp_dir, f"sentinel_report_{scan_session_id}.pdf")
            export_pdf(db, scan_session_id, pdf_path)
            with open(pdf_path, "rb") as pdf_file:
                pdf_bytes = pdf_file.read()

        report_col2.download_button(
            label="Download PDF Report",
            data=pdf_bytes,
            file_name=f"sentinel_report_{scan_session_id}.pdf",
            mime="application/pdf",
        )

        st.subheader("Controls")
        if scan_session.status == ScanStatus.RUNNING:
            if st.button("Halt Scan (kill switch)", type="primary"):
                _request_halt(scan_session_id)
        else:
            st.caption(f"Scan session status is '{scan_session.status.value}' — halt control is only active while running.")


main()
