# Accessibility audit evidence

Tracked by [issue #22](https://github.com/amanverasia/estudely-packet-explorer/issues/22).

## Implemented access

- Native controls, labelled table/grid/tree/dialog roles, visible keyboard focus, a trapped packet drawer with Escape dismissal and focus restoration, reduced-motion styles, and forced-colour styles.
- Overview chart data is available in an expandable table with a row per interval, exact packet/byte totals, and named protocol columns. Keyboard start/end inputs provide an alternative to dragging a time range.
- DNS relationship data is available in an expandable table with complete endpoint names and query counts, including pairs aggregated in the visual chart. It mounts only when expanded and uses pages of 50 relationships so a large capture does not create an unbounded table.
- Bar chart actions accept both Enter and Space.
- The Network list has host totals and link totals. Its Inspect host and Inspect link buttons select the same details shown by clicking the graph; the details region announces updates. Host focus/filter/detail actions and conversation navigation are available from these controls. The list follows the graph filters and identifies aggregated hosts.

## Automated checks

The existing `e2e/app.spec.ts` audit covers the start screen, protocol and host views, packet drawer, field-tree keyboard navigation and drawer focus trap in light and dark themes. Its contrast test measures the text/status/button palette at 4.5:1 and chart/focus palette at 3:1 on their supported surfaces. Axe checks rendered content against WCAG 2.1 A/AA rules; palette tests do not establish that every possible capture or assistive technology is accessible.

`e2e/accessibility.spec.ts` adds populated Files and QUIC/SSH/DHCP/ARP/ICMP views, expanded Overview/DNS tables, and Network host/link inspection in both themes. It verifies that interval packet totals equal the capture count and that Space activates a talker filter. These checks use local synthetic captures and the bundled axe-core script; captures never leave the browser.

Audit run on 7 October 2026, on Linux:

| Check | Chromium | Firefox |
| --- | --- | --- |
| Expanded chart tables, Network inspection, Space activation | Passed | Passed |
| Files and populated protocol dashboards, light/dark axe | Passed | Passed |
| Text, status, button, chart and focus palette contrast | Passed | Passed |
| Start screen, each covered view and drawer, light/dark axe | Passed | Passed |

The production build and TypeScript checks passed. Local WebKit could not launch because the host lacks `libavif.so.16`; this is an environment limitation, not a completed Safari accessibility check.

Run the focused checks after building:

```sh
npm run build
npx playwright test e2e/accessibility.spec.ts e2e/app.spec.ts --grep 'chart data|Files and populated|axe WCAG|text and chart colors' --project=chromium --project=firefox
```

## Manual screen-reader pass remains open

No NVDA or VoiceOver pass was performed. This Linux host cannot run those readers; an installed Orca binary is not evidence of a completed manual pass. Issue #22 remains open until the requested manual evidence is recorded. Automated role queries, keyboard tests and axe results must not be described as screen-reader testing.

For the manual pass, record the tester, operating system, browser and reader versions, commit or deployed version, fixture, date, and observed result for each step:

1. Start screen: read the local-processing notice, navigate headings, select a capture and announce loading, cancellation and failure states.
2. Open `dns.pcap`, `http.pcap`, `tls.pcap` and `protocols.pcap` as appropriate. Visit Overview, DNS, HTTP, Files, TLS, QUIC, SSH, DHCP, ARP, ICMP, Hosts, Connections, Network and Packets. Verify headings, control names, table headers/row values, search/sort/filter results, and empty states.
3. Expand Overview and DNS data tables. Read protocol/endpoint columns and totals, navigate the scroll area and relationship pages, and operate time-range inputs and talker buttons.
4. Expand the Network list. Inspect a host and link, verify announcements and details, and use host focus/filter and conversation actions.
5. Open a packet drawer from a keyboard-selected record. Verify its name/description, entry focus, source packet selection, expandable field-tree navigation and selection, byte data, focus trap, Escape dismissal and return focus.
6. Repeat representative controls with light/dark themes, reduced motion and operating-system high contrast. Record any defects with reproduction details and fix/retest them before marking the manual criterion complete.
