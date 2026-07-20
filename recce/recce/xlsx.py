"""Minimal .xlsx reader/writer using only the Python standard library.

Airgapped-friendly: no openpyxl, no third-party packages - just zipfile + XML.
Supports exactly the features this project needs:

  writing : multiple sheets, a fixed style palette (header/severity fills, bold,
            title), column widths, hidden columns, frozen header row, autofilter,
            a TRUE/FALSE data-validation dropdown, and "green when TRUE"
            conditional formatting.
  reading : cell values from both inline-string files (what we write) and
            shared-string files (what Excel writes when the operator saves),
            so tracking read-back survives a round-trip through Excel.

The style palette is fixed and baked into STYLES_XML; callers reference styles by
name via STYLE.
"""

from __future__ import annotations

import re
import zipfile
from xml.sax.saxutils import escape, quoteattr

# style name -> cellXfs index (see STYLES_XML below)
STYLE = {
    "default": 0, "header": 1, "bold": 2, "title": 3, "sub": 4, "boldred": 5,
    "sev_critical": 6, "sev_high": 7, "sev_medium": 8, "sev_low": 9,
    "sev_info": 10, "done": 11, "wrap": 12,
    # zebra-banding + row-separator variants used by the report writer so data
    # sheets get subtle alternating rows and clean rules instead of raw gridlines.
    "cell": 13, "cell_band": 14, "wrap_band": 15, "center": 16, "center_band": 17,
}

# Checkbox glyphs: an empty ballot box (off) and a checked one (on). These read
# as real checkboxes and are picked from a dropdown, working in Excel + LibreOffice.
CHECK_ON = "☑"    # ballot box with check
CHECK_OFF = "☐"   # ballot box

# Palette (AARRGGBB). A calmer, higher-contrast set than raw Office defaults:
#   header  = clean medium blue, white bold
#   band    = very light blue-grey for alternating rows
#   sev ramp: critical/high are solid with WHITE text (legible); medium/low/info
#             are soft tints with black text; done = soft green.
#   rule    = light-grey hairline under every data cell (row separator)
STYLES_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="6">
<font><sz val="11"/><color rgb="FF212121"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><color rgb="FF212121"/><name val="Calibri"/></font>
<font><b/><sz val="15"/><color rgb="FF1F3864"/><name val="Calibri"/></font>
<font><i/><sz val="10"/><color rgb="FF595959"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><color rgb="FFC00000"/><name val="Calibri"/></font>
</fonts>
<fills count="10">
<fill><patternFill patternType="none"/></fill>
<fill><patternFill patternType="gray125"/></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FF2F5496"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFF2F6FC"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFC00000"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFED7D31"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFFFC000"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFFFE699"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFDDEBF7"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFC6EFCE"/></patternFill></fill>
</fills>
<borders count="3">
<border><left/><right/><top/><bottom/><diagonal/></border>
<border><left/><right/><top/><bottom style="thin"><color rgb="FFDCE1E8"/></bottom><diagonal/></border>
<border><left/><right/><top/><bottom style="medium"><color rgb="FF1F3864"/></bottom><diagonal/></border>
</borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="18">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="1" fillId="2" borderId="2" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>
<xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/>
<xf numFmtId="0" fontId="3" fillId="0" borderId="0" xfId="0" applyFont="1"/>
<xf numFmtId="0" fontId="4" fillId="0" borderId="0" xfId="0" applyFont="1"/>
<xf numFmtId="0" fontId="5" fillId="0" borderId="1" xfId="0" applyFont="1" applyBorder="1"/>
<xf numFmtId="0" fontId="1" fillId="4" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center"/></xf>
<xf numFmtId="0" fontId="1" fillId="5" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center"/></xf>
<xf numFmtId="0" fontId="0" fillId="6" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center"/></xf>
<xf numFmtId="0" fontId="0" fillId="7" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center"/></xf>
<xf numFmtId="0" fontId="0" fillId="8" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center"/></xf>
<xf numFmtId="0" fontId="0" fillId="9" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="center"/></xf>
<xf numFmtId="0" fontId="0" fillId="3" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="center"/></xf>
<xf numFmtId="0" fontId="0" fillId="3" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf>
<xf numFmtId="0" fontId="0" fillId="3" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf>
</cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
<dxfs count="2"><dxf><fill><patternFill><bgColor rgb="FFC6EFCE"/></patternFill></fill></dxf><dxf><fill><patternFill><bgColor rgb="FFFFE699"/></patternFill></fill></dxf></dxfs>
</styleSheet>"""

_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
    '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
    "{sheet_overrides}</Types>"
)

_ROOT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
    "</Relationships>"
)


def col_letter(idx: int) -> str:
    """1-based column index -> spreadsheet column letters (1 -> A)."""
    s = ""
    while idx > 0:
        idx, rem = divmod(idx - 1, 26)
        s = chr(65 + rem) + s
    return s


class Sheet:
    def __init__(self, title: str):
        self.title = title
        self._rows: list[list[tuple]] = []   # each cell: (value, style_idx)
        self.col_widths: dict[int, float] = {}
        self.hidden_cols: set[int] = set()
        self.freeze_header = False
        self.freeze_cols = 0            # also freeze the first N columns (left pane)
        self.hide_gridlines = False     # hide native gridlines (we draw our own rules)
        self.header_height: float | None = None
        self.autofilter_cols = 0
        self._dv_rules: list[tuple[str, str]] = []   # (sqref, comma-joined list values)
        self._cf_rules: list[tuple[str, str, int]] = []  # (sqref, equals-value, dxfId)

    def write(self, cells: list) -> None:
        """Append a row. Each cell is a value or a (value, style_name) tuple."""
        row = []
        for c in cells:
            if isinstance(c, tuple):
                value, style = c
                row.append((value, STYLE.get(style, 0)))
            else:
                row.append((c, 0))
        self._rows.append(row)

    def set_col(self, idx: int, width: float, hidden: bool = False) -> None:
        self.col_widths[idx] = width
        if hidden:
            self.hidden_cols.add(idx)

    def _resolve_sqref(self, col_idx: int, first_row: int, last_row: int,
                       sqref: str | None) -> str | None:
        # `sqref` (a space-separated cell/range list) overrides the contiguous
        # range - used to skip N/A cells that must not get list validation.
        if sqref is not None:
            return sqref or None
        if last_row >= first_row:
            letter = col_letter(col_idx)
            return f"{letter}{first_row}:{letter}{last_row}"
        return None

    def dropdown(self, col_idx: int, first_row: int, last_row: int,
                 sqref: str | None = None, values: list[str] | None = None) -> None:
        """Attach a list-validation. Defaults to the ☑/☐ pair; pass `values` for a
        multi-state dropdown (e.g. a not-started / in-progress / done status)."""
        ref = self._resolve_sqref(col_idx, first_row, last_row, sqref)
        if ref:
            self._dv_rules.append((ref, ",".join(values or [CHECK_OFF, CHECK_ON])))

    def highlight_when_equal(self, col_idx: int, first_row: int, last_row: int,
                             value: str, dxf_id: int = 0,
                             sqref: str | None = None) -> None:
        """Conditional fill when a cell equals `value` (dxf_id: 0=green, 1=amber)."""
        ref = self._resolve_sqref(col_idx, first_row, last_row, sqref)
        if ref:
            self._cf_rules.append((ref, value, dxf_id))

    def green_when_true(self, col_idx: int, first_row: int, last_row: int,
                        sqref: str | None = None) -> None:
        self.highlight_when_equal(col_idx, first_row, last_row, CHECK_ON, 0, sqref)

    @property
    def nrows(self) -> int:
        return len(self._rows)

    # --- XML rendering ----------------------------------------------------------

    def _cols_xml(self) -> str:
        if not self.col_widths and not self.hidden_cols:
            return ""
        parts = []
        for idx in sorted(set(self.col_widths) | self.hidden_cols):
            width = self.col_widths.get(idx, 10)
            hidden = ' hidden="1"' if idx in self.hidden_cols else ""
            parts.append(f'<col min="{idx}" max="{idx}" width="{width:.2f}" '
                         f'customWidth="1"{hidden}/>')
        return "<cols>" + "".join(parts) + "</cols>"

    def _rows_xml(self) -> str:
        out = []
        for r, row in enumerate(self._rows, start=1):
            cells = []
            row_attr = f'<row r="{r}">'
            if r == 1 and self.header_height:
                row_attr = f'<row r="1" ht="{self.header_height:.0f}" customHeight="1">'
            for c, (value, style) in enumerate(row, start=1):
                if value is None or value == "":
                    if style:
                        cells.append(f'<c r="{col_letter(c)}{r}" s="{style}"/>')
                    continue
                ref = f"{col_letter(c)}{r}"
                s_attr = f' s="{style}"' if style else ""
                if isinstance(value, bool):
                    value = "TRUE" if value else "FALSE"
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    cells.append(f'<c r="{ref}"{s_attr}><v>{value}</v></c>')
                else:
                    text = escape(str(value))
                    cells.append(f'<c r="{ref}"{s_attr} t="inlineStr"><is><t xml:space="preserve">{text}</t></is></c>')
            out.append(row_attr + "".join(cells) + "</row>")
        return "".join(out)

    def _pane_xml(self) -> str:
        """Frozen pane: header row and/or the first N identity columns."""
        x, y = self.freeze_cols, (1 if self.freeze_header else 0)
        if not x and not y:
            return ""
        top_left = f"{col_letter(x + 1)}{y + 1}"
        active = "bottomRight" if (x and y) else ("topRight" if x else "bottomLeft")
        split = ""
        if x:
            split += f' xSplit="{x}"'
        if y:
            split += f' ySplit="{y}"'
        return (f'<pane{split} topLeftCell="{top_left}" activePane="{active}" '
                f'state="frozen"/>'
                f'<selection pane="{active}" activeCell="{top_left}" '
                f'sqref="{top_left}"/>')

    def to_xml(self) -> str:
        grid = ' showGridLines="0"' if self.hide_gridlines else ""
        pane = self._pane_xml()
        if pane:
            views = (f'<sheetViews><sheetView{grid} workbookViewId="0">'
                     f'{pane}</sheetView></sheetViews>')
        else:
            views = f'<sheetViews><sheetView{grid} workbookViewId="0"/></sheetViews>'

        autofilter = ""
        if self.autofilter_cols:
            autofilter = f'<autoFilter ref="A1:{col_letter(self.autofilter_cols)}1"/>'

        cf = ""
        for i, (sq, value, dxf_id) in enumerate(self._cf_rules):
            cf += (f'<conditionalFormatting sqref="{sq}">'
                   f'<cfRule type="cellIs" dxfId="{dxf_id}" priority="{i + 1}" operator="equal">'
                   f'<formula>"{value}"</formula></cfRule></conditionalFormatting>')

        dv = ""
        if self._dv_rules:
            body = ""
            for sq, values in self._dv_rules:
                body += (f'<dataValidation type="list" allowBlank="1" showInputMessage="1" '
                         f'showErrorMessage="1" sqref="{sq}"><formula1>"{values}"</formula1>'
                         f'</dataValidation>')
            dv = f'<dataValidations count="{len(self._dv_rules)}">{body}</dataValidations>'

        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            + views
            + '<sheetFormatPr defaultRowHeight="15"/>'
            + self._cols_xml()
            + "<sheetData>" + self._rows_xml() + "</sheetData>"
            + autofilter + cf + dv
            + "</worksheet>"
        )


class Workbook:
    def __init__(self):
        self.sheets: list[Sheet] = []

    def add_sheet(self, title: str) -> Sheet:
        sh = Sheet(title)
        self.sheets.append(sh)
        return sh

    def save(self, path: str) -> str:
        n = len(self.sheets)
        overrides = "".join(
            f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
            f'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            for i in range(1, n + 1)
        )
        content_types = _CONTENT_TYPES.format(sheet_overrides=overrides)

        # workbook.xml: sheet rIds 1..n, styles rId n+1.
        sheet_els = "".join(
            f'<sheet name={quoteattr(sh.title)} sheetId="{i}" r:id="rId{i}"/>'
            for i, sh in enumerate(self.sheets, start=1)
        )
        workbook_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            f"<sheets>{sheet_els}</sheets></workbook>"
        )
        rels = "".join(
            f'<Relationship Id="rId{i}" '
            f'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            f'Target="worksheets/sheet{i}.xml"/>'
            for i in range(1, n + 1)
        )
        rels += (f'<Relationship Id="rId{n + 1}" '
                 f'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
                 f'Target="styles.xml"/>')
        workbook_rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f"{rels}</Relationships>"
        )

        # Write to a temp file in the same dir, then atomically replace, so a
        # target that is open/locked (Excel) fails cleanly without corrupting the
        # existing file - essential for safe mid-scan refreshes.
        import os
        import tempfile

        directory = os.path.dirname(os.path.abspath(path))
        fd, tmp = tempfile.mkstemp(suffix=".xlsx", dir=directory)
        os.close(fd)
        try:
            with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("[Content_Types].xml", content_types)
                z.writestr("_rels/.rels", _ROOT_RELS)
                z.writestr("xl/workbook.xml", workbook_xml)
                z.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
                z.writestr("xl/styles.xml", STYLES_XML)
                for i, sh in enumerate(self.sheets, start=1):
                    z.writestr(f"xl/worksheets/sheet{i}.xml", sh.to_xml())
            os.replace(tmp, path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        return path


# --- reading --------------------------------------------------------------------

_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_R_NS = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
_CELL_RE = re.compile(r"([A-Z]+)(\d+)")


def _col_index(ref: str) -> int:
    m = _CELL_RE.match(ref)
    if not m:
        return 1
    letters = m.group(1)
    idx = 0
    for ch in letters:
        idx = idx * 26 + (ord(ch) - 64)
    return idx


def read_sheets(path: str) -> dict[str, list[list[str]]]:
    """Return {sheet_title: [ [cell_str, ...], ... ]}.

    Resolves both inline strings and shared strings, so it reads files this
    module writes AND files Excel/LibreOffice writes after the operator saves.
    """
    import xml.etree.ElementTree as ET

    result: dict[str, list[list[str]]] = {}
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())

        shared: list[str] = []
        if "xl/sharedStrings.xml" in names:
            root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            for si in root.findall(f"{_NS}si"):
                shared.append("".join(t.text or "" for t in si.iter(f"{_NS}t")))

        # Map sheet title -> worksheet part via workbook.xml + rels.
        wb_root = ET.fromstring(z.read("xl/workbook.xml"))
        rel_root = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
        rid_to_target = {
            r.get("Id"): r.get("Target")
            for r in rel_root.findall(
                "{http://schemas.openxmlformats.org/package/2006/relationships}Relationship")
        }
        title_to_part: dict[str, str] = {}
        for sh in wb_root.find(f"{_NS}sheets").findall(f"{_NS}sheet"):
            title = sh.get("name")
            rid = sh.get(f"{_R_NS}id")
            target = rid_to_target.get(rid, "")
            if target and not target.startswith("/"):
                target = "xl/" + target
            title_to_part[title] = target.lstrip("/")

        for title, part in title_to_part.items():
            if part not in names:
                result[title] = []
                continue
            sroot = ET.fromstring(z.read(part))
            data = sroot.find(f"{_NS}sheetData")
            rows_out: list[list[str]] = []
            if data is None:
                result[title] = rows_out
                continue
            for row in data.findall(f"{_NS}row"):
                cells: list[str] = []
                max_c = 0
                staged: dict[int, str] = {}
                for c in row.findall(f"{_NS}c"):
                    ref = c.get("r", "")
                    ci = _col_index(ref) if ref else (len(cells) + 1)
                    ctype = c.get("t", "")
                    val = ""
                    if ctype == "inlineStr":
                        is_el = c.find(f"{_NS}is")
                        if is_el is not None:
                            val = "".join(t.text or "" for t in is_el.iter(f"{_NS}t"))
                    elif ctype == "s":
                        v = c.find(f"{_NS}v")
                        if v is not None and v.text is not None:
                            try:
                                val = shared[int(v.text)]
                            except (ValueError, IndexError):
                                val = ""
                    else:
                        v = c.find(f"{_NS}v")
                        if v is not None:
                            val = v.text or ""
                    staged[ci] = val
                    max_c = max(max_c, ci)
                for i in range(1, max_c + 1):
                    cells.append(staged.get(i, ""))
                rows_out.append(cells)
            result[title] = rows_out
    return result
