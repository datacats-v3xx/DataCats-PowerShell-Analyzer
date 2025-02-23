from fpdf import FPDF, XPos, YPos  # Correct import for positional controls (finally)
import os
import sys
import base64
import re
import hashlib
import requests
import whois
from bs4 import BeautifulSoup
from fpdf import FPDF
from pygments import lex
from pygments.lexers import PowerShellLexer
from pygments.token import Token
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit,
    QFileDialog, QLabel, QProgressBar, QTabWidget, QLineEdit, QPlainTextEdit, QCheckBox, QMessageBox
)
from PyQt5.QtGui import QTextCharFormat, QColor, QFont, QSyntaxHighlighter, QPainter
from PyQt5.QtCore import Qt, QSettings

# YARA Integration
import yara
from yara_rules import yara_rules


def run_yara_analysis(script_content):
    """⚡ Run YARA rules against the provided PowerShell script content."""
    try:
        rules = yara.compile(source=yara_rules)
        matches = rules.match(data=script_content)
        return matches
    except Exception as e:
        print(f"⚠️ YARA analysis failed: {e}")
        return []


# PowerShell Syntax Highlighter
class PowerShellHighlighter(QSyntaxHighlighter):
    def __init__(self, parent):
        super(PowerShellHighlighter, self).__init__(parent)
        self.lexer = PowerShellLexer()
        self.styles = {
            Token.Keyword: self.format(QColor('#bd93f9'), 'bold'),
            Token.Name: self.format(QColor('#f8f8f2')),
            Token.Comment: self.format(QColor('#6272a4'), 'italic'),
            Token.String: self.format(QColor('#8be9fd')),
            Token.Operator: self.format(QColor('#ffb86c')),
            Token.Number: self.format(QColor('#bd93f9')),
            Token.Punctuation: self.format(QColor('#f8f8f2')),
            Token.Text: self.format(QColor('#f8f8f2')),
        }

    def format(self, color, style=''):
        _format = QTextCharFormat()
        _format.setForeground(color)
        if 'bold' in style:
            _format.setFontWeight(QFont.Bold)
        if 'italic' in style:
            _format.setFontItalic(True)
        return _format

    def highlightBlock(self, text):
        for token, content in lex(text, self.lexer):
            length = len(content)
            index = text.find(content)
            if index >= 0:
                self.setFormat(index, length, self.styles.get(token, QTextCharFormat()))


# Code Editor - Has problems with line numbers. Future work needed.
class CodeEditor(QPlainTextEdit):
    def __init__(self, parent=None):
        super(CodeEditor, self).__init__(parent)
        self.lineNumberArea = QWidget(self)
        self.suspicious_lines = set()
        self.blockCountChanged.connect(self.updateLineNumberAreaWidth)
        self.updateRequest.connect(self.updateLineNumberArea)
        self.cursorPositionChanged.connect(self.highlightCurrentLine)
        self.updateLineNumberAreaWidth(0)

    def lineNumberAreaWidth(self):
        digits = len(str(self.blockCount()))
        return 3 + self.fontMetrics().width('9') * digits

    def updateLineNumberAreaWidth(self, _=None):
        self.setViewportMargins(self.lineNumberAreaWidth(), 0, 0, 0)

    def updateLineNumberArea(self, rect, dy):
        if dy:
            self.lineNumberArea.scroll(0, dy)
        else:
            self.lineNumberArea.update(0, rect.y(), self.lineNumberArea.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self.updateLineNumberAreaWidth(0)

    def highlightCurrentLine(self):
        extraSelections = []
        if not self.isReadOnly():
            selection = QTextEdit.ExtraSelection()
            lineColor = QColor("#5a4b8a").lighter(160)  # Deep purple glow
            selection.format.setBackground(lineColor)
            selection.format.setProperty(QTextCharFormat.FullWidthSelection, True)
            selection.cursor = self.textCursor()
            selection.cursor.clearSelection()
            extraSelections.append(selection)
        self.setExtraSelections(extraSelections)


# Drag-and-Drop Text Editor - If it was actually working. PS drag/drop still needs work.
class DragDropTextEdit(QTextEdit):
    """✨ Supports drag-and-drop for PowerShell scripts."""

    def __init__(self, load_callback=None):
        super().__init__()
        self.load_callback = load_callback
        self.setAcceptDrops(True)
        self.setStyleSheet("""
            QTextEdit {
                border: 2px dashed #8a2be2;
                background-color: #1e1e2e;
                color: #f8f8f2;
                font-family: Consolas;
                font-size: 12pt;
            }
        """)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            if file_path.lower().endswith('.ps1'):
                self.load_callback(file_path)
            else:
                QMessageBox.warning(self, "⚠️ Unsupported File",
                                    "Only .ps1 PowerShell scripts are supported.")


# 🐾 Main Analyzer Application - The Prowler
class DataCatsAnalyzer(QWidget):
    def __init__(self):
        super().__init__()
        self.settings = QSettings('DataCats™', 'Preferences')
        self.dark_mode = self.settings.value('dark_mode', True, type=bool)
        self.initUI()

    def initUI(self):
        self.setWindowTitle('🐾 DataCats™: PowerShell Analyzer')
        self.setGeometry(100, 100, 1200, 800)
        main_layout = QVBoxLayout()

        self.darkModeToggle = QCheckBox("🌙 Dark Mode")
        self.darkModeToggle.setChecked(self.dark_mode)
        self.darkModeToggle.stateChanged.connect(self.toggleDarkMode)
        main_layout.addWidget(self.darkModeToggle)

        self.searchBox = QLineEdit(self)
        self.searchBox.setPlaceholderText('🔍 Search analysis or code...')
        self.searchBox.textChanged.connect(self.search_text)
        main_layout.addWidget(self.searchBox)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        self.codeView = CodeEditor(self)
        self.codeView.setReadOnly(True)
        self.codeView.setFont(QFont('Consolas', 10))
        self.highlighter = PowerShellHighlighter(self.codeView.document())
        self.tabs.addTab(self.codeView, "💻 Code View")

        self.analysisView = QTextEdit(self)
        self.analysisView.setReadOnly(True)
        self.analysisView.setFont(QFont('Consolas', 10))
        self.tabs.addTab(self.analysisView, "📊 Analysis")

        self.openBtn = QPushButton('📂 Open PowerShell Script')
        self.openBtn.clicked.connect(self.openFile)
        main_layout.addWidget(self.openBtn)

        self.exportBtn = QPushButton('📜 Export PDF Report')
        self.exportBtn.clicked.connect(self.export_report)
        main_layout.addWidget(self.exportBtn)

        self.riskLabel = QLabel('🛡 Risk Level: N/A')
        self.riskBar = QProgressBar(self)
        self.riskBar.setMaximum(100)
        main_layout.addWidget(self.riskLabel)
        main_layout.addWidget(self.riskBar)

        self.setLayout(main_layout)
        self.applyTheme()

    def toggleDarkMode(self):
        self.dark_mode = self.darkModeToggle.isChecked()
        self.settings.setValue('dark_mode', self.dark_mode)
        self.applyTheme()

    def applyTheme(self):
        if self.dark_mode:
            self.setStyleSheet("""
                QWidget { background-color: #1a1a2e; color: #f8f8f2; }
                QPushButton { background-color: #bd93f9; color: #1a1a2e; padding: 8px; border-radius: 5px; }
                QPushButton:hover { background-color: #caa7fa; }
                QLineEdit { background-color: #333; color: #f8f8f2; padding: 5px; }
                QTextEdit { background-color: #1a1a2e; color: #f8f8f2; }
                QTabWidget::pane { border: 1px solid #bd93f9; }
                QTabBar::tab { 
                    background: #2a2a3d; 
                    color: #e2e2f2; 
                    padding: 10px; 
                    border-radius: 4px;
                }
                QTabBar::tab:selected { 
                    background: #bd93f9; 
                    color: #1a1a2e; 
                    font-weight: bold;
                }
                QTabBar::tab:hover { 
                    background: #5a4b8a; 
                    color: #ffffff;
                }
            """)
        else:
            self.setStyleSheet("")

    def search_text(self, text):
        self.codeView.find(text)
        self.analysisView.find(text)

    def openFile(self):
        fileName, _ = QFileDialog.getOpenFileName(self, "Open PowerShell Script", "", "PowerShell Files (*.ps1)")
        if fileName:
            with open(fileName, 'r', encoding='utf-8') as file:
                code = file.read()
                self.codeView.setPlainText(code)
                self.analyzeScript(code)

    def analyzeScript(self, code):
        self.analysisView.clear()
        self.analysisView.append("=============================")
        self.analysisView.append("🔐 HASHES & IDENTIFIERS")
        self.analysisView.append("=============================")
        for htype, hval in self.generate_hashes(code).items():
            self.analysisView.append(f"• {htype}: {hval}")
        self.analysisView.append("\n")

        suspicious_cmds = {
            'Invoke-WebRequest': 40, 'Invoke-Expression': 30,
            'Set-MpPreference': 25, 'Add-MpPreference': 20,
            'Start-Process': 15, 'IEX': 40
        }
        total_risk = 0
        for idx, line in enumerate(code.split('\n')):
            for cmd, score in suspicious_cmds.items():
                if cmd.lower() in line.lower():
                    total_risk += score
                    self.analysisView.append(f"⚠️ [Line {idx + 1}] {cmd} ({score} pts)")
                    self.codeView.suspicious_lines.add(idx + 1)
        self.highlight_suspicious_lines()
        risk_label = "LOW 🟢" if total_risk < 30 else "MEDIUM 🟡" if total_risk < 60 else "HIGH 🟠" if total_risk < 90 else "CRITICAL 🔴"
        self.riskLabel.setText(f"🛡 Risk Level: {risk_label}")
        self.riskBar.setValue(min(total_risk, 100))

    def highlight_suspicious_lines(self):
        extraSelections = []
        for line_num in self.codeView.suspicious_lines:
            selection = QTextEdit.ExtraSelection()
            lineColor = QColor("#5a4b8a").lighter(160)
            selection.format.setBackground(lineColor)
            cursor = self.codeView.textCursor()
            cursor.movePosition(cursor.Start)
            cursor.movePosition(cursor.Down, cursor.MoveAnchor, line_num - 1)
            cursor.select(cursor.LineUnderCursor)
            selection.cursor = cursor
            extraSelections.append(selection)
        self.codeView.setExtraSelections(extraSelections)

    def generate_hashes(self, code):
        return {
            'SHA-256': hashlib.sha256(code.encode()).hexdigest(),
            'SHA-1': hashlib.sha1(code.encode()).hexdigest(),
            'MD5': hashlib.md5(code.encode()).hexdigest()
        }

    from fpdf import FPDF, XPos, YPos  # Ensures XPos and YPos are imported
    import os

    def export_report(self):
        try:
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()

            # 🐾 Use Segoe UI Emoji for full Unicode support because we like the damn paws.
            font_path = "C:\\Windows\\Fonts\\seguiemj.ttf"  # Segoe UI Emoji path - Native is good
            if os.path.exists(font_path):
                pdf.add_font('SegoeUIEmoji', '', font_path)  # Removed deprecated 'uni=True'
                pdf.set_font('SegoeUIEmoji', '', 16)
            else:
                QMessageBox.warning(self, "⚠️ Font Missing", "Segoe UI Emoji not found. Some icons may not display.")
                pdf.set_font('Arial', size=16)

            pdf.set_text_color(0, 0, 0)

            # Title with corrected XPos/YPos usage
            pdf.cell(200, 10, text="🐾 DataCats™ - IR Analysis Report",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')

            # Analysis Section Header
            pdf.set_font('SegoeUIEmoji', '', 12)
            pdf.set_text_color(0, 0, 255)
            pdf.cell(0, 10, text="🔎 Analysis Section",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            # Analysis Content
            pdf.set_font('SegoeUIEmoji', '', 10)
            pdf.set_text_color(0, 0, 0)
            pdf.multi_cell(0, 8, self.analysisView.toPlainText())

            # Footer with Signature (Fixed line finally)
            pdf.set_y(-20)
            pdf.set_font('SegoeUIEmoji', '', 10)  # 🐾 Fixed this line
            pdf.set_text_color(128, 128, 128)
            pdf.cell(0, 10, text="🐾 Powered by DataCats™: Always lands on its feet. 😼✨",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')

            # Export PDF - Adding a save as window might be preferable. Undecided.
            pdf.output("DataCats_IR_Report.pdf")
            QMessageBox.information(self, "✅ Export Complete", "Saved as 'DataCats_IR_Report.pdf'")

        except Exception as e:
            QMessageBox.critical(self, "⚠️ Export Failed", f"An error occurred:\n{str(e)}")
if __name__ == '__main__':
    import sys
    from PyQt5.QtWidgets import QApplication

    app = QApplication(sys.argv)
    datacats = DataCatsAnalyzer()  # Make sure the class name matches exactly
    datacats.show()                # Show the main window
    sys.exit(app.exec_())          # Start Qt event loop (use exec_() for PyQt5)
