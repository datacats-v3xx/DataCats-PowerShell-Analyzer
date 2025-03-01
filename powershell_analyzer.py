import sys
import os
import base64
import re
import hashlib
import datetime
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit,
    QFileDialog, QLabel, QProgressBar, QLineEdit, QPlainTextEdit, QCheckBox, QMessageBox
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
from fpdf import FPDF


# 🔓 **Deobfuscation Functions**
def decode_base64(encoded_text):
    """Attempts to decode a Base64 string and logs the result."""
    try:
        decoded_bytes = base64.b64decode(encoded_text)
        decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
        print(f"Decoded Base64: {decoded_text}")  # ✅ Log decoding results
        return decoded_text
    except Exception:
        return None


def decode_char_encoding(powershell_code):
    """Detects and converts PowerShell char obfuscation like '[char]72+[char]101' to 'Hello'."""
    matches = re.findall(r"\[char\](\d+)", powershell_code)
    if matches:
        decoded_string = ''.join(chr(int(num)) for num in matches)
        return decoded_string
    return None


# 🚨 **Detect Malicious Commands & Block Execution**
def detect_malicious_powershell(script_content):
    """Checks for dangerous PowerShell commands. If found, execution is blocked."""
    dangerous_patterns = {
        r"Invoke-Expression": "⚠️ Invoke-Expression (IEX) detected - Possible remote code execution",
        r"Invoke-WebRequest": "⚠️ Invoke-WebRequest detected - Possible remote file download",
        r"Start-Process": "⚠️ Start-Process detected - May launch external executables",
        r"Set-MpPreference": "⚠️ Set-MpPreference detected - Disables Windows Defender",
        r"New-ItemProperty": "⚠️ Registry Persistence detected - Script modifies startup settings"
    }
    
    warnings = [msg for pattern, msg in dangerous_patterns.items() if re.search(pattern, script_content, re.IGNORECASE)]
    
    if warnings:
        return warnings  # 🚨 Block execution if ANY dangerous command is found
    return None


# ⚠️ **PowerShell Risk Analysis**
def calculate_risk(script_content):
    """Assigns a dynamic risk score based on suspicious PowerShell commands."""
    risk_scores = {
        'Invoke-WebRequest': 50, 'Invoke-Expression': 40, 'Start-Process': 30,
        'Set-MpPreference': 25, 'Add-MpPreference': 20, 'IEX': 50
    }
    total_risk = sum(score for cmd, score in risk_scores.items() if cmd.lower() in script_content.lower())

    if total_risk > 100:
        risk_label = "CRITICAL 🔴"
    elif total_risk > 60:
        risk_label = "HIGH 🟠"
    elif total_risk > 30:
        risk_label = "MEDIUM 🟡"
    else:
        risk_label = "LOW 🟢"

    return total_risk, risk_label


# 🔍 **PowerShell Analyzer with Deobfuscation & Execution Blocking**
def analyze_script(script_content):
    """Runs multiple security checks and blocks execution if dangerous commands are found."""
    
    # 🛑 Step 1: Block Execution If Malicious Commands Are Found
    warnings = detect_malicious_powershell(script_content)
    if warnings:
        warning_message = "\n🚨 **Execution Blocked: Suspicious PowerShell Detected!**\n"
        for warning in warnings:
            warning_message += f"🔴 {warning}\n"
        return warning_message, 100, "CRITICAL 🔴"  # 🚨 Always return max risk score if execution is blocked

    # 🟢 Step 2: Attempt to decode Base64
    base64_matches = re.findall(r'FromBase64String\("([^"]+)"\)', script_content)
    decoded_b64_strings = [decode_base64(match) for match in base64_matches if decode_base64(match)]
    
    # 🟢 Step 3: Attempt to decode `[char]` obfuscation
    decoded_char_text = decode_char_encoding(script_content)

    # 🟢 Step 4: Construct output with decoded values
    analysis_result = "🔍 **PowerShell Analyzer Report**\n=================================\n"

    if decoded_b64_strings:
        analysis_result += "🛠 **Decoded Base64 Strings:**\n"
        for decoded in decoded_b64_strings:
            analysis_result += f"🔓 {decoded}\n"
    
    if decoded_char_text:
        analysis_result += f"\n🛠 **Decoded Char Encoding:**\n🔓 {decoded_char_text}\n"

    # 🟢 Step 5: Run risk analysis
    total_risk, risk_label = calculate_risk(script_content)
    
    analysis_result += f"\n⚠️ **Risk Level:** {risk_label}\n"

    return analysis_result, total_risk, risk_label


# 🚀 **Main GUI Application**
class PowerShellAnalyzer(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('🐾 PowerShell Analyzer')
        self.setGeometry(100, 100, 1200, 800)
        main_layout = QVBoxLayout()

        self.darkModeToggle = QCheckBox("🌙 Dark Mode")
        self.darkModeToggle.setChecked(True)
        self.darkModeToggle.stateChanged.connect(self.toggleDarkMode)
        main_layout.addWidget(self.darkModeToggle)

        self.searchBox = QLineEdit(self)
        self.searchBox.setPlaceholderText('🔍 Search analysis or code...')
        main_layout.addWidget(self.searchBox)

        self.codeView = QPlainTextEdit(self)
        self.codeView.setReadOnly(True)
        self.codeView.setFont(QFont('Consolas', 10))
        main_layout.addWidget(self.codeView)

        self.analysisView = QTextEdit(self)
        self.analysisView.setReadOnly(True)
        self.analysisView.setFont(QFont('Consolas', 10))
        main_layout.addWidget(self.analysisView)

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
        
        # Apply dark mode by default
        self.toggleDarkMode()

    def toggleDarkMode(self):
        """Toggles dark mode for the UI."""
        if self.darkModeToggle.isChecked():
            self.setStyleSheet("""
                QWidget { background-color: #1a1a2e; color: #f8f8f2; }
                QPushButton { background-color: #5a4b8a; color: #ffffff; font-weight: bold; padding: 8px; border-radius: 5px; }
                QPushButton:hover { background-color: #7b5fb3; }
            """)
        else:
            self.setStyleSheet("")
            
    def openFile(self):
        """Opens a PowerShell script file and analyzes it."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, 'Open PowerShell Script', '', 
            'PowerShell Scripts (*.ps1);;All Files (*)'
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    script_content = file.read()
                    
                # Display the script content
                self.codeView.setPlainText(script_content)
                
                # Analyze the script
                analysis_result, risk_score, risk_label = analyze_script(script_content)
                
                # Update the UI with analysis results
                self.analysisView.setText(analysis_result)
                self.riskLabel.setText(f'🛡 Risk Level: {risk_label}')
                self.riskBar.setValue(risk_score)
                
            except Exception as e:
                self.analysisView.setText(f"Error analyzing file: {str(e)}")
                self.riskLabel.setText('🛡 Risk Level: Error')
                self.riskBar.setValue(0)

    def export_report(self):
        """Exports the analysis results to a PDF report."""
        if not self.analysisView.toPlainText().strip():
            QMessageBox.warning(self, "Export Failed", "No analysis results to export!")
            return

        try:
            # Create a text version of the report with emojis replaced by text descriptions
            report_text = self.analysisView.toPlainText()
            # Replace emojis with text alternatives
            emoji_replacements = {
                "🔍": "[ANALYSIS]", 
                "🚨": "[ALERT]",
                "⚠️": "[WARNING]",
                "🔓": "[DECODED]",
                "🛠": "[TOOL]",
                "🔴": "[CRITICAL]",
                "🟠": "[HIGH]",
                "🟡": "[MEDIUM]",
                "🟢": "[LOW]",
                "🛡": "[PROTECTION]"
            }
            
            for emoji, replacement in emoji_replacements.items():
                report_text = report_text.replace(emoji, replacement)
            
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Helvetica", size=12)  # Use Helvetica instead of Arial
            
            # Add a title
            pdf.set_font("Helvetica", 'B', 16)
            pdf.cell(0, 10, "PowerShell Analysis Report", ln=True, align='C')
            pdf.ln(5)
            
            # Add timestamp
            pdf.set_font("Helvetica", size=10)
            pdf.cell(0, 10, f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
            pdf.ln(5)
            
            # Add the analysis content
            pdf.set_font("Helvetica", size=11)
            pdf.multi_cell(0, 7, report_text)

            save_path, _ = QFileDialog.getSaveFileName(self, "Save Report", "PowerShell_Analysis_Report.pdf", "PDF Files (*.pdf)")
            if save_path:
                pdf.output(save_path)
                QMessageBox.information(self, "Export Successful", f"Report saved as:\n{save_path}")
        
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export PDF: {str(e)}")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    analyzer = PowerShellAnalyzer()
    analyzer.show()
    sys.exit(app.exec_())
