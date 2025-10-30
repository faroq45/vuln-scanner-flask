#!/usr/bin/env python3
"""
VulScanner Technical Documentation PDF Generator
Converts the technical documentation to a professional PDF format
"""

import os
import sys
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, 
    Table, TableStyle, Image, KeepTogether
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
import markdown
import re

class VulScannerPDFGenerator:
    def __init__(self):
        self.doc_file = "TECHNICAL_DOCUMENTATION.md"
        self.output_file = "VulScanner_Technical_Documentation.pdf"
        
        # Setup styles
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
        
        # Document elements
        self.story = []
        
    def setup_custom_styles(self):
        """Setup custom paragraph styles for the PDF"""
        
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            textColor=colors.HexColor('#2E86AB'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Heading 1 style
        self.styles.add(ParagraphStyle(
            name='CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor('#2E86AB'),
            spaceBefore=20,
            spaceAfter=12,
            fontName='Helvetica-Bold'
        ))
        
        # Heading 2 style
        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#1B5E5E'),
            spaceBefore=16,
            spaceAfter=8,
            fontName='Helvetica-Bold'
        ))
        
        # Heading 3 style
        self.styles.add(ParagraphStyle(
            name='CustomHeading3',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#1B5E5E'),
            spaceBefore=12,
            spaceAfter=6,
            fontName='Helvetica-Bold'
        ))
        
        # Code style
        self.styles.add(ParagraphStyle(
            name='CustomCode',
            parent=self.styles['Normal'],
            fontSize=9,
            fontName='Courier',
            textColor=colors.HexColor('#333333'),
            backColor=colors.HexColor('#F5F5F5'),
            borderColor=colors.HexColor('#CCCCCC'),
            borderWidth=1,
            borderPadding=8,
            leftIndent=20,
            rightIndent=20,
            spaceBefore=6,
            spaceAfter=6
        ))
        
        # Bullet point style
        self.styles.add(ParagraphStyle(
            name='BulletPoint',
            parent=self.styles['Normal'],
            fontSize=10,
            leftIndent=20,
            bulletIndent=10,
            spaceBefore=3,
            spaceAfter=3
        ))
        
        # Footer style
        self.styles.add(ParagraphStyle(
            name='Footer',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=colors.grey,
            alignment=TA_CENTER
        ))

    def create_cover_page(self):
        """Create the cover page"""
        
        # Main title
        title = Paragraph("VulScanner", self.styles['CustomTitle'])
        self.story.append(title)
        self.story.append(Spacer(1, 0.2*inch))
        
        # Subtitle
        subtitle = Paragraph("Technical Documentation", self.styles['CustomHeading1'])
        subtitle.style.alignment = TA_CENTER
        self.story.append(subtitle)
        self.story.append(Spacer(1, 0.5*inch))
        
        # Description
        description = Paragraph(
            "Comprehensive Web Application Vulnerability Scanner<br/>"
            "Built with Flask, Redis, and Advanced Security Testing Modules",
            self.styles['Normal']
        )
        description.style.alignment = TA_CENTER
        description.style.fontSize = 12
        self.story.append(description)
        self.story.append(Spacer(1, 1*inch))
        
        # Feature highlights box
        features_data = [
            ['Key Features', ''],
            ['OWASP Top 10 Coverage', 'Complete vulnerability detection'],
            ['Multi-threaded Scanning', 'Parallel processing with Redis'],
            ['RESTful API', 'Integration-ready endpoints'],
            ['Multiple Databases', 'SQLite, PostgreSQL, MySQL support'],
            ['VS Code Integration', 'Full development environment'],
            ['Real-time Progress', 'Live scan status tracking'],
        ]
        
        features_table = Table(features_data, colWidths=[2.5*inch, 3*inch])
        features_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (1, 0), colors.HexColor('#2E86AB')),
            ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (1, 0), 12),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F8F9FA')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#CCCCCC')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        self.story.append(features_table)
        self.story.append(Spacer(1, 1*inch))
        
        # Date and version info
        date_info = Paragraph(
            f"Generated: {datetime.now().strftime('%B %d, %Y')}<br/>"
            f"Platform: Windows<br/>"
            f"Python Version: {sys.version.split()[0]}",
            self.styles['Normal']
        )
        date_info.style.alignment = TA_CENTER
        date_info.style.fontSize = 10
        date_info.style.textColor = colors.grey
        self.story.append(date_info)
        
        self.story.append(PageBreak())

    def process_markdown_content(self, content):
        """Process markdown content and convert to PDF elements"""
        
        lines = content.split('\n')
        i = 0
        
        while i < len(lines):
            line = lines[i].strip()
            
            if not line:
                i += 1
                continue
                
            # Handle headers
            if line.startswith('# '):
                if 'VulScanner - Technical Documentation' in line:
                    # Skip the main title as we have a custom cover
                    i += 1
                    continue
                text = line[2:].strip()
                para = Paragraph(text, self.styles['CustomHeading1'])
                self.story.append(para)
                self.story.append(Spacer(1, 12))
                
            elif line.startswith('## '):
                text = line[3:].strip()
                para = Paragraph(text, self.styles['CustomHeading2'])
                self.story.append(para)
                self.story.append(Spacer(1, 8))
                
            elif line.startswith('### '):
                text = line[4:].strip()
                para = Paragraph(text, self.styles['CustomHeading3'])
                self.story.append(para)
                self.story.append(Spacer(1, 6))
                
            elif line.startswith('#### '):
                text = line[5:].strip()
                para = Paragraph(f"<b>{text}</b>", self.styles['Normal'])
                para.style.spaceBefore = 8
                para.style.spaceAfter = 4
                self.story.append(para)
                
            # Handle code blocks
            elif line.startswith('```'):
                code_content = []
                i += 1
                while i < len(lines) and not lines[i].strip().startswith('```'):
                    code_content.append(lines[i])
                    i += 1
                
                if code_content:
                    code_text = '\n'.join(code_content)
                    # Escape HTML characters and preserve formatting
                    code_text = code_text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    code_para = Paragraph(f"<pre>{code_text}</pre>", self.styles['CustomCode'])
                    self.story.append(code_para)
                    self.story.append(Spacer(1, 6))
                
            # Handle bullet points
            elif line.startswith('- '):
                text = line[2:].strip()
                # Handle bold text in bullets
                text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
                para = Paragraph(f"• {text}", self.styles['BulletPoint'])
                self.story.append(para)
                
            # Handle regular paragraphs
            elif line and not line.startswith('---'):
                # Handle bold text
                text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', line)
                # Handle inline code
                text = re.sub(r'`([^`]+)`', r'<font name="Courier" size="9">\1</font>', text)
                
                para = Paragraph(text, self.styles['Normal'])
                self.story.append(para)
                self.story.append(Spacer(1, 3))
            
            # Handle horizontal rules
            elif line.startswith('---'):
                self.story.append(Spacer(1, 12))
                # Add a line
                line_table = Table([[''], ['']], colWidths=[6*inch], rowHeights=[1, 1])
                line_table.setStyle(TableStyle([
                    ('LINEABOVE', (0, 1), (-1, 1), 1, colors.HexColor('#CCCCCC')),
                ]))
                self.story.append(line_table)
                self.story.append(Spacer(1, 12))
            
            i += 1

    def create_table_of_contents(self):
        """Create table of contents"""
        toc_title = Paragraph("Table of Contents", self.styles['CustomHeading1'])
        toc_title.style.alignment = TA_CENTER
        self.story.append(toc_title)
        self.story.append(Spacer(1, 20))
        
        # Manual TOC since we're processing markdown directly
        toc_items = [
            ("Overview", "21"),
            ("Technology Stack", "22"),
            ("Architecture", "23"),
            ("Dependencies", "24"),
            ("Core Components", "26"),
            ("Security Testing Modules", "28"),
            ("Attack Types & Vulnerabilities", "32"),
            ("Integrations", "36"),
            ("Database Schema", "38"),
            ("API Endpoints", "40"),
            ("Configuration", "42"),
            ("Development Workflow", "44"),
            ("VS Code Integration", "46"),
            ("Deployment", "48"),
        ]
        
        for title, page in toc_items:
            toc_line = Paragraph(
                f'{title} {"." * (60 - len(title))} {page}',
                self.styles['Normal']
            )
            toc_line.style.fontName = 'Courier'
            self.story.append(toc_line)
            self.story.append(Spacer(1, 3))
        
        self.story.append(PageBreak())

    def add_footer(self, canvas, doc):
        """Add footer to each page"""
        canvas.saveState()
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.grey)
        
        # Page number
        page_num = canvas.getPageNumber()
        canvas.drawRightString(letter[0] - 0.75*inch, 0.5*inch, f"Page {page_num}")
        
        # Document title
        canvas.drawString(0.75*inch, 0.5*inch, "VulScanner - Technical Documentation")
        
        canvas.restoreState()

    def generate_pdf(self):
        """Generate the complete PDF document"""
        
        print("🔄 Generating VulScanner Technical Documentation PDF...")
        
        # Check if markdown file exists
        if not os.path.exists(self.doc_file):
            print(f"❌ Error: {self.doc_file} not found!")
            return False
        
        try:
            # Create PDF document
            doc = SimpleDocTemplate(
                self.output_file,
                pagesize=letter,
                rightMargin=0.75*inch,
                leftMargin=0.75*inch,
                topMargin=1*inch,
                bottomMargin=1*inch
            )
            
            # Create cover page
            self.create_cover_page()
            
            # Create table of contents
            self.create_table_of_contents()
            
            # Read and process markdown content
            with open(self.doc_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.process_markdown_content(content)
            
            # Build PDF
            doc.build(self.story, onFirstPage=self.add_footer, onLaterPages=self.add_footer)
            
            print(f"✅ PDF generated successfully: {self.output_file}")
            print(f"📄 File size: {os.path.getsize(self.output_file):,} bytes")
            
            return True
            
        except Exception as e:
            print(f"❌ Error generating PDF: {str(e)}")
            return False

def main():
    """Main function to generate PDF"""
    generator = VulScannerPDFGenerator()
    success = generator.generate_pdf()
    
    if success:
        print("\n🎉 PDF generation completed!")
        print(f"📁 Location: {os.path.abspath(generator.output_file)}")
        
        # Try to open the PDF
        try:
            if os.name == 'nt':  # Windows
                os.startfile(generator.output_file)
                print("📖 Opening PDF in default viewer...")
        except:
            print("💡 Please open the PDF manually to view the documentation.")
    else:
        print("\n💥 PDF generation failed!")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())