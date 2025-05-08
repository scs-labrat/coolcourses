import os
import shutil
import markdown
import glob
import re
from datetime import datetime

# --- Configuration ---
SOURCE_DIR = "."
OUTPUT_DIR = os.path.join(SOURCE_DIR, "generated_website")
COURSE_TITLE = "Nothing Cyber - Threat Hunting 101"
COURSE_NAV_TITLE = "Threat Hunting 101" # Can be same as COURSE_TITLE

PRESENTATION_DIR_NAME = "presentation"
COURSE_OUTLINE_MD_NAME = "course_outline.md"
MODULE_MD_PATTERN_STR = "module_*.md"
MODULE_PRESENTATION_MD_PATTERN_STR = "module_*_presentation.md"

MAIN_CSS_FILE_NAME = "style.css"
PRINT_CSS_FILE_NAME = "print.css"

NEW_MAIN_CSS_CONTENT = """
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@300;400;500;600;700&display=swap');

:root {
  --font-body: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
  --font-heading: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
  --font-code: 'JetBrains Mono', 'SFMono-Regular', Consolas, "Liberation Mono", Menlo, Courier, monospace;

  --bg-primary: #0d1117;
  --bg-secondary: #161b22;
  --bg-tertiary: #010409;
  --bg-overlay: rgba(1, 4, 9, 0.8); /* For blurred backgrounds */

  --text-primary: #c9d1d9;
  --text-secondary: #8b949e;
  --text-heading: #e6edf3;
  --text-link: #58a6ff;
  --text-link-hover: #79c0ff;

  --border-primary: #30363d;
  --border-secondary: #21262d;
  --border-focus: var(--text-link);

  --accent-primary: #58a6ff; /* Blue */
  --accent-primary-glow: rgba(88, 166, 255, 0.2);
  --accent-secondary: #3fb950; /* Green */
  --accent-warning: #f0b948; /* Yellow/Orange */
  --accent-danger: #f85149; /* Red */

  --code-bg: #1A1B26; /* Slightly different for code */
  --code-text: #c9d1d9;
  --code-border: var(--border-secondary);

  --shadow-sm: 0 1px 2px 0 rgba(1, 4, 9, 0.15);
  --shadow-md: 0 4px 6px -1px rgba(1, 4, 9, 0.15), 0 2px 4px -1px rgba(1, 4, 9, 0.1);
  --shadow-lg: 0 10px 15px -3px rgba(1, 4, 9, 0.15), 0 4px 6px -2px rgba(1, 4, 9, 0.1);

  --border-radius-sm: 4px;
  --border-radius-md: 6px;
  --border-radius-lg: 8px;

  --navbar-height: 60px;
  --transition-speed: 0.2s;
}

*, *::before, *::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

html {
  scroll-behavior: smooth;
}

body {
  background: var(--bg-primary);
  color: var(--text-primary);
  font-family: var(--font-body);
  font-size: 1rem; /* 16px base */
  line-height: 1.7;
  padding-top: var(--navbar-height); /* Space for fixed navbar */
}

.content-wrapper {
  max-width: 880px;
  margin: 0 auto;
  padding: 2rem 1.5rem; /* Page content padding */
}

/* --- Navbar --- */
.navbar {
  background: var(--bg-overlay);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border-bottom: 1px solid var(--border-secondary);
  box-shadow: var(--shadow-sm);
  padding: 0 2rem; /* Horizontal padding */
  height: var(--navbar-height);
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  z-index: 1000;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.navbar-brand {
  font-family: var(--font-heading);
  font-size: 1.5rem; /* 24px */
  font-weight: 700;
  color: var(--text-heading);
  text-decoration: none;
  border-bottom: none;
  transition: color var(--transition-speed) ease;
}
.navbar-brand:hover {
  color: var(--text-link-hover);
}

.navbar-links {
  list-style: none;
  display: flex;
  align-items: center;
}

.navbar-links > li {
  margin-left: 1.5rem; /* Spacing between top-level nav items */
  position: relative; /* For dropdown positioning */
}

.navbar-links a, .navbar-links .nav-dropdown-toggle {
  color: var(--text-secondary);
  text-decoration: none;
  font-size: 0.9375rem; /* 15px */
  font-weight: 500;
  padding: 0.5rem 0.25rem;
  border-bottom: 2px solid transparent;
  transition: color var(--transition-speed) ease, border-color var(--transition-speed) ease;
  cursor: pointer;
  display: block; /* Ensure padding is applied correctly */
}

.navbar-links a:hover,
.navbar-links .nav-dropdown-toggle:hover,
.navbar-links a.active,
.navbar-links .nav-dropdown.active .nav-dropdown-toggle { /* Keep toggle highlighted when dropdown is open/active */
  color: var(--text-link-hover);
  border-bottom-color: var(--text-link);
}

/* Dropdown Menu */
.nav-dropdown {
  position: relative;
}

.nav-dropdown-toggle::after { /* Simple arrow for dropdown */
  content: ' ▼';
  font-size: 0.7em;
  margin-left: 0.3em;
  display: inline-block;
  transition: transform var(--transition-speed) ease;
}
.nav-dropdown:hover .nav-dropdown-toggle::after {
  transform: rotate(180deg);
}


.dropdown-menu {
  display: none;
  position: absolute;
  top: 100%; /* Position below the toggle */
  left: 50%;
  transform: translateX(-50%);
  min-width: 200px;
  background: var(--bg-secondary);
  border: 1px solid var(--border-primary);
  border-radius: var(--border-radius-md);
  box-shadow: var(--shadow-md);
  list-style: none;
  padding: 0.5rem 0;
  margin-top: 0.5rem; /* Small gap */
  z-index: 1100;
  opacity: 0;
  visibility: hidden;
  transition: opacity var(--transition-speed) ease, visibility var(--transition-speed) ease, transform 0.1s ease;
  transform-origin: top center;
}

.nav-dropdown:hover .dropdown-menu {
  display: block;
  opacity: 1;
  visibility: visible;
  transform: translateX(-50%) translateY(0);
}

.dropdown-menu li a {
  display: block;
  padding: 0.6rem 1.2rem;
  color: var(--text-primary);
  font-size: 0.9rem;
  border-bottom: none; /* Remove default link border */
  white-space: nowrap;
}
.dropdown-menu li a:hover {
  background-color: var(--accent-primary-glow);
  color: var(--text-link-hover);
}
.dropdown-menu li a.active {
  background-color: var(--accent-primary-glow);
  color: var(--text-link);
  font-weight: 600;
}


/* --- Headings & Text --- */
h1, h2, h3, h4, h5, h6 {
  font-family: var(--font-heading);
  color: var(--text-heading);
  margin-top: 2.8rem;
  margin-bottom: 1.2rem;
  line-height: 1.3;
  font-weight: 600;
}

h1 { font-size: 2.5rem; border-bottom: 1px solid var(--border-primary); padding-bottom: 0.6rem; font-weight: 700;}
h2 { font-size: 2rem; border-bottom: 1px solid var(--border-secondary); padding-bottom: 0.5rem;}
h3 { font-size: 1.5rem; color: var(--text-primary); }
h4 { font-size: 1.25rem; color: var(--text-secondary); font-weight: 500; }

p, ul, ol {
  margin-bottom: 1.25rem;
  color: var(--text-primary);
}
ul, ol {
  padding-left: 1.5rem;
}
li {
  margin-bottom: 0.5rem;
}

a {
  color: var(--text-link);
  text-decoration: none;
  border-bottom: 1px solid transparent; /* Subtle underline on hover */
  transition: color var(--transition-speed) ease, border-color var(--transition-speed) ease;
}
a:hover {
  color: var(--text-link-hover);
  border-bottom-color: var(--text-link-hover);
}
article a { /* Links within main content */
    border-bottom: 1px dashed var(--text-link);
}
article a:hover {
    border-bottom-style: solid;
}


hr {
  border: 0;
  height: 1px;
  background: var(--border-primary);
  margin: 3rem 0;
}

/* --- Code Blocks --- */
code { /* Inline code */
  font-family: var(--font-code);
  background: var(--bg-secondary);
  color: var(--accent-secondary);
  padding: 0.25em 0.5em;
  border-radius: var(--border-radius-sm);
  font-size: 0.9em;
  border: 1px solid var(--border-secondary);
}

pre {
  background: var(--code-bg);
  color: var(--code-text);
  font-family: var(--font-code);
  font-size: 0.9rem; /* 14.4px */
  line-height: 1.6;
  padding: 1.25rem;
  border: 1px solid var(--code-border);
  border-radius: var(--border-radius-md);
  overflow-x: auto;
  margin: 1.5rem 0 2rem 0;
  box-shadow: var(--shadow-sm);
  transition: box-shadow var(--transition-speed) ease;
}
pre:hover {
  box-shadow: 0 0 15px var(--accent-primary-glow);
}
pre code { /* Reset for code inside pre, as Pygments handles it */
  background: transparent;
  color: inherit;
  padding: 0;
  border: none;
  font-size: inherit;
  line-height: inherit;
}

pre.output {
  background: var(--bg-tertiary);
  color: var(--text-link); /* Using link color for output */
  border-left: 4px solid var(--accent-primary);
  font-style: italic;
}

/* Pygments (for .highlight class from markdown extension) */
.highlight .c { color: #8b949e; font-style: italic; } /* Comment */
.highlight .k { color: #ff7b72; } /* Keyword */
.highlight .kn { color: #ff7b72; }
.highlight .kp { color: #ff7b72; }
.highlight .kr { color: #ff7b72; }
.highlight .kt { color: #ff7b72; }
.highlight .o { color: #ff7b72; } /* Operator */
.highlight .ow { color: #ff7b72; }
.highlight .s { color: #a5d6ff; } /* String */
.highlight .s1 { color: #a5d6ff; }
.highlight .s2 { color: #a5d6ff; }
.highlight .sd { color: #a5d6ff; font-style: italic; }
.highlight .se { color: #a5d6ff; }
.highlight .si { color: #a5d6ff; }
.highlight .sr { color: #a5d6ff; }
.highlight .na { color: #79c0ff; } /* Name.Attribute */
.highlight .nc { color: #ffa657; } /* Name.Class */
.highlight .nf { color: #d2a8ff; } /* Name.Function */
.highlight .nn { color: #ffa657; } /* Name.Namespace */
.highlight .nt { color: #7ee787; } /* Name.Tag */
.highlight .nv { color: #ffa657; } /* Name.Variable */
.highlight .m { color: #a5d6ff; } /* Number */
.highlight .mi { color: #a5d6ff; }
.highlight .mf { color: #a5d6ff; }
.highlight .p { color: #c9d1d9; } /* Punctuation */
.highlight .err { background-color: var(--accent-danger); color: var(--text-heading); padding: 0.1em; }

/* --- Tables --- */
.table-wrapper { /* Add this class around tables in MD if possible, or use JS */
  overflow-x: auto;
  margin: 2rem 0;
  border: 1px solid var(--border-primary);
  border-radius: var(--border-radius-md);
  box-shadow: var(--shadow-sm);
}
table {
  width: 100%;
  border-collapse: collapse;
  background-color: var(--bg-secondary);
  font-size: 0.9375rem; /* 15px */
}
th, td {
  padding: 0.8rem 1rem;
  border: 1px solid var(--border-primary);
  text-align: left;
  vertical-align: top;
}
th {
  background-color: var(--bg-tertiary);
  font-weight: 600;
  color: var(--text-heading);
}
tr:nth-child(even) {
  background-color: var(--bg-primary); /* Slightly darker for striping */
}
tr:hover {
  background-color: rgba(88, 166, 255, 0.05); /* Subtle hover */
}

/* --- Blockquotes & Callouts --- */
blockquote {
  border-left: 4px solid var(--accent-primary);
  background: var(--bg-secondary);
  padding: 1rem 1.5rem;
  margin: 1.75rem 0;
  color: var(--text-secondary);
  font-style: italic;
  border-radius: 0 var(--border-radius-sm) var(--border-radius-sm) 0;
}
blockquote p:last-child { margin-bottom: 0; }

.callout {
  padding: 1.25rem 1.5rem;
  border-left-width: 5px;
  border-left-style: solid;
  border-radius: var(--border-radius-md);
  margin: 2rem 0;
  box-shadow: var(--shadow-sm);
}
.callout p:last-child, .callout ul:last-child, .callout ol:last-child { margin-bottom: 0; }
.callout strong { color: inherit; } /* Make strong text inherit callout color */

.callout.info { background-color: rgba(88,166,255,0.1); border-color: var(--accent-primary); color: var(--text-link); }
.callout.tip { background-color: rgba(63,185,80,0.1); border-color: var(--accent-secondary); color: var(--accent-secondary); }
.callout.alert { background-color: rgba(248,81,73,0.1); border-color: var(--accent-danger); color: var(--accent-danger); }
.callout.warning { background-color: rgba(240,185,72,0.1); border-color: var(--accent-warning); color: var(--accent-warning); }


.note {
  font-size: 0.9rem;
  font-style: italic;
  color: var(--text-secondary);
  background: var(--bg-secondary);
  padding: 1rem 1.5rem;
  margin: 1.5rem 0;
  border-left: 3px solid var(--border-primary);
  border-radius: 0 var(--border-radius-sm) var(--border-radius-sm) 0;
}
.note p:last-child { margin-bottom: 0; }

/* --- TOC (Table of Contents) --- */
.toc {
  background: var(--bg-secondary);
  border: 1px solid var(--border-primary);
  padding: 1.5rem;
  margin: 2.5rem 0;
  border-radius: var(--border-radius-md);
  font-size: 0.9rem;
  box-shadow: var(--shadow-sm);
}
.toc .toctitle, .toc p:first-child { /* .toctitle for [TOC], p:first-child if it's just text */
  font-weight: 600;
  color: var(--text-heading);
  margin-bottom: 1rem;
  font-size: 1.1em;
}
.toc ul { list-style: none; padding-left: 0; }
.toc ul ul { padding-left: 1rem; margin-top: 0.3rem; } /* Indent sub-items */
.toc li { margin-bottom: 0.4rem; }
.toc a {
  color: var(--text-primary);
  border-bottom: 1px dotted transparent;
}
.toc a:hover {
  color: var(--text-link-hover);
  border-bottom-color: var(--text-link-hover);
}

/* --- Footnotes --- */
.footnote {
  font-size: 0.875rem;
  color: var(--text-secondary);
  border-top: 1px solid var(--border-secondary);
  margin-top: 3.5rem;
  padding-top: 1.5rem;
}
.footnote hr { display: none; }
.footnote ol { padding-left: 1.2rem; }
.footnote p { margin-bottom: 0.5rem; }


/* --- Landing Page Specifics --- */
.landing-hero {
  text-align: center;
  padding: 3rem 1rem 2rem 1rem;
  margin-bottom: 2rem;
}
.landing-hero h1 {
  font-size: 3rem; /* Larger for hero */
  border-bottom: none;
  color: var(--text-heading);
  margin-bottom: 1rem;
}
.landing-hero p {
  font-size: 1.15rem;
  color: var(--text-primary);
  max-width: 700px;
  margin: 0 auto 2.5rem auto;
}
.landing-links-section {
  text-align: center;
}
.landing-links-section h2 {
    border-bottom: none;
    margin-bottom: 1.5rem;
    font-size: 1.8rem;
}
.landing-links-list {
  list-style: none;
  padding: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1rem;
}
.landing-links-list li a {
  display: inline-block;
  background: transparent;
  color: var(--text-link);
  border: 2px solid var(--text-link);
  padding: 0.75rem 2rem;
  border-radius: var(--border-radius-md);
  font-family: var(--font-heading);
  font-weight: 500;
  font-size: 1.1rem;
  text-decoration: none;
  transition: background-color var(--transition-speed) ease, color var(--transition-speed) ease, transform var(--transition-speed) ease;
  box-shadow: 0 0 8px var(--accent-primary-glow);
}
.landing-links-list li a:hover {
  background-color: var(--text-link);
  color: var(--bg-primary);
  transform: translateY(-2px);
  box-shadow: 0 4px 15px var(--accent-primary-glow);
}


/* --- Footer --- */
.footer {
  text-align: center;
  padding: 2.5rem 1rem 1.5rem 1rem;
  margin-top: 4rem;
  border-top: 1px solid var(--border-secondary);
  font-size: 0.875rem;
  color: var(--text-secondary);
}

/* --- Responsive Design --- */
@media (max-width: 768px) {
  body { padding-top: calc(var(--navbar-height) + 10px); /* A bit more if navbar wraps */ }
  .content-wrapper { padding: 1.5rem 1rem; }
  .navbar { padding: 0 1rem; flex-direction: column; height: auto; align-items: flex-start; }
  .navbar-brand { margin-bottom: 0.5rem; padding: 0.5rem 0;}
  .navbar-links { flex-direction: column; width: 100%; align-items: flex-start; }
  .navbar-links > li { margin-left: 0; width: 100%; }
  .navbar-links a, .navbar-links .nav-dropdown-toggle { padding: 0.6rem 0; width:100%; }
  
  .nav-dropdown:hover .dropdown-menu { /* Adjust dropdown for mobile */
    left: 0;
    transform: translateX(0);
    width: 100%;
    margin-top: 0.2rem;
  }
  .nav-dropdown-toggle::after { display: inline-block; } /* Ensure arrow shows on mobile */


  h1 { font-size: 2.1rem; }
  h2 { font-size: 1.75rem; }
  h3 { font-size: 1.3rem; }

  .landing-hero h1 { font-size: 2.5rem; }
  .landing-hero p { font-size: 1.05rem; }
}

@media (max-width: 480px) {
    .navbar-brand { font-size: 1.3rem; }
    .navbar-links a, .navbar-links .nav-dropdown-toggle { font-size: 0.9rem; }
    h1 { font-size: 1.9rem; }
    h2 { font-size: 1.6rem; }
}
"""

PRINT_CSS_CONTENT = """
@media print {
  body {
    background: white !important;
    color: black !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 10pt !important;
    max-width: 100% !important;
    padding: 1in !important;
    margin: 0 !important;
  }
  .navbar, .footer, .toc { display: none !important; } /* Hide elements not for print */
  
  h1, h2, h3, h4, h5, h6 {
    color: black !important;
    border-bottom-color: #ccc !important;
    page-break-after: avoid !important;
    font-family: 'Inter', sans-serif !important; /* Ensure heading font is consistent */
  }
  a {
    color: #0000EE !important; 
    text-decoration: underline !important;
    border-bottom: none !important;
  }
  a[href^="http"]:after, a[href^="https"]:after {
    content: " (" attr(href) ")";
    font-size: 0.8em;
    font-weight: normal; /* Avoid bolding URLs */
  }
  a[href^="#"]:after { content: ""; } /* Don't show URL for fragment links */
  
  pre, code {
    background: #f0f0f0 !important;
    color: black !important;
    border: 1px solid #ddd !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 9pt !important;
    white-space: pre-wrap !important;
    word-wrap: break-word !important;
    page-break-inside: avoid !important;
    box-shadow: none !important;
  }
  code { padding: 0.1em 0.2em !important; } /* Slightly smaller padding for inline code */

  .callout, .sidebar, .note {
    border: 1px solid #ccc !important;
    background: #f9f9f9 !important;
    color: black !important;
    padding: 0.5em !important;
    margin: 1em 0 !important;
    page-break-inside: avoid !important;
    box-shadow: none !important;
  }
  .callout.tip { border-left-color: #22c55e !important; }
  .callout.alert { border-left-color: #ef4444 !important; }
  .callout.info { border-left-color: #2a9d8f !important; }
  .callout.warning { border-left-color: #f0b948 !important; }
  
  table, th, td {
    border: 1px solid #ccc !important;
    color: black !important;
    page-break-inside: avoid !important;
    font-size: 9pt !important;
  }
  th { background-color: #eee !important; font-weight: bold !important; }
  tr:nth-child(even) { background-color: #f9f9f9 !important; }
  
  blockquote {
    border-left-color: #ccc !important;
    background: #f9f9f9 !important;
    color: #333 !important;
    font-style: italic !important;
    padding: 0.5em 1em !important;
  }
  .footnote {
    color: #444 !important;
    font-size: 0.8em !important;
    border-top-color: #ccc !important;
    margin-top: 1.5em !important;
    padding-top: 0.5em !important;
  }
  .footnote hr { display: none !important; }
  article img { max-width: 100% !important; page-break-inside: avoid !important; }
}
"""

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link rel="stylesheet" href="{main_css_path}">
    <link rel="stylesheet" href="{print_css_path}" media="print">
</head>
<body>
    <nav class="navbar">
        <a href="index.html" class="navbar-brand">{course_nav_title}</a>
        <ul class="navbar-links">
            <li><a href="index.html" class="{active_home}">Home</a></li>
            <li><a href="course_outline.html" class="{active_outline}">Course Outline</a></li>
            {modules_dropdown_li}
        </ul>
    </nav>
    <main class="content-wrapper">
        <article>
{content}
        </article>
    </main>
    <footer class="footer">
        <p>© {year} {course_title}. Generated on {generation_date}.</p>
    </footer>
</body>
</html>
"""

# --- Helper Functions ---
def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def read_file_content(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Warning: File not found '{filepath}'")
        return None

def write_file_content(filepath, content):
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

def extract_module_title(md_content, module_num):
    if not md_content:
        return f"Module {module_num}"
    pattern_bold_title = re.compile(r"^\s*\*\*(?:Module\s*" + str(module_num) + r":\s*)(.+?)\*\*\s*$", re.MULTILINE | re.IGNORECASE)
    match = pattern_bold_title.search(md_content)
    if match:
        return match.group(1).strip().strip('"')
    heading_patterns = [
        re.compile(r"^#\s*(?:Module\s*" + str(module_num) + r"(?::|-)?\s*)(.+?)\s*#*\s*$", re.MULTILINE | re.IGNORECASE),
        re.compile(r"^##\s*(?:Module\s*" + str(module_num) + r"(?::|-)?\s*)(.+?)\s*#*\s*$", re.MULTILINE | re.IGNORECASE),
    ]
    for pattern in heading_patterns:
        match = pattern.search(md_content)
        if match:
            title_candidate = match.group(1).strip().strip('"')
            if not re.fullmatch(r"Module\s*\d+", title_candidate, re.IGNORECASE) and title_candidate:
                return title_candidate
    h1_pattern = re.compile(r"^#\s+(.+?)\s*#*\s*$", re.MULTILINE)
    first_few_lines = "\n".join(md_content.splitlines()[:15])
    h1_match = h1_pattern.search(first_few_lines)
    if h1_match:
        title = h1_match.group(1).strip().strip('"')
        if not re.match(r"^Module\s*\d+\s*$", title, re.IGNORECASE) and len(title.split()) > 1:
            return title
    h2_pattern = re.compile(r"^##\s+(.+?)\s*#*\s*$", re.MULTILINE)
    h2_match = h2_pattern.search(first_few_lines)
    if h2_match:
        title = h2_match.group(1).strip().strip('"')
        if not re.match(r"^Module\s*\d+\s*$", title, re.IGNORECASE) and len(title.split()) > 1:
            return title
    return f"Module {module_num}"

def md_to_html_custom(md_content):
    if md_content is None:
        return ""
    html = markdown.markdown(
        md_content,
        extensions=[
            'fenced_code', 'codehilite', 'tables', 'toc',
            'nl2br', 'extra'
        ],
        extension_configs={'codehilite': {'css_class': 'highlight'}}
    )
    # Automatically wrap tables in a div for better responsive handling if desired
    html = re.sub(r"(<table.*?>)", r'<div class="table-wrapper">\1', html, flags=re.IGNORECASE | re.DOTALL)
    html = re.sub(r"(</table>)", r"\1</div>", html, flags=re.IGNORECASE | re.DOTALL)
    return html

def generate_modules_dropdown_li_html(modules_info, current_page_filename=""):
    if not modules_info:
        return ""

    dropdown_items_html = ""
    is_current_page_a_module = False
    for mod in modules_info:
        if mod["html_filename"] == current_page_filename:
            is_current_page_a_module = True
            break

    for mod in modules_info:
        active_class = "active" if mod["html_filename"] == current_page_filename else ""
        link_text = mod["title"]
        dropdown_items_html += f'                <li><a href="{mod["html_filename"]}" class="{active_class}">{link_text}</a></li>\n'
    
    # Add 'active' to the "Modules" toggle itself if any module page is active
    modules_toggle_active_class = "active" if is_current_page_a_module else ""

    dropdown_li_html = f"""
            <li class="nav-dropdown {modules_toggle_active_class}">
                <span class="nav-dropdown-toggle">Modules</span>
                <ul class="dropdown-menu">
{dropdown_items_html}
                </ul>
            </li>"""
    return dropdown_li_html

def generate_page_html(page_specific_title, content_html, modules_info=None, current_page_filename=""):
    active_map = {"home": "", "outline": ""}
    if current_page_filename == "index.html":
        active_map["home"] = "active"
    elif current_page_filename == "course_outline.html":
        active_map["outline"] = "active"

    current_year = datetime.now().year
    generation_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    modules_dropdown_html_content = generate_modules_dropdown_li_html(modules_info, current_page_filename)

    page_html = HTML_TEMPLATE.format(
        title=f"{page_specific_title} | {COURSE_TITLE}",
        course_nav_title=COURSE_NAV_TITLE,
        content=content_html,
        main_css_path=MAIN_CSS_FILE_NAME,
        print_css_path=PRINT_CSS_FILE_NAME,
        active_home=active_map["home"],
        active_outline=active_map["outline"],
        modules_dropdown_li=modules_dropdown_html_content, # New placeholder
        year=current_year,
        course_title=COURSE_TITLE,
        generation_date=generation_date
    )
    return page_html

# --- Main Script Logic ---
def main():
    ensure_dir(OUTPUT_DIR)

    main_css_output_path = os.path.join(OUTPUT_DIR, MAIN_CSS_FILE_NAME)
    write_file_content(main_css_output_path, NEW_MAIN_CSS_CONTENT)
    print(f"Created '{MAIN_CSS_FILE_NAME}' in '{OUTPUT_DIR}'.")

    print_css_output_path = os.path.join(OUTPUT_DIR, PRINT_CSS_FILE_NAME)
    write_file_content(print_css_output_path, PRINT_CSS_CONTENT)
    print(f"Created '{PRINT_CSS_FILE_NAME}' in '{OUTPUT_DIR}'.")

    module_md_files_glob = os.path.join(SOURCE_DIR, MODULE_MD_PATTERN_STR)
    module_files_paths = sorted(glob.glob(module_md_files_glob))
    
    modules_info = []
    for mf_path in module_files_paths:
        basename = os.path.basename(mf_path)
        if basename in [COURSE_OUTLINE_MD_NAME, "combined_course_modules.md", "all_course_content.html", "all_course_presentations.html"]:
            continue
        
        module_num_match = re.search(r"module_(\d+)\.md", basename)
        if module_num_match:
            num = int(module_num_match.group(1))
            md_content_for_title = read_file_content(mf_path)
            extracted_title = extract_module_title(md_content_for_title, num)
            html_filename = f"module_{num}.html"
            modules_info.append({
                "num": num, 
                "title": extracted_title,
                "path": mf_path, 
                "html_filename": html_filename
            })
    modules_info.sort(key=lambda m: m["num"])

    # --- Generate Landing Page (index.html) ---
    landing_page_title = "Home"
    landing_content_html = f"""
    <section class="landing-hero">
        <h1>Welcome to {COURSE_TITLE}</h1>
        <p>This course provides a comprehensive introduction to Cyber Threat Hunting, equipping you with the foundational knowledge and practical skills to proactively identify and mitigate threats.</p>
        <p>Navigate through the course outline and modules using the navigation bar above or the links below to begin your learning journey.</p>
    </section>
    <section class="landing-links-section">
        <h2>Quick Links</h2>
        <ul class="landing-links-list">
            <li><a href="course_outline.html">View Course Outline</a></li>
        </ul>
    </section>
    """
    if modules_info:
        landing_content_html += """
    <section class="landing-links-section">
        <h2>Course Modules</h2>
        <ul class="landing-links-list">"""
        for mod_info in modules_info:
            landing_content_html += f'            <li><a href="{mod_info["html_filename"]}">{mod_info["title"]}</a></li>\n'
        landing_content_html += """
        </ul>
    </section>"""
    
    index_html_content = generate_page_html(
        landing_page_title, 
        landing_content_html, 
        modules_info=modules_info,
        current_page_filename="index.html"
    )
    write_file_content(os.path.join(OUTPUT_DIR, "index.html"), index_html_content)
    print("Generated index.html")

    # --- Generate Course Outline Page ---
    course_outline_page_title = "Course Outline"
    course_outline_md_path = os.path.join(SOURCE_DIR, COURSE_OUTLINE_MD_NAME)
    course_outline_md_content = read_file_content(course_outline_md_path)
    if course_outline_md_content:
        course_outline_html_body = md_to_html_custom(course_outline_md_content)
        first_element_is_h1 = course_outline_html_body.lstrip().lower().startswith("<h1")
        if not first_element_is_h1:
             course_outline_html_body = f"<h1>{course_outline_page_title}</h1>\n" + course_outline_html_body
        
        outline_page_full_html = generate_page_html(
            course_outline_page_title, 
            course_outline_html_body, 
            modules_info=modules_info,
            current_page_filename="course_outline.html"
        )
        write_file_content(os.path.join(OUTPUT_DIR, "course_outline.html"), outline_page_full_html)
        print("Generated course_outline.html")

    # --- Generate Module Pages ---
    presentation_base_dir = os.path.join(SOURCE_DIR, PRESENTATION_DIR_NAME)
    for mod_info in modules_info:
        page_specific_title = mod_info["title"]
        module_md_content = read_file_content(mod_info["path"])
        module_html_body = ""
        
        if module_md_content:
            temp_html = md_to_html_custom(module_md_content)
            first_h1_text = ""
            h1_search = re.search(r"<h1[^>]*>(.*?)</h1>", temp_html, re.IGNORECASE | re.DOTALL)
            if h1_search:
                first_h1_text = re.sub('<[^<]+?>', '', h1_search.group(1)).strip()

            if not (h1_search and first_h1_text.lower() == page_specific_title.lower()):
                 module_html_body += f"<h1>{page_specific_title}</h1>\n"
            module_html_body += temp_html
        
        presentation_md_filename = f"module_{mod_info['num']}_presentation.md"
        presentation_md_path = os.path.join(presentation_base_dir, presentation_md_filename)
        presentation_md_content = read_file_content(presentation_md_path)
        
        if presentation_md_content:
            module_html_body += "\n<hr>\n<h2>Presentation Content</h2>\n" # Simpler hr
            module_html_body += md_to_html_custom(presentation_md_content)
        
        module_page_full_html = generate_page_html(
            page_specific_title, 
            module_html_body, 
            modules_info=modules_info,
            current_page_filename=mod_info["html_filename"]
        )
        write_file_content(os.path.join(OUTPUT_DIR, mod_info["html_filename"]), module_page_full_html)
        print(f"Generated {mod_info['html_filename']} (Title: '{page_specific_title}')")

    print(f"\nWebsite generated in '{OUTPUT_DIR}' directory.")

if __name__ == "__main__":
    main()