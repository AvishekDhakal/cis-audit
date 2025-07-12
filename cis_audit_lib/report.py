import json
import argparse
from jinja2 import Template

def render_markdown(report):
    """
    Render the report data as a Markdown table.
    """
    md_template = """# CIS Audit Report for {{ host }}

| Control ID | Description | Status | Details |
|------------|-------------|--------|---------|
{% for f in findings -%}
| {{ f.control_id }} | {{ f.description }} | {{ f.status }} | {{ f.details }} |
{% endfor %}

**Overall Compliance:** {{ overall_compliance }}%"""
    template = Template(md_template)
    return template.render(
        host=report.get('host', 'unknown'),
        findings=report.get('findings', []),
        overall_compliance=report.get('overall_compliance', 0.0)
    )


def render_html(report):
    """
    Render the report data as an HTML document with basic styling.
    """
    html_template = """<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<title>CIS Audit Report for {{ host }}</title>
<style>
  body { font-family: Arial, sans-serif; padding: 1rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
  tr.pass { background-color: #c8e6c9; }
  tr.fail { background-color: #ffcdd2; }
</style>
</head>
<body>
<h1>CIS Audit Report for {{ host }}</h1>
<table>
<thead>
<tr><th>Control ID</th><th>Description</th><th>Status</th><th>Details</th></tr>
</thead>
<tbody>
{% for f in findings -%}
<tr class="{{ f.status|lower }}">
  <td>{{ f.control_id }}</td>
  <td>{{ f.description }}</td>
  <td>{{ f.status }}</td>
  <td>{{ f.details }}</td>
</tr>
{% endfor %}
</tbody>
</table>
<p><strong>Overall Compliance:</strong> {{ overall_compliance }}%</p>
</body>
</html>"""
    template = Template(html_template)
    return template.render(
        host=report.get('host', 'unknown'),
        findings=report.get('findings', []),
        overall_compliance=report.get('overall_compliance', 0.0)
    )


def report_cli():
    """
    CLI entry point for cis-report.
    """
    parser = argparse.ArgumentParser(description="CIS Audit Report Generator")
    parser.add_argument("-i", "--input", required=True,
                        help="Path to JSON file with scan results")
    parser.add_argument("-f", "--format", choices=["markdown", "html"],
                        default="markdown", help="Output format")
    parser.add_argument("-o", "--output", help="Output file path; defaults to stdout")
    args = parser.parse_args()

    # Load scan results
    try:
        with open(args.input) as f:
            report = json.load(f)
    except Exception as e:
        print(f"Error reading input file: {e}")
        return 1

    # Render
    if args.format == 'markdown':
        output = render_markdown(report)
    else:
        output = render_html(report)

    # Write
    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Report written to {args.output}")
        except Exception as e:
            print(f"Error writing output file: {e}")
            return 1
    else:
        print(output)

    return 0
