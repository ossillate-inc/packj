#!/usr/bin/env python

import sys
import os
import tempfile

from packj.util.files import write_to_file, write_json_to_file

html_template = """
<!DOCTYPE html>
<html>
<head>
	<title>
		Packj security audit report
	</title>
</head>
<body>
	<div>
		<h4><a href="https://github.com/ossillate-inc/packj" target="_blank">Packj</a> audit found {{ num_risky_deps }}/{{ data | length }} risky dependencies.</h4>
	</div>
	<details>
		<summary><h4>Click here for details</h4></summary>
		<table style="border-style: solid; border-width: thin;">
			<tr>
				<th>Registry</th>
				<th>Package</th>
				<th>Version</th>
				<th>Risks</th>
			</tr>
			{% for item in data %}
				<tr>
					<td>{{ item.pm_name }}</td>
					<td>{{ item.pkg_name }}</td>
					<td>{{ item.pkg_ver }}</td>
					<td>
						{% for key,val_list in item.risks.items %}
							<details>
								<summary><h4>{{ key }}</h4>. Click for details</summary>
								{% for val in val_list %}
									<li>{{ val }}</li>
								{% endfor %}
							</details>
						{% endfor %}
					</td>
				</tr>
			{% endfor %}
		</table>
	</details>
</body>
</html>
"""

def generate_summary(reports, report_dir, args, suffix='.html'):

	host_volume, container_mountpoint, _ = args

	from django.conf import settings
	TEMPLATES = [{'BACKEND':  'django.template.backends.django.DjangoTemplates'}]
	settings.configure(TEMPLATES=TEMPLATES)
	
	import django
	django.setup()
	
	from django.template import Template, Context

	total_risks = len(reports)
	report_title = f'Packj security audit report'

	data = []
	num_risky_deps = 0
	for report in reports:
		data.append({
			'pkg_name'	: report['pkg_name'],
			'pm_name'	: report['pm_name'],
			'pkg_ver'	: report['pkg_ver'],
			'risks'		: report['risks'],
		})
		if report['risks']:
			num_risky_deps += 1

	t = Template(html_template)
	c = Context({"title": report_title, "data": data, "num_risky_deps": num_risky_deps})

	_, filepath = tempfile.mkstemp(prefix=f'report_', dir=report_dir, suffix=suffix)
	write_to_file(filepath, t.render(c))

	os.chmod(filepath, 0o444)
	if container_mountpoint:
		filepath = filepath.replace(container_mountpoint, host_volume)
	print(f'=> HTML summary available at: {filepath}')

def generate_package_report(report, args, suffix='.json'):

	container_mountpoint, report_dir, host_volume = args

	_, filepath = tempfile.mkstemp(prefix=f'report_', dir=report_dir, suffix=suffix)
	write_json_to_file(filepath, report, indent=4)
		
	os.chmod(filepath, 0o444)
	if container_mountpoint:
		filepath = filepath.replace(container_mountpoint, host_volume)
	print(f'=> Complete report: {filepath}')
