---
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# mkosi — Build Bespoke OS Images

A fancy wrapper around `dnf --installroot`, `apt`, `pacman` and `zypper` that generates customized disk images with a number of bells and whistles.

---

{% assign manuals = site.pages | group_by:"category" | where:"name", "Manuals" %}
{% assign contributing = site.pages | group_by:"category" | where:"name", "Contributing" %}
{% assign tutorials = site.pages | group_by:"category" | where:"name", "Tutorials" %}
{% assign tutorials = site.pages | group_by:"category" | where:"name", "Tutorials" %}
{% assign project = site.data.project_pages | group_by:"category" | where:"name", "Project" %}
{% assign merged = manuals | concat: contributing | concat: tutorials | concat: project %}


{% for pair in merged %}
  {% if pair.name != "" %}
## {{ pair.name }}
{% assign sorted = pair.items | sort:"title" %}{% for page in sorted %}
* [{{ page.title }}]({{ page.url | relative_url }}){% endfor %}
  {% endif %}
{% endfor %}

---
