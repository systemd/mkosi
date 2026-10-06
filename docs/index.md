---
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# mkosi — Build Bespoke OS Images

A fancy wrapper around `dnf --installroot`, `apt`, `pacman` and `zypper` that generates customized disk images with a number of bells and whistles.

---

{% assign tutorials = site.pages | group_by:"category" %}
{% assign project = site.data.project_pages | group_by:"category" %}
{% assign documentation = site.data.documentation_page | group_by:"category" %}
{% assign merged = documentation | concat: tutorials | concat: project %}


{% for pair in merged %}
  {% if pair.name != "" %}
## {{ pair.name }}
{% assign sorted = pair.items | sort:"title" %}{% for page in sorted %}
* [{{ page.title }}]({{ page.url | relative_url }}){% endfor %}
  {% endif %}
{% endfor %}

---
