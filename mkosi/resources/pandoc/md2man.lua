-- SPDX-License-Identifier: LGPL-2.1-or-later

-- Modify the way pandoc transforms markdown to man pages

-- Convert `code` syntax to **code** in man page output
function Code(elem)
  -- Returns the content as a Strong (bold) element
  return pandoc.Strong(elem.text)
end
