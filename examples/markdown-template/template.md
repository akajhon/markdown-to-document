---
title: "Title Example"
subtitle: "SubTitle Example"
author: 
  - Your Company
date: \today
lang: "en-US" 

# Layout Configs
toc: true
toc-own-page: true
toc-title: "Summary"
numbersections: true
titlepage: true
listings: true
listings-no-page-break: true
highlight-style: tango
papersize: "a4"

# Visual Configs
titlepage-logo: "logo.png"
logo-width: 125mm
titlepage-background: "background.jpg"
titlepage-text-color: "000000"
titlepage-rule-color: "0033A0" 
titlepage-rule-height: 2

# Header and Footer
header-left: "Your Company - \\thetitle"
header-right: "\\includegraphics[width=30mm]{logo.png}"
footer-left: "\\footnotesize Report\\hspace{2pt} | \\hspace{2pt} Confidential document"
footer-right: "Page \\thepage\\hspace{2pt} of \\pageref{LastPage}"

# Table Configs
table-use-row-colors: true
table-caption: "Table"

# Font Configs
mainfont: "Ubuntu"
sansfont: "Georgia"
monofont: "Courier New"
fontsize: 11pt
geometry: "left=2.5cm,right=2.5cm,top=2.5cm,bottom=2.5cm"

header-includes:
    - \usepackage{lastpage}
    - \usepackage{graphicx}
    - \usepackage{caption}
    - \usepackage{indentfirst}
    - \usepackage{tcolorbox}
    - \usepackage{listings}
    - \usepackage{fontspec}
    - \usepackage{ulem}
...

# Markdown Test Document

This is a document to test all Markdown features with Pandoc.

# Basic Formatting

**Bold**, *italic*, ***bold and italic***, ~~strikethrough~~, `inline code`.

Superscript^[example of footnote], H~2~O (subscript), ==highlighted text==.

# Headers

# Header 1
## Header 2
### Header 3
#### Header 4
##### Header 5
###### Header 6

# Lists

## Unordered List
- Item 1
- Item 2
  - Subitem 2.1
  - Subitem 2.2
- Item 3

## Ordered List
1. First item
2. Second item
   1. Subitem 2.1
   2. Subitem 2.2
3. Third item

## Task List
- [x] Completed task
- [ ] Pending task
- [ ] Another task

# Links and Images

[Pandoc Website](https://pandoc.org)

![Sample Image](https://pandoc.org/pandoc-cartoon.svgz "Pandoc Logo")

# Code Blocks

Inline `code` example.

```python
# Python code block
def hello():
    print("Hello, World!")
```


```javascript
function test() {
    console.log("Test");
}
```

# Blockquotes

> This is a blockquote.  
> It can span multiple lines.

# Tables

| Header 1 | Header 2 | Header 3 |
|----------|----------|----------|
| Row 1, Cell 1 | Row 1, Cell 2 | Row 1, Cell 3 |
| Row 2, Cell 1 | Row 2, Cell 2 | Row 2, Cell 3 |
| Row 3, Cell 1 | Row 3, Cell 2 | Row 3, Cell 3 |

# Horizontal Rule

---

# Footnotes

Here is a text with a footnote.[^1]

[^1]: This is the content of the footnote.

# Definition Lists

Term 1
: Definition of Term 1

Term 2
: Definition of Term 2

# HTML Elements

You can use HTML elements in your markdown:

<p>This is a paragraph in HTML</p>
<strong>This is bold using HTML</strong>
<em>This is italic using HTML</em>

# Comments

<!-- This is a comment that will not be visible in the output -->

# LaTeX Math (Inline)

For inline LaTeX math, use `\( a^2 + b^2 = c^2 \)`.

# LaTeX Math (Block)

For block LaTeX math, use:

$$
\int_{0}^{\infty} e^{-x^2} \, dx = \frac{\sqrt{\pi}}{2}
$$

# Anchor Links

You can create links to sections within the document:

[Go to Header 2](#header-2)

# Image with Link

You can link an image to a URL:

[![Link to Pandoc](https://pandoc.org/pandoc-cartoon.svgz)](https://pandoc.org)

# Strikethrough

You can use strikethrough `~~text~~` in markdown to indicate deleted text.

# Abbreviations

You can define abbreviations like this:

*HTML*: HyperText Markup Language

And refer to them like this: *HTML*.

# Custom Styles

You can add custom styles using HTML or custom syntax, depending on the output format.

# Nested Lists

- Main Item 1
  - Subitem 1.1
  - Subitem 1.2
- Main Item 2
  - Subitem 2.1
  - Subitem 2.2
    - Sub-subitem 2.2.1

# Markdown Inside a List

1. First Item
   * Nested unordered list item
   2. Nested ordered list item
