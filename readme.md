# Markdown to Document

Using Markdown, Pandoc, and Eisvogel, you can create a document for your company. In this repository, you will find ready-to-use templates that you can customize based on your needs.

## Advantages

1. Spend less time on formatting
2. Standardization
3. Faster document creation
4. Creation of multiple templates
5. Customization
6. Professional design
7. Can be used for documents, contracts, technical reports, etc.

# Install

I used Ubuntu 22.04 for the development of these templates.

1. Download Pandoc and its dependencies

```sh
sudo apt install -y pandoc texlive-xetex texlive-latex-recommended texlive-fonts-recommended texlive-latex-extra
```

2. Download Eisvogel

```sh
wget https://raw.githubusercontent.com/Wandmalfarbe/pandoc-latex-template/master/eisvogel.tex -O /usr/share/pandoc/data/templates/

wget https://raw.githubusercontent.com/Wandmalfarbe/pandoc-latex-template/master/eisvogel.tex -O ~/.local/share/pandoc
```

3. Use autobuild or

```sh
pandoc <FILE MARKDOWN>>.md -o <OUTPUT EXPECT NAME FILE>.pdf --from markdown --template eisvogel --pdf-engine xelatex
```

# Usage

## Add Image

```markdown
\begin{figure}[h]
    \centering
    \includegraphics[width=0.8\textwidth]{<YOUR IMAGE>.png}
    \captionsetup{justification=centering, singlelinecheck=false, format=plain}
    \caption{Add some caption here}
\end{figure}
```

## Add Indentation

Place `\setlength{\parindent}{1.5cm}` after the metadata in the body of the markdown.

If you want to indent a block of text, use:

```markdown
::: {.idented}

Text here

:::
```

## For Code Block

Insert the following after the metadata in the body of the markdown:

```markdown
\lstset{
      basicstyle=\ttfamily\footnotesize,
      columns=fullflexible,
      breaklines=true,
      frame=none,
      xleftmargin=10pt,
      xrightmargin=10pt
    }
\newtcolorbox{forum}{
      colback=gray!3,
      colframe=gray!30,
      boxrule=0.3pt,
      left=5pt,
      right=5pt,
      top=3pt,
      bottom=3pt,
      arc=1pt,
      fontupper=\ttfamily\footnotesize
    }
```

Then, use:

```markdown
\begin{forum}
\begin{lstlisting}

Your code here

\end{lstlisting}
\end{forum}
```