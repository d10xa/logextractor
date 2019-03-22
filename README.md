# logextractor

Extract !@%& WRAPPED &%@! content from stdin!

## Install

```
cargo install --git https://github.com/d10xa/logextractor.git
```

## Usage

```
$ echo 'text #>hello<# text #>world<#' | logextractor --prefix '#>' --suffix '<#'
hello
world
```

