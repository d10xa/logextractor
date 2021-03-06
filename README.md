# logextractor

Extract !@%& WRAPPED &%@! content from stdin!

## Install

```
cargo install --git https://github.com/d10xa/logextractor.git --force
```

## Usage


```
Usage:
    logextractor -p <PREFIX> -s <SUFFIX> [-d DELIMITER] [COMMAND]

Examples:
    echo 'text #>hello<# text #>world<#' | logextractor --prefix '#>' --suffix '<#'
    echo '<(aGVsbG8K)><(d29ybGQK)>' | logextractor -p '<(' -s ')>' -d ''  base64 --decode

Options:
    -p, --prefix [PREFIX]
                        set prefix of text
    -s, --suffix [SUFFIX]
                        set suffix of text
    -d, --delimiter [DELIMITER]
                        stdout results delimiter
    -o, --output-dir [PATH]
                        save results to files
    -e, --enumerate-files 
                        enumerate output files
    -u, --unique        do not make duplicates
```
