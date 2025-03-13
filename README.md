# py-genhash-path
A simple command line utility script that generates two hash files for each file in the provided directory path - `.sha256` and `.md5`

## Usage
```sh
genhash-path.py [root_dir] [-h] [--no-keep-files] [--table] [--subsup]
```

You can alias this in your shell (on Linux) to something like:
```sh
alias genhash=/home/user/my/path/to/file/genhash-path.py
```

#### Positional Arguments
<pre>
root_dir: Path to the system location (default: current working directory).
</pre>
  
#### Optionals
<pre>
--help, -h:            Show help message and quit.
--no-keep-files, -nkf: Delete generated hash files after run. Preserves original files.
--table, -t:           Print output table in command line where headers are: Files, SHA256, MD5.
--subsup, -ss:         Encapsulate row results (exclude header column) in &lt;sub&gt;&lt;sup&gt;WORD&lt;/sup&gt;&lt;/sub&gt; tag for smaller font size.(Mostly useful for Markdown)
</pre>

# Examples
## Generate hash files and print table
```sh
> ls

executable.exe  file_a  file_b
```

```sh
genhash --table
```
<pre>
Generate SHA-256 and MD5 checksums for files in '/home/user/genhash-examples'
Collected 3 files.

Generating SHA-256 Hashes
* Generated SHA-256 hash for file file_a (/home/user/genhash-examples/file_a)
* Generated SHA-256 hash for file executable.exe (/home/user/genhash-examples/executable.exe)
* Generated SHA-256 hash for file file_b (/home/user/genhash-examples/file_b)

Generating MD5 Hashes
* Generated MD5 hash for file file_a (/home/user/genhash-examples/file_a)
* Generated MD5 hash for file executable.exe (/home/user/genhash-examples/executable.exe)
* Generated MD5 hash for file file_b (/home/user/genhash-examples/file_b)

Generated table [--table]
| File           | SHA256                                                           | MD5                              |
|----------------|------------------------------------------------------------------|----------------------------------|
| executable.exe | 8744fcc20f56091731b86ef9eeca399985dda9a391e3e648cf17dc204c4acacf | cb91b679c0aecc2fc28e00116c3c75bc |
| file_a         | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | d41d8cd98f00b204e9800998ecf8427e |
| file_b         | 4b9bf1dedf2384342d32c0116ce01668918a8196a3babd962664ef6a2403ea78 | c96b1cbe66f69b234cf361d8c1e5bbb9 |

Finished.
</pre>

```sh
> ls

executable.exe  executable.exe.md5  executable.exe.sha256  file_a  file_a.md5  file_a.sha256  file_b  file_b.md5  file_b.sha256
```


## Generate hash files, don't keep generated hash files and print table
```sh
> ls

executable.exe  file_a  file_b
```


```sh
genhash --table -nkf
```
<pre>
Generate SHA-256 and MD5 checksums for files in '/home/user/genhash-examples'
Collected 3 files.

Generating SHA-256 Hashes
* Generated SHA-256 hash for file file_b (/home/user/genhash-examples/file_b)
* Generated SHA-256 hash for file executable.exe (/home/user/genhash-examples/executable.exe)
* Generated SHA-256 hash for file file_a (/home/user/genhash-examples/file_a)

Generating MD5 Hashes
* Generated MD5 hash for file file_b (/home/user/genhash-examples/file_b)
* Generated MD5 hash for file executable.exe (/home/user/genhash-examples/executable.exe)
* Generated MD5 hash for file file_a (/home/user/genhash-examples/file_a)

Delete generated hash files [--no-keep-files]
* Delete /home/user/genhash-examples/file_a.sha256
* Delete /home/user/genhash-examples/executable.exe.md5
* Delete /home/user/genhash-examples/file_a.md5
* Delete /home/user/genhash-examples/file_b.sha256
* Delete /home/user/genhash-examples/file_b.md5
* Delete /home/user/genhash-examples/executable.exe.sha256

Generated table [--table]
| File           | SHA256                                                           | MD5                              |
|----------------|------------------------------------------------------------------|----------------------------------|
| executable.exe | 8744fcc20f56091731b86ef9eeca399985dda9a391e3e648cf17dc204c4acacf | cb91b679c0aecc2fc28e00116c3c75bc |
| file_a         | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | d41d8cd98f00b204e9800998ecf8427e |
| file_b         | 4b9bf1dedf2384342d32c0116ce01668918a8196a3babd962664ef6a2403ea78 | c96b1cbe66f69b234cf361d8c1e5bbb9 |

Finished.
</pre>

```sh
> ls

executable.exe  file_a  file_b
```


## Generate hash files, print table with subssup
```sh
> ls

executable.exe  file_a  file_b
```

```sh
genhash --table -ss
```
<pre>
Generate SHA-256 and MD5 checksums for files in '/home/user/genhash-examples'
Collected 3 files.

Generating SHA-256 Hashes
* Generated SHA-256 hash for file file_b (/home/user/genhash-examples/file_b)
* Generated SHA-256 hash for file executable.exe (/home/user/genhash-examples/executable.exe)
* Generated SHA-256 hash for file file_a (/home/user/genhash-examples/file_a)

Generating MD5 Hashes
* Generated MD5 hash for file file_b (/home/user/genhash-examples/file_b)
* Generated MD5 hash for file executable.exe (/home/user/genhash-examples/executable.exe)
* Generated MD5 hash for file file_a (/home/user/genhash-examples/file_a)

Generated table [--table, --subsup]
| File           | SHA256                                                                                 | MD5                                                    |
|----------------|----------------------------------------------------------------------------------------|--------------------------------------------------------|
| executable.exe | &lt;sub&gt;&lt;sup&gt;8744fcc20f56091731b86ef9eeca399985dda9a391e3e648cf17dc204c4acacf&lt;/sup&gt;&lt;/sub&gt; | &lt;sub&gt;&lt;sup&gt;cb91b679c0aecc2fc28e00116c3c75bc&lt;/sup&gt;&lt;/sub&gt; |
| file_a         | &lt;sub&gt;&lt;sup&gt;e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855&lt;/sup&gt;&lt;/sub&gt; | &lt;sub&gt;&lt;sup&gt;d41d8cd98f00b204e9800998ecf8427e&lt;/sup&gt;&lt;/sub&gt; |
| file_b         | &lt;sub&gt;&lt;sup&gt;4b9bf1dedf2384342d32c0116ce01668918a8196a3babd962664ef6a2403ea78&lt;/sup&gt;&lt;/sub&gt; | &lt;sub&gt;&lt;sup&gt;c96b1cbe66f69b234cf361d8c1e5bbb9&lt;/sup&gt;&lt;/sub&gt; |

Finished.
</pre>

```sh
> ls

executable.exe  executable.exe.md5  executable.exe.sha256  file_a  file_a.md5  file_a.sha256  file_b  file_b.md5  file_b.sha256
```