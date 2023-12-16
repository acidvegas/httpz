# HTTP-Z
###### This is still a work in progress...stay tuned for updates!

## Information
This script is developed as a robust alternative to HTTPX, addressing the limitations in customizing JSON outputs and other functionalities that HTTPX lacks. It is specifically designed for asynchronous lookups on a list of domains, efficiently gathering DNS information and web content details such as page titles and body previews.

## Usage
| Argument               | Description                                                 |
| ---------------------- | ----------------------------------------------------------- |
| `<input_file>`         | File containing list of domains                             |
| `-c`, `--concurrency`  | Number of concurrent requests                               |
| `-m`, `--memory_limit` | Number of results to store in memory before syncing to file |
| `-o`, `--output`       | Output file                                                 |
| `-t`, `--timeout`      | Timeout for HTTP requests                                   |
| `-u`, `--user_agent`   | User agent to use for HTTP requests                         |
| `-x`, `--proxy`        | Proxy to use for HTTP requests                              |
| `-r`, `--retry`        | Number of times to retry failed requests                    |
| `-v`, `--verbose`      | Increase output verbosity                                   |
| `-p`, `--preview`      | Preview size in bytes for body & title *(default: 500)*     |

___

###### Mirrors
[acid.vegas](https://git.acid.vegas/httpz) • [GitHub](https://github.com/acidvegas/httpz) • [GitLab](https://gitlab.com/acidvegas/httpz) • [SuperNETs](https://git.supernets.org/acidvegas/httpz)
