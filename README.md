# InfraTrack
> InfraTrack is a powerful Python-based tool for tracking infrastructure and identifying potential Command and Control (C2) servers. It allows for the lookup of IP addresses and domain names using multiple feeds, and 
the ability to save the results to a MongoDB instance. Additionally, the script can identify possible C2 infrastructure using Shodan and Censys queries, providing a comprehensive and efficient method for threat 
intelligence gathering.

 ## Features
* Virustotal API lookup:
  * Community score (IP addresses & domains)
  * Historical resolutions (IP addresses)
  * Communicating files count (domains)
* CriminalIP API:
  * To be added
* RiskIQ API:
  * PassiveDNS resolutions (IP addresses & domains)
  * First & Last seen dates/times (IP addresses & domains)
* GreyNoise API:
  * Noise Response
  * RIOT (to be added)
* WhoIs Info:
  * Country
  * Nameservers (if applicable)
  * Registrar 
* Add a custom tag to the above results for tracking and analysis, save to a MongoDB instance.
* Identify possible C2 infrastructure utilizing Shodan and Censys queries (queries to be released)
* Easy to use command line interface

## Requirements
* Python3 
* MongoDB Atlas account
* Virustotal API Key
* Shodan API Key (Optional)
* Censys API Key (Optional)

<!-- ![](screenshot.png) -->
<!---
## Installation

OS X & Linux:

```sh
npm install my-crazy-module --save
```

Windows:

```sh
edit autoexec.bat
```
--->
## Usage example

```python
python3 infratrack.py --hunt '/path/to/shodan/censys/query/files'

python3 infratrack.py --domain 'example.com'

python3 infratrack.py --ip '1.2.3.4'
```

Help page

![Screenshot](https://github.com/mrippey/InfraTrack/blob/master/images/Help0.png)

Domain Name Lookup Output
![Screenshot](https://github.com/mrippey/InfraTrack/blob/master/images/domain_lookup_example.png)

IP Address Lookup  Output
![Screenshot](https://github.com/mrippey/InfraTrack/blob/master/images/iplkup_example.png)

<!---
A few motivating and useful examples of how your product can be used. Spice this up with code blocks and potentially more screenshots.

_For more examples and usage, please refer to the [Wiki][wiki]._

## Development setup

Describe how to install all development dependencies and how to run an automated test-suite of some kind. Potentially do this for multiple platforms.

```sh
make install
npm test
```
--->
## Release History
<!---
* 0.2.1
    * CHANGE: Update docs (module code remains unchanged)
* 0.2.0
    * CHANGE: Remove `setDefaultXYZ()`
    * ADD: Add `init()` -->
* 1.0.0 (26 Jan 2023)
    * CHANGE: Separate Virustotal API calls into class to allow for ease of addition and removal of features
* 0.1.1
    * CHANGE: Separate main InfraTrack into multiple modules
* 0.1.0
    * The first proper release
    * CHANGE: Cleanup code, combine Domain & IP Summary, add "Machine Learning" algorithm to identify malicious URL's. 
    * CHANGE(2): Write Shodan and Censys query output to CSV file to ease upload into Splunk, ELK, or other analysis platform.
    * TODO: Implement correlation analysis among already gathered data.
* 0.0.1
    * Work in progress
<!-- [https://github.com/yourname/github-link](https://github.com/mrippey/) -->
<!---
## Contributing

1. Fork it (<https://github.com/yourname/yourproject/fork>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request
--->
<!-- Markdown link & img dfn's 
[npm-image]: https://img.shields.io/npm/v/datadog-metrics.svg?style=flat-square
[npm-url]: https://npmjs.org/package/datadog-metrics
[npm-downloads]: https://img.shields.io/npm/dm/datadog-metrics.svg?style=flat-square
[travis-image]: https://img.shields.io/travis/dbader/node-datadog-metrics/master.svg?style=flat-square
[travis-url]: https://travis-ci.org/dbader/node-datadog-metrics
[wiki]: https://github.com/yourname/yourproject/wiki
--->

