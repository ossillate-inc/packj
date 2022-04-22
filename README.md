# packj

<img src="https://www.svgrepo.com/show/255045/box-package.svg" width="164"/>

*packj* (pronounced package) is a tool to vet open-source software packages for "risky" attributes that make them vulnerable to supply chain attacks.

## Risky attributes

packj vets for several code and metadata attributes, including

- Use of sensitive APIs, such as ```exec``` 
- Correctness and validity of author email (for 2FA)
- Presence and validity of public source repo
