# password-strength

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-%3E%3D3.9-blue.svg)](https://www.python.org/)

Score **password strength** (0-100) from stdin, a file, or command-line
arguments. Purely local heuristic estimator — nothing is stored or sent
anywhere. Designed for onboarding checklists, account-migration audits and CI
gates. No dependencies, Python >= 3.9.

## How it scores

- Length (up to 40 points), character-class mix (lower/upper/digit/symbol)
- Variety bonus based on the number of distinct characters
- Penalties for runs of the same character (`aaaa`) and sequential runs
  (`abcd`, `4321`)
- A small built-in list of extremely common passwords scores 0

Labels: `0-19 very weak`, `20-39 weak`, `40-59 fair`, `60-79 strong`,
`80-100 very strong`.

## Install

```bash
pip install .
# or straight from the repo:
pip install git+https://github.com/TataneSan/password-strength.git
```

## Usage

```console
$ password-strength 'hunter2' 'Tr0ub4dor&3' --feedback
  8/100  very weak   (7 chars)
    - use at least 8 characters
    - avoid sequential runs like 'abcd' or '1234'
 62/100  strong      (11 chars)
```

```console
$ printf 'password\nX7!k#29pQw$z\n' | password-strength
  0/100  very weak   (8 chars)
 94/100  very strong (12 chars)
```

### CI gate examples

```bash
# fail the pipeline if any seeded test password is weak
cat fixtures/dev-accounts.txt | password-strength --min-score 60 -q -

# require a very strong admin password in a provisioning script
password-strength --min-score 80 "$ADMIN_PASSWORD"
```

## Options

| Option | Description |
| --- | --- |
| `--file FILE` | read one password per line from FILE |
| `--min-score N` | exit 2 if the weakest password scores below N |
| `--feedback` | print improvement hints under each score |
| `--json` | print a JSON report |
| `-q`, `--quiet` | suppress per-password output |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | every password meets `--min-score` |
| 1 | input/output or command-line error |
| 2 | at least one password scores below `--min-score` |

## License

MIT — see [LICENSE](LICENSE).
