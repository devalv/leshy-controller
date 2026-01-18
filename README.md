[![clang-format-check](https://github.com/devalv/leshy-controller/actions/workflows/clang-format.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/clang-format.yml)
[![Hadolint Dockerfile scan](https://github.com/devalv/leshy-controller/actions/workflows/hadolint-scan.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/hadolint-scan.yml)
[![semgrep C Code Security Scan](https://github.com/devalv/leshy-controller/actions/workflows/semgrep-cpbf-scan.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/semgrep-cpbf-scan.yml)
[![Trivy CBPF builder scan](https://github.com/devalv/leshy-controller/actions/workflows/trivy-cbpf-scan.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/trivy-cbpf-scan.yml)


```
project/
├── cbpf/
│   ├── filter/
│   │   ├── *.c
│   ├── tests/
│   ├── Makefile
│   └── README.md
├── cmd/
│   └── ... (Go код)
├── internal/
│   └── ... (Go код)
├── devops/
│   └── ... (скрипты сборки)
├── examples/
│   ├── basic/
│   ├── advanced/
├── docs/
│   ├── architecture.md
│   ├── development.md
│   └── api/
├── .pre-commit-config.yaml    # Pre-commit хуки
├── .clang-format              # Форматирование C
├── .golangci.yaml             # Go линтер
├── Makefile                   # Основной Makefile
├── go.mod                     # Go модули
├── go.sum
├── LICENSE
└── README.md
```
