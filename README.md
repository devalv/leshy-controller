[![clang-format-check](https://github.com/devalv/leshy-controller/actions/workflows/clang-format.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/clang-format.yml)
[![Hadolint Dockerfile scan](https://github.com/devalv/leshy-controller/actions/workflows/hadolint-scan.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/hadolint-scan.yml)
[![semgrep C Code Security Scan](https://github.com/devalv/leshy-controller/actions/workflows/semgrep-cpbf-scan.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/semgrep-cpbf-scan.yml)
[![Trivy CBPF builder scan](https://github.com/devalv/leshy-controller/actions/workflows/trivy-cbpf-scan.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/trivy-cbpf-scan.yml)
[![tests-go](https://github.com/devalv/leshy-controller/actions/workflows/go-tests.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/go-tests.yml)


# leshy-controller

## Компоненты

### bpf-фильтр
См. [README](./cbpf/README.md)

## Структура репозитория

```plaintext
project/
├── cbpf/
│   ├── filter/
│   │   ├── *.c
│   ├── tests/
│   ├── Makefile
│   └── README.md
├── cmd/
│   └── ... (Go код с точкой входа в приложение)
├── internal/
│   ├── app
│   ├── config
│   ├── interfaces
│   │   ├──rest
│   │   │  ├──v1
│   │   ├──grpc?
│   └── ... (Go код)
├── devops/
│   └── ... (скрипты сборки)

├── docs/
│   ├── examples/
│   │   ├── basic.md
│   │   ├── advanced/
│   ├── cbpf/
│   ├── architecture.md
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
