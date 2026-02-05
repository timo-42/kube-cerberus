# TODO Status

All previously listed TODO items have been implemented:

- [x] Pre-condition skip behavior with tri-state handling (`match` / `reject` / `skip`)
- [x] Mutating webhook framework (`@mutating` and mutating AdmissionReview processing)
- [x] Validation message details via validator return type `(bool, str)`
- [x] Async hook support (validators and mutators)
- [x] Webhook configuration generator CLI (`cerberus generate-webhook`)
- [x] Prometheus metrics export (`Registry.metrics_text()`)
- [x] Structured logging (replacing `print`-based runtime diagnostics)

Unit test coverage for these features lives in `tests/unit_tests/todo_features_test.py`.
