# CT fixture

`check-russian-trusted-leaf.der` — публичный сертификат `check.russian-trusted.ru`, полученный 25 августа 2026 года через TLS. SHA-256: `807f96b96ca23f5c9afd55e1e08e2df02de377e58d9791beccbe28365f733b2d`.

`russian-trusted-sub-ca.der` — его exact intermediate из AIA `http://nuc-cdp.digital.gov.ru/cdp/subca_ssl_rsa2024.crt`. SHA-256: `2155785036c900dbb5f1bb2a1569c80c55595bd6bf94867a29bbddbc7d88a3f2`.

Пара содержит три реально подписанных встроенных SCT (Yandex, VK и Минцифры) и используется как полностью офлайн-проверяемый криптографический вектор. Runtime-код не обращается к этим адресам.

