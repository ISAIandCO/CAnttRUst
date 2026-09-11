export const statusText: Record<string, string> = {
  ct_valid: "SCT проверены", other_ca: "Цепочка не содержит защищаемого CA",
  protected_ca_outside_zone: "Защищаемый CA вне разрешённой зоны",
  missing_embedded_sct: "В сертификате нет встроенных SCT", no_trusted_log: "Нет SCT доверенного лога",
  invalid_sct_signature: "Неверная подпись SCT", sct_outside_log_interval: "SCT вне интервала лога",
  log_not_accepted_at_sct_time: "Статус или время CT-лога не допускает этот SCT",
  policy_not_satisfied: "Недостаточно независимых операторов CT",
  certificate_parse_error: "Не удалось разобрать сертификат", issuer_not_found: "Не найден сертификат издателя",
  unsupported_signature_algorithm: "Алгоритм подписи не поддерживается", internal_error: "Ошибка проверки SCT",
  tls_unavailable: "Проверка недоступна: Firefox не предоставил цепочку TLS",
  disabled: "Защита отключена", one_time: "Однократный обход проверки",
  ct_exception: "Проверка CT отключена исключением", zone_exception_ct_valid: "Исключение зоны; SCT проверены"
};
export function reasonText(reason: string): string { return statusText[reason] ?? reason; }
