export function versionForChannel(version, channel = "listed") {
  if (!/^\d+\.\d+\.\d+$/.test(version) || version.split(".").some((n) => Number(n) > 65535)) throw new Error("Expected a three-part release version");
  if (channel === "listed") return version;
  if (channel === "unlisted") return `${version}.1`;
  throw new Error(`Unknown release channel: ${channel}`);
}
