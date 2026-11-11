# Merges the CycloneDX SBOM of the web client, written by `pnpm sbom`, into the SBOM of the server binary, written by cyclonedx-gomod
# The server binary embeds the web client, so its SBOM must list the web client's dependencies too
#
# Usage:
#   jq --slurpfile client <web client SBOM> --arg version <release version> -f merge-web-client-sbom.jq <server SBOM>

($client[0]) as $c
| if .specVersion != $c.specVersion then
    error("the server SBOM uses CycloneDX \(.specVersion), but the web client SBOM uses \($c.specVersion)")
  else . end
| .metadata.component["bom-ref"] as $serverRef
| $c.metadata.component["bom-ref"] as $oldClientRef
| ("revaulter-client@" + $version) as $clientRef
# The web client is a private package, so it gets the release version, and no npm package URL that scanners could match to an unrelated package
| ($c.metadata.component + {version: $version, "bom-ref": $clientRef} | del(.purl)) as $clientComponent
| .components += [$clientComponent] + $c.components
# The server depends on the web client, which keeps its own dependency graph
| .dependencies = [
    (.dependencies[] | if .ref == $serverRef then .dependsOn += [$clientRef] else . end),
    ($c.dependencies[] | if .ref == $oldClientRef then .ref = $clientRef else . end)
  ]
# Record the tool that generated the web client's part, in the same form as the server SBOM's tools
| .metadata.tools |= (
    if type == "array" then
      . + [($c.metadata.tools.components // [])[] | {name, version}]
    else
      .components += ($c.metadata.tools.components // [])
    end
  )
